#!/usr/bin/env python3
"""Isolated regression tests for Marketplace installer version-pinning and git-staging hardening."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import common_functions

ROOT = Path(__file__).resolve().parents[1]
REAL_GIT = shutil.which("git") or "/usr/bin/git"
REAL_PYTHON3 = sys.executable

REBASE_PREFIXES = (
    "/usr/local",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/share",
    "/opt",
    "/var",
    "/etc",
    "/srv",
    "/mnt",
    "/run",
    "/install",
    "/tmp",
    "/home",
    "/root",
    "/data",
)
REBASE_PATTERN = re.compile(
    r"(?<![\w/.-])("
    + "|".join(re.escape(prefix) for prefix in REBASE_PREFIXES)
    + r")(?=/|[^\w.-]|$)"
)


def rebase_paths(source: str, root: Path) -> str:
    return REBASE_PATTERN.sub(lambda match: str(root) + match.group(0), source)


def run_git(cwd: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "AetherFlow Test",
        "GIT_AUTHOR_EMAIL": "test@aetherflow.invalid",
        "GIT_COMMITTER_NAME": "AetherFlow Test",
        "GIT_COMMITTER_EMAIL": "test@aetherflow.invalid",
    }
    res = subprocess.run(
        [REAL_GIT, *args],
        cwd=str(cwd),
        env=env,
        text=True,
        capture_output=True,
        timeout=30,
    )
    if res.returncode != 0:
        raise AssertionError(f"git {' '.join(args)} failed ({res.returncode}): {res.stdout}{res.stderr}")
    return res.stdout.strip()


MOCK_BIN = r"""#!/usr/bin/python3
import json
import os
import pathlib
import subprocess
import sys

root = pathlib.Path(os.environ["AF_TEST_ROOT"])
cmd = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]

with (root / "commands.jsonl").open("a", encoding="utf-8") as log:
    log.write(json.dumps([cmd, *args]) + "\n")

if cmd == "git":
    real_git = os.environ["AF_REAL_GIT"]
    fault = os.environ.get("AF_GIT_FAULT", "")
    if fault == "head_mismatch" and "rev-parse" in args and any("HEAD" in a for a in args):
        print("0000000000000000000000000000000000000000")
        sys.exit(0)
    res = subprocess.run([real_git, *args])
    sys.exit(res.returncode)

if cmd == "systemctl":
    sub = args[0] if args else ""
    units = [a.removesuffix(".service") for a in args[1:] if not a.startswith("-")]
    if sub == "is-active":
        active = all((root / f"service_active_{u}").exists() for u in units)
        if "--quiet" not in args and "-q" not in args:
            print("active" if active else "inactive")
        sys.exit(0 if active else 3)
    if sub == "is-enabled":
        enabled = all((root / f"service_enabled_{u}").exists() for u in units)
        if "--quiet" not in args and "-q" not in args:
            print("enabled" if enabled else "disabled")
        sys.exit(0 if enabled else 1)
    if sub == "show":
        if "-p" in args and "ExecMainPID" in args:
            unit = units[-1] if units else ""
            print("12345" if (root / f"service_active_{unit}").exists() else "0")
            sys.exit(0)
        unit = units[-1] if units else ""
        active = (root / f"service_active_{unit}").exists()
        enabled = (root / f"service_enabled_{unit}").exists()
        unit_file = root / f"etc/systemd/system/{unit}.service"
        print(f"LoadState={'loaded' if (unit_file.exists() or active or enabled) else 'not-found'}")
        print(f"UnitFileState={'enabled' if enabled else 'disabled'}")
        print(f"ActiveState={'active' if active else 'inactive'}")
        print(f"SubState={'running' if active else 'dead'}")
        print(f"MainPID={'12345' if active else '0'}")
        sys.exit(0)
    if sub == "stop":
        for u in units:
            (root / f"service_active_{u}").unlink(missing_ok=True)
            if u == "af-piped-proxy":
                (root / "proc/12345/exe").unlink(missing_ok=True)
        sys.exit(0)
    if sub in ("start", "restart", "reload"):
        for u in units:
            (root / f"service_active_{u}").touch()
            if u == "af-piped-proxy":
                (root / "proc/12345").mkdir(parents=True, exist_ok=True)
                exe = root / "proc/12345/exe"
                exe.unlink(missing_ok=True)
                exe.symlink_to(root / "opt/piped/piped-proxy")
        sys.exit(0)
    if sub == "enable":
        for u in units:
            (root / f"service_enabled_{u}").touch()
            if "--now" in args:
                (root / f"service_active_{u}").touch()
        sys.exit(0)
    if sub == "disable":
        for u in units:
            (root / f"service_enabled_{u}").unlink(missing_ok=True)
            if "--now" in args:
                (root / f"service_active_{u}").unlink(missing_ok=True)
        sys.exit(0)
    sys.exit(0)

if cmd == "dpkg":
    if "--print-architecture" in args:
        print(os.environ.get("AF_MOCK_ARCH", "amd64"))
        sys.exit(0)
    if "--compare-versions" in args:
        sys.exit(subprocess.run(["/usr/bin/dpkg", *args]).returncode)
    if "-i" in args:
        deb_path = args[args.index("-i") + 1]
        ver = pathlib.Path(deb_path).read_text(encoding="utf-8").strip() or os.environ.get("AF_MOCK_DEB_VER", "2.20.0")
        (root / "installed_deb_version").write_text(ver, encoding="utf-8")
        sys.exit(0)
    sys.exit(0)

if cmd == "dpkg-deb":
    deb_path = args[-1]
    if os.environ.get("AF_MOCK_DEB_VER"):
        print(os.environ["AF_MOCK_DEB_VER"])
    else:
        print(pathlib.Path(deb_path).read_text(encoding="utf-8").strip())
    sys.exit(0)

if cmd == "dpkg-query":
    state_file = root / "installed_deb_version"
    if not state_file.exists():
        sys.exit(1)
    ver = state_file.read_text(encoding="utf-8").strip()
    if any("db:Status-Status" in a for a in args):
        print(f"installed {ver}")
    else:
        print(ver)
    sys.exit(0)

if cmd == "apt-get":
    if args and args[0] == "install" and "audiobookshelf" in args:
        ver = os.environ.get("AF_MOCK_PPA_VER", "2.99.0")
        (root / "installed_deb_version").write_text(ver, encoding="utf-8")
    sys.exit(0)

if cmd == "python3":
    if len(args) >= 3 and args[0] == "-m" and args[1] == "venv":
        venv_dir = pathlib.Path(args[2])
        bin_dir = venv_dir / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        py_bin = bin_dir / "python"
        py_bin.write_text(
            "#!/usr/bin/python3\n"
            "import os, pathlib, sys\n"
            "if sys.argv[1:3] == ['-m', 'pip']:\n"
            "    sys.exit(0)\n"
            "if len(sys.argv) >= 2 and sys.argv[1] == 'manage.py':\n"
            "    sys.exit(0)\n"
            "if len(sys.argv) >= 2 and sys.argv[1] == '-':\n"
            "    src = sys.stdin.read()\n"
            "    if 'operator_settings' in src:\n"
            "        print('{\"SECRET_KEY\":\"\",\"ALLOWED_HOSTS\":[],\"CSRF_TRUSTED_ORIGINS\":[]}')\n"
            "    sys.exit(0)\n"
            "sys.exit(0)\n",
            encoding="utf-8",
        )
        py_bin.chmod(0o755)
        (bin_dir / "python3").symlink_to(py_bin)
        pip_bin = bin_dir / "pip"
        pip_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        pip_bin.chmod(0o755)
        sys.exit(0)
    if args == ["-"] and os.environ.get("AF_SEED_USER"):
        sys.exit(0)
    python = os.environ["AF_REAL_PYTHON3"]
    os.execv(python, [python, *args])

if cmd == "su":
    if "-c" in args:
        call = args[args.index("-c") + 1]
        res = subprocess.run(["/bin/bash", "-c", call], input=sys.stdin.read(), text=True)
        sys.exit(res.returncode)
    sys.exit(0)

if cmd == "runuser":
    if "--" in args:
        inner = args[args.index("--") + 1 :]
        while inner and inner[0] == "env":
            inner = inner[1:]
            while inner and (inner[0].startswith("-") or "=" in inner[0]):
                inner = inner[1:]
        if inner and inner[0] == "git":
            real_git = os.environ["AF_REAL_GIT"]
            sys.exit(subprocess.run([real_git, *inner[1:]]).returncode)
        if inner and inner[0] == "cp":
            sys.exit(subprocess.run(["/bin/cp", *inner[1:]]).returncode)
        if inner and inner[0] == "rustc" and "--version" in inner:
            print("rustc 1.90.0 (fixture)")
            sys.exit(0)
        if inner and inner[0] == "cargo":
            manifest = pathlib.Path(inner[inner.index("--manifest-path") + 1])
            out = manifest.parent / "target/release/piped-proxy"
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            out.chmod(0o755)
            sys.exit(0)
        if inner and inner[0] == "bash" and any("gradlew" in a for a in inner):
            bdir = pathlib.Path(inner[-1])
            jar = bdir / "build/libs/piped-1.0-all.jar"
            jar.parent.mkdir(parents=True, exist_ok=True)
            jar.write_text("fixture-piped-jar\n", encoding="utf-8")
            sys.exit(0)
        if inner and inner[0] == "bash" and any("pnpm" in a for a in inner):
            fdir = pathlib.Path(inner[-3])
            dist = fdir / "dist"
            dist.mkdir(parents=True, exist_ok=True)
            (dist / "index.html").write_text("<html>piped</html>\n", encoding="utf-8")
            sys.exit(0)
        if inner and inner[0] in ("psql", "pg_dump", "npm"):
            if inner[0] == "pg_dump":
                print("-- fixture dump")
            sys.exit(0)
    sys.exit(0)

if cmd == "cargo":
    if "--manifest-path" in args:
        manifest = pathlib.Path(args[args.index("--manifest-path") + 1])
        out = manifest.parent / "target/release/mcvnc"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        out.chmod(0o755)
    sys.exit(0)

if cmd == "rustc":
    if "--version" in args:
        print("rustc 1.90.0 (fixture)")
    sys.exit(0)

if cmd == "curl":
    if any("http_code" in a for a in args):
        print("200")
    elif any("ifconfig.me" in a for a in args):
        print("192.0.2.55")
    sys.exit(0)

if cmd == "stat":
    if len(args) >= 3 and args[0] == "-c" and args[1] == "%u" and pathlib.Path(args[2]).name in ("cargo", "rustc"):
        print("0")
        sys.exit(0)
    sys.exit(subprocess.run(["/usr/bin/stat", *args]).returncode)

if cmd == "install":
    cleaned = []
    i = 0
    while i < len(args):
        if args[i] in ("-o", "-g"):
            i += 2
            continue
        cleaned.append(args[i])
        i += 1
    sys.exit(subprocess.run(["/usr/bin/install", *cleaned]).returncode)

if cmd == "chmod":
    sys.exit(subprocess.run(["/bin/chmod", *args]).returncode)

if cmd == "node":
    print("v20.18.0")
    sys.exit(0)

if cmd in ("wg",):
    if args == ["genkey"]:
        print("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    elif args == ["pubkey"]:
        _ = sys.stdin.read()
        print("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
    elif args[:2] == ["show", "wg0"]:
        print("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
    sys.exit(0)

if cmd == "ip":
    if args[:3] == ["route", "show", "default"]:
        print("default via 192.0.2.1 dev eth0")
    elif args == ["-o", "link", "show", "dev", "wg0"]:
        print("4: wg0: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420")
    sys.exit(0)

if cmd == "hostname":
    print("192.0.2.55")
    sys.exit(0)

sys.exit(0)
"""


def _load_common_sh_base() -> str:
    source = (ROOT / "packages/common.sh").read_text(encoding="utf-8")
    names = re.findall(r"(?m)^([a-zA-Z_][a-zA-Z0-9_-]*)\(\) [({]$", source)
    return common_functions(*(n for n in names if n != "seed_jellyfin_master_user"))


_COMMON_SH_BASE = _load_common_sh_base()
_YOUTUBE_COMMON_RAW = (ROOT / "packages/youtube-common.sh").read_text(encoding="utf-8")


class HardeningFixture:
    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="af-pin-hardening-")
        self.root = Path(self._tmp.name)
        for rel in (
            "mock-bin",
            "opt/AetherFlow/packages",
            "var/log/aetherflow",
            "var/backups",
            "var/lib",
            "var/www",
            "var/tmp",
            "etc/systemd/system",
            "etc/apache2/sites-available",
            "etc/apache2/sites-enabled",
            "etc/apache2/conf-available",
            "etc/apache2/conf-enabled",
            "etc/apt/keyrings",
            "etc/apt/sources.list.d",
            "etc/default",
            "etc/sysctl.d",
            "run/lock",
            "install",
            "tmp",
            "home",
            "usr/bin",
            "usr/sbin",
            "usr/local/bin",
            "proc",
        ):
            (self.root / rel).mkdir(parents=True, exist_ok=True)
        (self.root / "etc/os-release").write_text("ID=debian\nVERSION_CODENAME=bookworm\n", encoding="utf-8")

        py_mock_cmds = (
            "git",
            "systemctl",
            "dpkg",
            "dpkg-deb",
            "dpkg-query",
            "apt-get",
            "python3",
            "su",
            "runuser",
            "cargo",
            "rustc",
            "curl",
            "stat",
            "install",
            "wg",
            "ip",
            "hostname",
        )
        fast_noop_cmds = (
            "npm",
            "flock",
            "id",
            "useradd",
            "usermod",
            "getent",
            "chown",
            "a2enmod",
            "a2ensite",
            "a2dissite",
            "apache2ctl",
            "sqlite3",
            "sysctl",
            "sleep",
        )
        py_dispatch = self.root / "mock-bin/_dispatch.py"
        py_dispatch.write_text(MOCK_BIN, encoding="utf-8")
        py_dispatch.chmod(0o755)
        for cmd in py_mock_cmds:
            p = self.root / "mock-bin" / cmd
            p.symlink_to(py_dispatch)
            for mirror in ("usr/bin", "usr/local/bin", "usr/sbin"):
                (self.root / mirror / cmd).symlink_to(p)

        fast_noop = self.root / "mock-bin/_noop.sh"
        fast_noop.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fast_noop.chmod(0o755)
        for cmd in fast_noop_cmds:
            p = self.root / "mock-bin" / cmd
            p.symlink_to(fast_noop)
            for mirror in ("usr/bin", "usr/local/bin", "usr/sbin"):
                (self.root / mirror / cmd).symlink_to(p)

        node_stub = self.root / "mock-bin/node"
        node_stub.write_text("#!/bin/sh\necho v20.18.0\n", encoding="utf-8")
        node_stub.chmod(0o755)
        for mirror in ("usr/bin", "usr/local/bin", "usr/sbin"):
            (self.root / mirror / "node").symlink_to(node_stub)

        helpers = rebase_paths(_COMMON_SH_BASE, self.root)
        overrides = r"""
set -euo pipefail
MASTER_USER=test-admin
MASTER_PASS=test-password
LOCK_DIR="$AF_TEST_ROOT/install"
export AF_JOB_SCRATCH_ROOT="$AF_TEST_ROOT/var/tmp"
export AF_JOB_SCRATCH_DIR="$AF_TEST_ROOT/var/tmp/scratch"
mkdir -p "$AF_JOB_SCRATCH_DIR"
require_root() { :; }
load_master_credentials() { :; }
ensure_node() { :; }
sync_node_global_bins() { :; }
get_base_domain() { printf 'example.test\n'; }
wait_for_service_ready() { :; }
wait_for_apache_app_ready() { :; }
af_wait_local_web_services() { printf 'http://127.0.0.1:8083/login\n'; }
apache_app_enter_maintenance() { :; }
apache_app_activate_vhost() { touch "$AF_TEST_ROOT/service_active_apache2"; }
apache_app_quiesce_for_rollback() { :; }
apache_app_resume_after_rollback() { :; }
configure_apache_app_listener() { :; }
install_apt_signing_key() { printf 'mock-key\n' > "$2"; }
download_file() {
    if [[ "${1:-}" == "--transport" ]]; then
        shift
        command curl "$@"
        return $?
    fi
    printf '["download_file","%s","%s"]\n' "$1" "$2" >> "$AF_TEST_ROOT/commands.jsonl"
    if [[ "${AF_MOCK_DOWNLOAD_FAIL:-0}" == "1" ]]; then
        return 1
    fi
    printf '%s\n' "${AF_MOCK_DOWNLOAD_PAYLOAD:-2.20.0}" > "$2"
    return 0
}
write_lock() { touch "$AF_TEST_ROOT/install/.$1.lock"; INSTALL_COMMITTED=true; [[ -z "${AF_ARCHIVE_BACKUP:-}" ]] || rm -f "$AF_ARCHIVE_BACKUP/.af-archive-pending"; }
lock_path() { printf '%s/install/.%s.lock\n' "$AF_TEST_ROOT" "$1"; }
remove_lock() { rm -f "$AF_TEST_ROOT/install/.$1.lock"; }
purge_systemd_unit() { :; }
seed_jellyfin_master_user() { :; }
af_prepare_job_scratch() { export AF_JOB_SCRATCH_DIR="$AF_TEST_ROOT/var/tmp/scratch"; mkdir -p "$AF_JOB_SCRATCH_DIR"; }
af_cleanup_job_scratch() { :; }
"""
        (self.root / "opt/AetherFlow/packages/common.sh").write_text(
            helpers + "\n" + overrides, encoding="utf-8"
        )
        yt_common = rebase_paths(_YOUTUBE_COMMON_RAW, self.root)
        (self.root / "opt/AetherFlow/packages/youtube-common.sh").write_text(yt_common, encoding="utf-8")

    def cleanup(self):
        self._tmp.cleanup()

    def commands(self) -> list[list[str]]:
        log = self.root / "commands.jsonl"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]

    def reset_commands(self):
        log = self.root / "commands.jsonl"
        if log.exists():
            log.unlink()

    def make_bare_repo(self, name: str, commits: list[dict], default_branch: str = "main") -> tuple[Path, dict[str, str]]:
        origin = self.root / f"repos/{name}.git"
        work = self.root / f"repos/{name}-work"
        origin.mkdir(parents=True, exist_ok=True)
        work.mkdir(parents=True, exist_ok=True)
        run_git(origin, "init", "--bare", "-b", default_branch)
        run_git(work, "init", "-b", default_branch)

        recorded: dict[str, str] = {}
        extra_branches: list[str] = []
        for entry in commits:
            for rel, content in entry.get("files", {}).items():
                fp = work / rel
                fp.parent.mkdir(parents=True, exist_ok=True)
                fp.write_text(content, encoding="utf-8")
            run_git(work, "add", "-A")
            run_git(work, "commit", "-m", entry["message"])
            sha = run_git(work, "rev-parse", "HEAD")
            recorded[entry["id"]] = sha
            for tag in entry.get("annotated_tags", []):
                run_git(work, "tag", "-a", tag, "-m", f"Release {tag}")
            for tag in entry.get("tags", []):
                run_git(work, "tag", tag)
            for branch in entry.get("branches", []):
                run_git(work, "branch", branch, sha)
                extra_branches.append(branch)

        run_git(work, "remote", "add", "origin", f"file://{origin}")
        push_refs = [f"refs/heads/{default_branch}:refs/heads/{default_branch}"]
        for branch in extra_branches:
            push_refs.append(f"refs/heads/{branch}:refs/heads/{branch}")
        run_git(work, "push", "origin", *push_refs, "--tags")
        return origin, recorded

    def run_installer(
        self,
        package: str,
        repo_map: dict[str, Path] | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        script_path = ROOT / f"packages/package/install/installpackage-{package}"
        rebased = rebase_paths(script_path.read_text(encoding="utf-8"), self.root)
        rebased = rebased.replace(
            '${SELF_DIR}/../../common.sh', str(self.root / "opt/AetherFlow/packages/common.sh")
        )
        rebased = rebased.replace(
            '${SELF_DIR}/../../youtube-common.sh', str(self.root / "opt/AetherFlow/packages/youtube-common.sh")
        )
        staged = self.root / f"run-install-{package}.sh"
        staged.write_text(rebased, encoding="utf-8")
        staged.chmod(0o755)

        env = {
            **os.environ,
            "PATH": f"{self.root}/mock-bin:/usr/bin:/bin",
            "HOME": str(self.root / "home"),
            "TMPDIR": str(self.root / "tmp"),
            "AF_TEST_ROOT": str(self.root),
            "AF_PROC_ROOT": str(self.root / "proc"),
            "AF_REAL_GIT": REAL_GIT,
            "AF_REAL_PYTHON3": REAL_PYTHON3,
            "AETHERFLOW_INSTALL_ROOT": str(self.root),
            "AETHERFLOW_APACHE_ROOT": str(self.root / "etc/apache2"),
            "AETHERFLOW_SKIP_PROVENANCE_VERIFY": "1",
        }
        for key in ("AF_TARGET_VERSION", "PIPED_TARGET_VERSION", "AF_ALLOW_DOWNGRADE", "TEST_ROOT", "AF_FIXTURE_ROOT"):
            env.pop(key, None)

        if repo_map:
            env["GIT_CONFIG_COUNT"] = str(len(repo_map))
            for idx, (remote_url, local_bare) in enumerate(repo_map.items()):
                env[f"GIT_CONFIG_KEY_{idx}"] = f"url.file://{local_bare}.insteadOf"
                env[f"GIT_CONFIG_VALUE_{idx}"] = remote_url

        if extra_env:
            for k, v in extra_env.items():
                if v is None:
                    env.pop(k, None)
                else:
                    env[k] = v

        return subprocess.run(
            ["/bin/bash", str(staged)],
            env=env,
            stdin=subprocess.DEVNULL,
            text=True,
            capture_output=True,
            timeout=45,
        )

    def run_helper(
        self,
        bash_code: str,
        repo_map: dict[str, Path] | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        env = {
            **os.environ,
            "PATH": f"{self.root}/mock-bin:/usr/bin:/bin",
            "HOME": str(self.root / "home"),
            "TMPDIR": str(self.root / "tmp"),
            "AF_TEST_ROOT": str(self.root),
            "AF_REAL_GIT": REAL_GIT,
            "AF_REAL_PYTHON3": REAL_PYTHON3,
            "LOGFILE": str(self.root / "var/log/aetherflow/helper.log"),
        }
        for key in ("AF_TARGET_VERSION", "PIPED_TARGET_VERSION", "TEST_ROOT", "AF_FIXTURE_ROOT"):
            env.pop(key, None)
        if repo_map:
            env["GIT_CONFIG_COUNT"] = str(len(repo_map))
            for idx, (remote_url, local_bare) in enumerate(repo_map.items()):
                env[f"GIT_CONFIG_KEY_{idx}"] = f"url.file://{local_bare}.insteadOf"
                env[f"GIT_CONFIG_VALUE_{idx}"] = remote_url
        if extra_env:
            for k, v in extra_env.items():
                if v is None:
                    env.pop(k, None)
                else:
                    env[k] = v
        script = (
            f'source "{self.root}/opt/AetherFlow/packages/common.sh"\n'
            f'source "{self.root}/opt/AetherFlow/packages/youtube-common.sh"\n'
            f"{bash_code}\n"
        )
        return subprocess.run(
            ["/bin/bash", "-euo", "pipefail", "-c", script],
            env=env,
            stdin=subprocess.DEVNULL,
            text=True,
            capture_output=True,
            timeout=30,
        )


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "Requires Linux Bash")
class MarketplaceVersionPinningHardeningTests(unittest.TestCase):
    def setUp(self):
        self.fx = HardeningFixture()
        self.addCleanup(self.fx.cleanup)

    # 1. Audiobookshelf P1: fail closed under AF_TARGET_VERSION instead of unversioned PPA fallback
    def test_audiobookshelf_fails_closed_under_af_target_version_without_ppa_fallback(self):
        opt_dir = self.fx.root / "opt/audiobookshelf"
        opt_dir.mkdir(parents=True, exist_ok=True)
        (opt_dir / ".af-version").write_text("2.10.0\n", encoding="utf-8")
        (self.fx.root / "installed_deb_version").write_text("2.10.0", encoding="utf-8")
        (self.fx.root / "service_active_audiobookshelf").touch()
        (self.fx.root / "service_enabled_audiobookshelf").touch()
        (self.fx.root / "etc/systemd/system/audiobookshelf.service").write_text("[Unit]\nDescription=Prior\n", encoding="utf-8")

        res = self.fx.run_installer(
            "audiobookshelf",
            extra_env={"AF_TARGET_VERSION": "2.20.0", "AF_MOCK_DOWNLOAD_FAIL": "1"},
        )
        self.assertNotEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("refusing unversioned PPA fallback", res.stderr)
        self.assertFalse((self.fx.root / "etc/apt/sources.list.d/audiobookshelf.list").exists())
        self.assertFalse((self.fx.root / "etc/apt/keyrings/audiobookshelf-archive-keyring.gpg").exists())
        cmds = self.fx.commands()
        self.assertFalse(any(c[0] == "apt-get" and "audiobookshelf" in c for c in cmds), cmds)
        self.assertEqual((opt_dir / ".af-version").read_text(encoding="utf-8").strip(), "2.10.0")
        self.assertTrue((self.fx.root / "service_active_audiobookshelf").exists())

    def test_audiobookshelf_rejects_mismatched_deb_and_invalid_targets_but_keeps_unpinned_ppa_fallback(self):
        # Mismatched .deb Version header fails before dpkg -i
        self.fx.reset_commands()
        res_mismatch = self.fx.run_installer(
            "audiobookshelf",
            extra_env={
                "AF_TARGET_VERSION": "2.20.0",
                "AF_MOCK_DOWNLOAD_PAYLOAD": "2.37.2",
                "AF_MOCK_DEB_VER": "2.37.2",
            },
        )
        self.assertNotEqual(res_mismatch.returncode, 0)
        self.assertIn("does not match requested target", res_mismatch.stderr)
        self.assertFalse(any(c[0] == "dpkg" and "-i" in c for c in self.fx.commands()))

        # Invalid target tokens fail before download
        for bad_target in ("../evil", "--flag", "latest"):
            with self.subTest(bad_target=bad_target):
                self.fx.reset_commands()
                res_bad = self.fx.run_installer("audiobookshelf", extra_env={"AF_TARGET_VERSION": bad_target})
                self.assertNotEqual(res_bad.returncode, 0)
                self.assertFalse(any(c[0] == "download_file" for c in self.fx.commands()))

        # Unpinned download failure retains PPA fallback
        self.fx.reset_commands()
        res_unpinned = self.fx.run_installer(
            "audiobookshelf",
            extra_env={
                "AF_MOCK_DOWNLOAD_FAIL": "1",
                "AF_MOCK_PPA_VER": "2.37.2",
                "AF_ALLOW_RELEASE_FALLBACK": "1",
            },
        )
        self.assertEqual(res_unpinned.returncode, 0, res_unpinned.stdout + res_unpinned.stderr)
        self.assertTrue((self.fx.root / "etc/apt/sources.list.d/audiobookshelf.list").is_file())
        self.assertEqual((self.fx.root / "opt/audiobookshelf/.af-version").read_text(encoding="utf-8").strip(), "2.37.2")

    # 2A. Piped P1: 3-component verification, partial single-SHA rejection, no premature write
    def test_piped_rejects_partial_single_sha_and_unsafe_component_refs(self):
        piped_src = (ROOT / "packages/package/install/installpackage-piped").read_text(encoding="utf-8")
        self.assertNotIn('write_piped_receipt_safely "${INSTALL_DIR}" ".af-version"', piped_src)

        bad_targets = (
            "deadbeef1234",
            "a" * 40,
            "frontend=deadbeef1234",
            "frontend=deadbeef1234,backend=cafebabe1234",
            "frontend=--upload-pack=evil,backend=cafebabe1234,proxy=0123456789ab",
            "frontend=main,backend=cafebabe1234,proxy=0123456789ab",
            "frontend:HEAD,backend:cafebabe1234,proxy:0123456789ab",
        )
        for bad in bad_targets:
            with self.subTest(target=bad):
                self.fx.reset_commands()
                res = self.fx.run_installer("piped", extra_env={"AF_TARGET_VERSION": bad})
                self.assertNotEqual(res.returncode, 0, f"Expected failure for {bad!r}")
                self.assertFalse(any(c[0] in ("git", "apt-get") for c in self.fx.commands()))
                self.assertFalse((self.fx.root / "opt/piped/.af-version").exists())
                self.assertFalse((self.fx.root / "opt/piped/.af-components.json").exists())

    def test_piped_end_to_end_3_component_short_sha_equals_and_tag_colon_manifests(self):
        fe_bare, fe_shas = self.fx.make_bare_repo(
            "piped-fe",
            [
                {"id": "v1", "message": "fe v1", "files": {"package.json": '{"name":"fe","version":"1.0.0"}\n'}, "annotated_tags": ["v1.0.0"]},
                {"id": "v2", "message": "fe v2", "files": {"package.json": '{"name":"fe","version":"2.0.0"}\n'}, "branches": ["v1.0.0"]},
            ],
        )
        be_bare, be_shas = self.fx.make_bare_repo(
            "piped-be",
            [
                {
                    "id": "v1",
                    "message": "be v1",
                    "files": {"src/main/java/me/kavin/piped/server/ServerLauncher.java": "new InetSocketAddress(Constants.PORT)\n"},
                    "tags": ["v2.0.0"],
                },
                {
                    "id": "v2",
                    "message": "be v2",
                    "files": {"src/main/java/me/kavin/piped/server/ServerLauncher.java": "new InetSocketAddress(Constants.PORT) // v2\n"},
                },
            ],
        )
        pr_bare, pr_shas = self.fx.make_bare_repo(
            "piped-pr",
            [
                {"id": "v1", "message": "pr v1", "files": {"Cargo.toml": '[package]\nname="piped-proxy"\nversion="1.0.0"\n'}, "annotated_tags": ["v3.0.0"]},
                {"id": "v2", "message": "pr v2", "files": {"Cargo.toml": '[package]\nname="piped-proxy"\nversion="2.0.0"\n'}},
            ],
        )
        repo_map = {
            "https://github.com/TeamPiped/Piped.git": fe_bare,
            "https://github.com/TeamPiped/Piped-Backend.git": be_bare,
            "https://github.com/TeamPiped/Piped-Proxy.git": pr_bare,
        }

        # 1. '=' separator + uppercase/lowercase short SHAs + reordered keys
        target_eq = f"proxy={pr_shas['v1'][:10].upper()},frontend={fe_shas['v1'][:10]},backend={be_shas['v1'][:12]}"
        res_eq = self.fx.run_installer("piped", repo_map=repo_map, extra_env={"AF_TARGET_VERSION": target_eq})
        self.assertEqual(res_eq.returncode, 0, res_eq.stdout + res_eq.stderr)
        expected_v1 = f"frontend:{fe_shas['v1']},backend:{be_shas['v1']},proxy:{pr_shas['v1']}"
        self.assertEqual((self.fx.root / "opt/piped/.af-version").read_text(encoding="utf-8").strip(), expected_v1)
        self.assertEqual(
            json.loads((self.fx.root / "opt/piped/.af-components.json").read_text(encoding="utf-8")),
            {"frontend": fe_shas["v1"], "backend": be_shas["v1"], "proxy": pr_shas["v1"]},
        )
        self.assertEqual(run_git(self.fx.root / "opt/piped/frontend", "rev-parse", "HEAD"), fe_shas["v1"])
        self.assertEqual(run_git(self.fx.root / "opt/piped/backend", "rev-parse", "HEAD"), be_shas["v1"])
        self.assertEqual(run_git(self.fx.root / "opt/piped/proxy", "rev-parse", "HEAD"), pr_shas["v1"])

        # 2. ':' separator + tags (including annotated tag with branch collision on frontend v1.0.0!)
        target_tags = "frontend:1.0.0,backend:v2.0.0,proxy:3.0.0"
        res_tags = self.fx.run_installer("piped", repo_map=repo_map, extra_env={"AF_TARGET_VERSION": target_tags})
        self.assertEqual(res_tags.returncode, 0, res_tags.stdout + res_tags.stderr)
        self.assertEqual((self.fx.root / "opt/piped/.af-version").read_text(encoding="utf-8").strip(), expected_v1)
        self.assertEqual(run_git(self.fx.root / "opt/piped/frontend", "rev-parse", "HEAD"), fe_shas["v1"])

        # 3. Nonexistent SHA in one component fails closed and preserves prior receipts
        bad_manifest = f"frontend={fe_shas['v2'][:10]},backend={be_shas['v2'][:10]},proxy=deadbeefdead"
        res_bad = self.fx.run_installer("piped", repo_map=repo_map, extra_env={"AF_TARGET_VERSION": bad_manifest})
        self.assertNotEqual(res_bad.returncode, 0)
        self.assertEqual((self.fx.root / "opt/piped/.af-version").read_text(encoding="utf-8").strip(), expected_v1)

        # 4. Conflicting PIPED_TARGET_VERSION vs AF_TARGET_VERSION fails closed
        res_conflict = self.fx.run_installer(
            "piped",
            repo_map=repo_map,
            extra_env={
                "PIPED_TARGET_VERSION": target_eq,
                "AF_TARGET_VERSION": f"frontend={fe_shas['v2'][:10]},backend={be_shas['v2'][:10]},proxy={pr_shas['v2'][:10]}",
            },
        )
        self.assertNotEqual(res_conflict.returncode, 0)
        self.assertIn("Conflicting PIPED_TARGET_VERSION and AF_TARGET_VERSION", res_conflict.stderr)
        self.assertEqual((self.fx.root / "opt/piped/.af-version").read_text(encoding="utf-8").strip(), expected_v1)

    def test_piped_record_version_never_writes_receipts_when_commit_or_target_fails(self):
        piped_src = (ROOT / "packages/package/install/installpackage-piped").read_text(encoding="utf-8")
        err_start = piped_src.index("_piped_err() {")
        err_end = piped_src.index("\n}\n", err_start) + 3
        receipt_start = piped_src.index("write_piped_receipt_safely() {")
        receipt_end = piped_src.index("\n}\n", receipt_start) + 3
        rec_start = piped_src.index('af_set_stage "record_version" 95')
        rec_end = piped_src.index("write_lock piped", rec_start)
        rec_block = piped_src[rec_start:rec_end]

        install_dir = self.fx.root / "opt/piped-rec-test"
        data_dir = self.fx.root / "var/lib/piped-rec-test"
        install_dir.mkdir(parents=True, exist_ok=True)
        data_dir.mkdir(parents=True, exist_ok=True)
        shas = {}
        for comp in ("frontend", "backend", "proxy"):
            cdir = install_dir / comp
            cdir.mkdir()
            run_git(cdir, "init", "-b", "main")
            (cdir / "f.txt").write_text(f"{comp}\n", encoding="utf-8")
            run_git(cdir, "add", "f.txt")
            run_git(cdir, "commit", "-m", comp)
            shas[comp] = run_git(cdir, "rev-parse", "HEAD")

        ver_file = install_dir / ".af-version"
        comp_file = install_dir / ".af-components.json"
        prior_ver = "frontend:1111111111111111111111111111111111111111,backend:2222222222222222222222222222222222222222,proxy:3333333333333333333333333333333333333333\n"
        prior_comp = '{"frontend":"old","backend":"old","proxy":"old"}\n'
        ver_file.write_text(prior_ver, encoding="utf-8")
        comp_file.write_text(prior_comp, encoding="utf-8")

        # Tampered/mismatched proxy ref must fail before queue_app_version/commit_app_versions and leave both files untouched
        snippet = f"""
APP_NAME=""
INSTALL_DIR="{install_dir}"
DATA_DIR="{data_dir}"
AF_TARGET_VERSION="frontend={shas['frontend'][:10]},backend={shas['backend'][:10]},proxy=deadbeefcafe"
PIPED_FRONTEND_REF="{shas['frontend'][:10]}"
PIPED_BACKEND_REF="{shas['backend'][:10]}"
PIPED_PROXY_REF="deadbeefcafe"
af_set_stage() {{ :; }}
run_as_piped_clean_env() {{ shift; "$@"; }}
{piped_src[err_start:err_end]}
{piped_src[receipt_start:receipt_end]}
{rec_block}
"""
        res = self.fx.run_helper(snippet)
        self.assertNotEqual(res.returncode, 0)
        self.assertEqual(ver_file.read_text(encoding="utf-8"), prior_ver)
        self.assertEqual(comp_file.read_text(encoding="utf-8"), prior_comp)

    # 2B. SeedCross P1: git_stage_exact_revision tag receipts, uppercase SHA, untagged head fallback
    def test_seedcross_tag_uppercase_sha_collision_and_untagged_head(self):
        bare, shas = self.fx.make_bare_repo(
            "seedcross",
            [
                {
                    "id": "v1_2_0",
                    "message": "seedcross v1.2.0",
                    "files": {
                        "manage.py": "# v1.2.0\n",
                        "csui/__init__.py": "",
                        "csui/settings.py": 'SECRET_KEY = "django-insecure-test"\nALLOWED_HOSTS = []\nMIDDLEWARE = []\nDATABASES = {"default": {"NAME": "db.sqlite3"}}\n',
                        "requirements.txt": "django\n",
                    },
                    "annotated_tags": ["v1.2.0"],
                },
                {
                    "id": "v1_3_0",
                    "message": "seedcross v1.3.0",
                    "files": {"manage.py": "# v1.3.0\n"},
                    "tags": ["v1.3.0"],
                },
                {
                    "id": "untagged_head",
                    "message": "untagged head + branch v1.3.0 collision",
                    "files": {"manage.py": "# untagged-head\n"},
                    "branches": ["v1.3.0"],
                },
            ],
        )
        repo_map = {"https://github.com/ccf-2012/seedcross.git": bare}

        # 1. Explicit unprefixed tag target queues stripped tag version matching AF_TARGET_VERSION
        res_tag = self.fx.run_installer("seedcross", repo_map=repo_map, extra_env={"AF_TARGET_VERSION": "1.2.0"})
        self.assertEqual(res_tag.returncode, 0, res_tag.stdout + res_tag.stderr)
        self.assertEqual((self.fx.root / "opt/seedcross/.af-version").read_text(encoding="utf-8").strip(), "1.2.0")
        self.assertEqual(run_git(self.fx.root / "opt/seedcross", "rev-parse", "HEAD"), shas["v1_2_0"])

        # 2. Tag colliding with branch selects exact tag commit (v1_3_0, NOT untagged_head!)
        res_col = self.fx.run_installer("seedcross", repo_map=repo_map, extra_env={"AF_TARGET_VERSION": "v1.3.0"})
        self.assertEqual(res_col.returncode, 0, res_col.stdout + res_col.stderr)
        self.assertEqual((self.fx.root / "opt/seedcross/.af-version").read_text(encoding="utf-8").strip(), "1.3.0")
        self.assertEqual(run_git(self.fx.root / "opt/seedcross", "rev-parse", "HEAD"), shas["v1_3_0"])

        # 3. Uppercase short commit SHA succeeds case-insensitively and records full lowercase SHA
        res_sha = self.fx.run_installer(
            "seedcross",
            repo_map=repo_map,
            extra_env={"AF_TARGET_VERSION": shas["untagged_head"][:12].upper(), "AF_ALLOW_DOWNGRADE": "1"},
        )
        self.assertEqual(res_sha.returncode, 0, res_sha.stdout + res_sha.stderr)
        self.assertEqual((self.fx.root / "opt/seedcross/.af-version").read_text(encoding="utf-8").strip(), shas["untagged_head"])
        self.assertEqual(run_git(self.fx.root / "opt/seedcross", "rev-parse", "HEAD"), shas["untagged_head"])

        # 4. Option injection & floating ref rejected
        for bad in ("--upload-pack=evil", "main", "HEAD", "latest"):
            with self.subTest(bad=bad):
                res_bad = self.fx.run_installer("seedcross", repo_map=repo_map, extra_env={"AF_TARGET_VERSION": bad})
                self.assertNotEqual(res_bad.returncode, 0)

        # 5. Untagged-only repo falls back cleanly to verified remote HEAD commit on unpinned install
        untagged_bare, untagged_shas = self.fx.make_bare_repo(
            "seedcross-untagged",
            [
                {
                    "id": "tip",
                    "message": "only commit",
                    "files": {
                        "manage.py": "# tip\n",
                        "csui/__init__.py": "",
                        "csui/settings.py": 'SECRET_KEY = "django-insecure-test"\nALLOWED_HOSTS = []\nMIDDLEWARE = []\nDATABASES = {"default": {"NAME": "db.sqlite3"}}\n',
                    },
                }
            ],
        )
        fx2 = HardeningFixture()
        self.addCleanup(fx2.cleanup)
        res_head = fx2.run_installer("seedcross", repo_map={"https://github.com/ccf-2012/seedcross.git": untagged_bare})
        self.assertEqual(res_head.returncode, 0, res_head.stdout + res_head.stderr)
        self.assertEqual((fx2.root / "opt/seedcross/.af-version").read_text(encoding="utf-8").strip(), untagged_shas["tip"])

    # 3A. Migrated git_stage_exact_revision installers + Tautulli duplicate stop removal
    def test_migrated_git_installers_static_and_end_to_end_collision_and_option_injection(self):
        tautulli_src = (ROOT / "packages/package/install/installpackage-tautulli").read_text(encoding="utf-8")
        self.assertEqual(tautulli_src.count("stop_systemd_unit tautulli"), 1)

        cases = (
            ("tautulli", "https://github.com/Tautulli/Tautulli.git", {"Tautulli.py": "# tautulli\n"}, "opt/Tautulli", "opt/Tautulli/.af-version", {}),
            ("calibreweb", "https://github.com/janeczku/calibre-web.git", {"cps.py": "# cps\n", "requirements.txt": "flask\n"}, "opt/calibre-web", "opt/calibre-web/.af-version", {"AF_APP_PORT": "8083"}),
            ("organizr", "https://github.com/causefx/Organizr.git", {"index.php": "<?php echo 'ok';\n", "api/config/default.php": "<?php\n"}, "var/www/organizr", "var/www/organizr/.af-version", {}),
            ("uptimekuma", "https://github.com/louislam/uptime-kuma.git", {"server/server.js": "// ok\n"}, "opt/uptime-kuma", "opt/uptime-kuma/.af-version", {}),
            ("mcvnc", "https://github.com/McEveritts/McVNC.git", {"Cargo.toml": '[package]\nname="mcvnc"\nversion="1.0.0"\n'}, None, "var/lib/mcvnc/.af-version", {}),
            ("flaresolverr", "https://github.com/FlareSolverr/FlareSolverr.git", {"src/flaresolverr.py": "print('ok')\n", "requirements.txt": "selenium\n"}, "opt/flaresolverr", "opt/flaresolverr/.af-version", {"AF_MOCK_ARCH": "arm64"}),
        )

        for pkg, remote_url, base_files, deployed_dir, version_rel, base_env in cases:
            installer_text = (ROOT / f"packages/package/install/installpackage-{pkg}").read_text(encoding="utf-8")
            self.assertIn("git_stage_exact_revision", installer_text, pkg)
            self.assertNotIn("git clone --branch", installer_text, pkg)
            self.assertNotIn("git clone --depth 1 --branch", installer_text, pkg)

            with self.subTest(package=pkg):
                fx = HardeningFixture()
                self.addCleanup(fx.cleanup)
                bare, shas = fx.make_bare_repo(
                    pkg,
                    [
                        {"id": "v1_0_0", "message": "v1.0.0", "files": {**base_files, "af_version_marker.js": "1.0.0\n"}, "annotated_tags": ["v1.0.0"]},
                        {"id": "v1_1_0", "message": "v1.1.0", "files": {**base_files, "af_version_marker.js": "1.1.0\n"}, "tags": ["v1.1.0"]},
                        {"id": "collision", "message": "branch v1.1.0 collision", "files": {**base_files, "af_version_marker.js": "COLLISION_BRANCH\n"}, "branches": ["v1.1.0"]},
                    ],
                )
                repo_map = {remote_url: bare}

                # Leading '-' option injection rejected before cloning
                for bad_target in ("--upload-pack=evil", "main", "HEAD", "latest"):
                    fx.reset_commands()
                    res_bad = fx.run_installer(pkg, repo_map=repo_map, extra_env={**base_env, "AF_TARGET_VERSION": bad_target})
                    self.assertNotEqual(res_bad.returncode, 0, f"{pkg} accepted bad target {bad_target!r}")
                    self.assertFalse(any(c[0] == "git" and "clone" in c for c in fx.commands()), f"{pkg} cloned on {bad_target!r}")

                # Unpinned install resolves v1.1.0 tag commit (c2), NOT colliding branch v1.1.0 (c3)
                res_latest = fx.run_installer(pkg, repo_map=repo_map, extra_env=base_env)
                self.assertEqual(res_latest.returncode, 0, f"{pkg}: {res_latest.stdout}{res_latest.stderr}")
                self.assertEqual((fx.root / version_rel).read_text(encoding="utf-8").strip(), "1.1.0")
                if deployed_dir is not None:
                    self.assertEqual((fx.root / deployed_dir / "af_version_marker.js").read_text(encoding="utf-8").strip(), "1.1.0")
                    self.assertEqual(run_git(fx.root / deployed_dir, "rev-parse", "HEAD"), shas["v1_1_0"])

                # Explicit pinned older annotated tag with AF_ALLOW_DOWNGRADE=1 resolves exact commit v1_0_0
                res_pin = fx.run_installer(
                    pkg,
                    repo_map=repo_map,
                    extra_env={**base_env, "AF_TARGET_VERSION": "1.0.0", "AF_ALLOW_DOWNGRADE": "1"},
                )
                self.assertEqual(res_pin.returncode, 0, f"{pkg}: {res_pin.stdout}{res_pin.stderr}")
                self.assertEqual((fx.root / version_rel).read_text(encoding="utf-8").strip(), "1.0.0")
                if deployed_dir is not None:
                    self.assertEqual((fx.root / deployed_dir / "af_version_marker.js").read_text(encoding="utf-8").strip(), "1.0.0")
                    self.assertEqual(run_git(fx.root / deployed_dir, "rev-parse", "HEAD"), shas["v1_0_0"])

    # 3B. youtube-common.sh: youtube_source & youtube_private_port hardening
    def test_youtube_source_guards_and_head_verification(self):
        bare, shas = self.fx.make_bare_repo(
            "yt-source",
            [
                {"id": "c1", "message": "v1.0.0", "files": {"app.txt": "1.0.0\n"}, "annotated_tags": ["v1.0.0"]},
                {"id": "c2", "message": "v1.1.0", "files": {"app.txt": "1.1.0\n"}, "tags": ["v1.1.0"]},
                {"id": "c3", "message": "collision + branch", "files": {"app.txt": "collision\n"}, "branches": ["v1.1.0", "feature-branch"]},
            ],
        )
        repo_map = {"https://github.com/TeamPiped/Piped.git": bare}

        # Reject option injection, floating refs, and untagged branches before cloning
        for bad in ("--upload-pack=evil", "-c", "HEAD", "main", "master", "latest", "feature-branch"):
            with self.subTest(bad=bad):
                dest = self.fx.root / f"yt-bad-{abs(hash(bad))}"
                res = self.fx.run_helper(
                    f'APP_NAME=""\nyoutube_source TeamPiped/Piped "{dest}" "$BAD_REF"',
                    repo_map=repo_map,
                    extra_env={"BAD_REF": bad},
                )
                self.assertNotEqual(res.returncode, 0, f"youtube_source accepted {bad!r}")
                self.assertFalse(dest.exists())

        # Tag with branch collision resolves exact tag commit (c2, NOT c3)
        dest_ok = self.fx.root / "yt-ok"
        res_tag = self.fx.run_helper(
            f'APP_NAME=""\nyoutube_source TeamPiped/Piped "{dest_ok}" "v1.1.0"',
            repo_map=repo_map,
        )
        self.assertEqual(res_tag.returncode, 0, res_tag.stdout + res_tag.stderr)
        self.assertEqual(run_git(dest_ok, "rev-parse", "HEAD"), shas["c2"])
        self.assertEqual((dest_ok / "app.txt").read_text(encoding="utf-8").strip(), "1.1.0")

        # Updating existing shallow clone to older uppercase short SHA resolves c1 cleanly
        res_sha = self.fx.run_helper(
            f'APP_NAME=""\nyoutube_source TeamPiped/Piped "{dest_ok}" "{shas["c1"][:10].upper()}"',
            repo_map=repo_map,
        )
        self.assertEqual(res_sha.returncode, 0, res_sha.stdout + res_sha.stderr)
        self.assertEqual(run_git(dest_ok, "rev-parse", "HEAD"), shas["c1"])

        # Injected HEAD verification mismatch fails closed
        dest_mismatch = self.fx.root / "yt-mismatch"
        res_mismatch = self.fx.run_helper(
            f'APP_NAME=""\nyoutube_source TeamPiped/Piped "{dest_mismatch}" "{shas["c1"]}"',
            repo_map=repo_map,
            extra_env={"AF_GIT_FAULT": "head_mismatch"},
        )
        self.assertNotEqual(res_mismatch.returncode, 0)
        self.assertIn("does not match expected commit", res_mismatch.stderr)

    def test_youtube_private_port_reallocates_on_app_port_collision_and_corrupt_file(self):
        cfg_dir = self.fx.root / "etc/piped"
        cfg_dir.mkdir(parents=True, exist_ok=True)
        (cfg_dir / "api-port").write_text("20000\n", encoding="utf-8")
        (cfg_dir / "proxy-port").write_text("20001\n", encoding="utf-8")

        # Non-colliding APP_PORT preserves persisted port
        res_keep = self.fx.run_helper(
            f'CONFIG_DIR="{cfg_dir}"\nAPP_PORT=8280\nyoutube_private_port api'
        )
        self.assertEqual(res_keep.returncode, 0, res_keep.stderr)
        self.assertEqual(res_keep.stdout.strip(), "20000")

        # Reinstalling on previously used private port (APP_PORT=20000) reallocates api-port away from 20000 and 20001
        res_realloc = self.fx.run_helper(
            f'CONFIG_DIR="{cfg_dir}"\nAPP_PORT=20000\n'
            'api_p="$(youtube_private_port api)"\n'
            'proxy_p="$(youtube_private_port proxy)"\n'
            'printf "%s,%s\\n" "$api_p" "$proxy_p"'
        )
        self.assertEqual(res_realloc.returncode, 0, res_realloc.stderr)
        api_p, proxy_p = res_realloc.stdout.strip().split(",")
        self.assertNotEqual(api_p, "20000")
        self.assertNotEqual(api_p, "20001")
        self.assertEqual(proxy_p, "20001")
        self.assertEqual((cfg_dir / "api-port").read_text(encoding="utf-8").strip(), api_p)

        # Invalid/privileged persisted port also reallocates cleanly
        (cfg_dir / "api-port").write_text("80\n", encoding="utf-8")
        res_bad_port = self.fx.run_helper(
            f'CONFIG_DIR="{cfg_dir}"\nAPP_PORT=8280\nyoutube_private_port api'
        )
        self.assertEqual(res_bad_port.returncode, 0, res_bad_port.stderr)
        new_port = int(res_bad_port.stdout.strip())
        self.assertGreaterEqual(new_port, 20000)
        self.assertNotEqual(new_port, 20001)

    # 4A. LibreSpeed P2: explicit AF_TARGET_VERSION < 4.0.0 fails closed
    def test_librespeed_rejects_explicit_target_version_below_4_0_0(self):
        for old_ver in ("3.9.0", "v3.1.7", "2.5.0", "1.1.5", "0.9.9"):
            with self.subTest(target=old_ver):
                self.fx.reset_commands()
                res = self.fx.run_installer("librespeed", extra_env={"AF_TARGET_VERSION": old_ver})
                self.assertNotEqual(res.returncode, 0, f"LibreSpeed accepted legacy version {old_ver!r}")
                self.assertIn(">= 4.0.0", res.stderr)
                self.assertFalse(any(c[0] in ("download_file", "curl") for c in self.fx.commands()))
                self.assertFalse((self.fx.root / "install/.librespeed.lock").exists())

    # 4B & 4C. WireGuard HTTPS-only curl & Unpackerr canonical org alignment
    def test_wireguard_https_proto_and_unpackerr_canonical_repo(self):
        wg_src = (ROOT / "packages/package/install/installpackage-wireguard").read_text(encoding="utf-8")
        self.assertIn("curl --proto '=https' --proto-redir '=https'", wg_src)

        res_wg = self.fx.run_installer("wireguard")
        self.assertEqual(res_wg.returncode, 0, res_wg.stdout + res_wg.stderr)
        curl_cmds = [c for c in self.fx.commands() if c[0] == "curl" and any("ifconfig.me" in a for a in c)]
        self.assertTrue(curl_cmds, "Expected WireGuard curl command to ifconfig.me")
        self.assertIn("--proto", curl_cmds[0])
        self.assertIn("=https", curl_cmds[0])
        self.assertIn("--proto-redir", curl_cmds[0])

        automation = json.loads((ROOT / "config/package_automation.json").read_text(encoding="utf-8"))
        self.assertEqual(automation["unpackerr"]["update_repo"], "Unpackerr/unpackerr")
        up_src = (ROOT / "packages/package/install/installpackage-unpackerr").read_text(encoding="utf-8")
        self.assertNotIn("davidnewhall/unpackerr", up_src)
        self.assertIn("https://github.com/Unpackerr/unpackerr/releases/download/", up_src)


if __name__ == "__main__":
    unittest.main()
