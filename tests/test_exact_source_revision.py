#!/usr/bin/env python3
"""Exact Git source revision selection and verification tests using local Git repos."""
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
from installer_test_helpers import common_functions, mock_rutorrent_backend

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


def run_git(cwd: Path, *args: str, env: dict[str, str] | None = None) -> str:
    merged_env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "AetherFlow Test",
        "GIT_AUTHOR_EMAIL": "test@aetherflow.invalid",
        "GIT_COMMITTER_NAME": "AetherFlow Test",
        "GIT_COMMITTER_EMAIL": "test@aetherflow.invalid",
        **(env or {}),
    }
    result = subprocess.run(
        [REAL_GIT, *args],
        cwd=str(cwd),
        env=merged_env,
        text=True,
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"git {' '.join(args)} failed ({result.returncode}): {result.stdout}{result.stderr}"
        )
    return result.stdout.strip()


MOCK_HOST_BIN = r"""#!/usr/bin/python3
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
    if fault == "checkout_fail" and "checkout" in args:
        sys.stderr.write("injected git checkout failure\n")
        sys.exit(1)
    if fault == "head_mismatch_after_checkout" and "rev-parse" in args and any("HEAD" in a for a in args):
        print("0000000000000000000000000000000000000000")
        sys.exit(0)
    if fault == "checkout_wrong_commit" and "checkout" in args:
        wrong_commit = os.environ["AF_GIT_WRONG_COMMIT"]
        rewritten = [wrong_commit if i == len(args) - 1 else a for i, a in enumerate(args)]
        res = subprocess.run([real_git, *rewritten])
        sys.exit(res.returncode)
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
        unit = units[0] if units else ""
        is_active = (root / f"service_active_{unit}").exists()
        is_enabled = (root / f"service_enabled_{unit}").exists()
        unit_file = root / f"etc/systemd/system/{unit}.service"
        load_state = "loaded" if (unit_file.exists() or is_active or is_enabled) else "not-found"
        print(f"LoadState={load_state}")
        print(f"UnitFileState={'enabled' if is_enabled else 'disabled'}")
        if is_active:
            print("ActiveState=active")
            print("SubState=running")
            print("MainPID=12345")
        else:
            print("ActiveState=inactive")
            print("SubState=dead")
            print("MainPID=0")
        sys.exit(0)
    if sub == "stop":
        for u in units:
            (root / f"service_active_{u}").unlink(missing_ok=True)
        sys.exit(0)
    if sub in ("start", "restart", "reload"):
        if os.environ.get("AF_FAIL_STAGE") == "start":
            sys.exit(1)
        for u in units:
            (root / f"service_active_{u}").touch()
        sys.exit(0)
    if sub == "enable":
        for u in units:
            (root / f"service_enabled_{u}").touch()
            if "--now" in args:
                if os.environ.get("AF_FAIL_STAGE") == "start":
                    sys.exit(1)
                (root / f"service_active_{u}").touch()
        sys.exit(0)
    if sub == "disable":
        for u in units:
            (root / f"service_enabled_{u}").unlink(missing_ok=True)
            if "--now" in args:
                (root / f"service_active_{u}").unlink(missing_ok=True)
        sys.exit(0)
    sys.exit(0)

if cmd == "python3":
    if len(args) >= 3 and args[0] == "-m" and args[1] == "venv":
        venv_dir = pathlib.Path(args[2])
        bin_dir = venv_dir / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        py_bin = bin_dir / "python"
        py_bin.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        py_bin.chmod(0o755)
        pip_bin = bin_dir / "pip"
        pip_bin.write_text(
            "#!/bin/sh\n"
            'exec "$AF_TEST_ROOT/mock-bin/pip" "$@"\n',
            encoding="utf-8",
        )
        pip_bin.chmod(0o755)
        sys.exit(0)
    python = os.environ["AF_REAL_PYTHON3"]
    os.execv(python, [python, *args])

if cmd in ("pip", "pip3"):
    if os.environ.get("AF_FAIL_STAGE") == "pip":
        sys.stderr.write("injected pip failure\n")
        sys.exit(1)
    sys.exit(0)

if cmd == "yarn":
    if os.environ.get("AF_FAIL_STAGE") == "build" and args and args[0] == "build":
        sys.stderr.write("injected yarn build failure\n")
        sys.exit(1)
    if args and args[0] == "build":
        cwd = pathlib.Path.cwd()
        (cwd / "dist").mkdir(parents=True, exist_ok=True)
        ver = "unknown"
        pkg_json = cwd / "package.json"
        if pkg_json.is_file():
            try:
                ver = json.loads(pkg_json.read_text(encoding="utf-8")).get("version", "unknown")
            except Exception:
                ver = "unknown"
        (cwd / "dist/index.js").write_text(f"// built overseerr {ver}\n", encoding="utf-8")
    sys.exit(0)

if cmd == "npm":
    if os.environ.get("AF_FAIL_STAGE") == "npm":
        sys.exit(1)
    sys.exit(0)

if cmd == "node":
    if args and args[0] in ("-v", "--version"):
        print("v20.18.0")
    sys.exit(0)

if cmd == "curl":
    if any("http_code" in a for a in args):
        print("200")
    sys.exit(0)

if cmd == "htpasswd":
    print(f"{args[-1]}:$2y$05$fixturehash")
    sys.exit(0)

if cmd == "dpkg":
    if "--compare-versions" in args:
        if os.path.exists("/usr/bin/dpkg"):
            sys.exit(subprocess.run(["/usr/bin/dpkg", *args]).returncode)
        sys.path.insert(0, os.environ["AF_TESTS_DIR"])
        from installer_test_helpers import dpkg_compare_versions_exit_code
        sys.exit(dpkg_compare_versions_exit_code(args))
    print("amd64")
    sys.exit(0)

if cmd in (
    "apt-get",
    "flock",
    "id",
    "useradd",
    "chown",
    "chmod",
    "a2enmod",
    "a2ensite",
    "a2dissite",
    "apache2ctl",
):
    if cmd == "chmod":
        sys.exit(subprocess.run(["/bin/chmod", *args]).returncode)
    sys.exit(0)

sys.exit(0)
"""


class ExactSourceRevisionFixture:
    def __init__(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="af-exact-rev-")
        self.root = Path(self._tmp.name)
        for rel in (
            "mock-bin",
            "opt/AetherFlow/packages",
            "var/log/aetherflow",
            "var/backups",
            "var/lib",
            "var/www",
            "etc/systemd/system",
            "etc/apache2/sites-available",
            "etc/apache2/conf-available",
            "etc/apache2/AetherFlow",
            "run/lock",
            "install",
            "tmp",
            "home",
            "usr/bin",
            "usr/local/bin",
            "mnt/local",
            "mnt/remote",
            "mnt/unionfs",
            "srv",
        ):
            (self.root / rel).mkdir(parents=True, exist_ok=True)

        mock_commands = (
            "git",
            "systemctl",
            "python3",
            "pip",
            "pip3",
            "yarn",
            "npm",
            "node",
            "curl",
            "htpasswd",
            "dpkg",
            "apt-get",
            "flock",
            "id",
            "useradd",
            "chown",
            "a2enmod",
            "a2ensite",
            "a2dissite",
            "apache2ctl",
        )
        for cmd in mock_commands:
            p = self.root / "mock-bin" / cmd
            p.write_text(MOCK_HOST_BIN, encoding="utf-8")
            p.chmod(0o755)
            for mirror in ("usr/bin", "usr/local/bin"):
                m = self.root / mirror / cmd
                shutil.copy2(p, m)

        # Build isolated common.sh with real production helpers + mocked root/readiness stubs
        source = (ROOT / "packages/common.sh").read_text(encoding="utf-8")
        names = re.findall(r"(?m)^([a-zA-Z_][a-zA-Z0-9_-]*)\(\) [({]$", source)
        helpers = rebase_paths(
            common_functions(*(n for n in names if n != "seed_jellyfin_master_user")),
            self.root,
        )
        overrides = r"""
set -euo pipefail
MASTER_USER=test-admin
MASTER_PASS=test-password
LOCK_DIR="$AF_TEST_ROOT/install"
require_root() { :; }
load_master_credentials() { :; }
ensure_node() { :; }
sync_node_global_bins() { :; }
get_base_domain() { printf 'example.test\n'; }
wait_for_service_ready() { :; }
write_lock() { touch "$AF_TEST_ROOT/install/.$1.lock"; INSTALL_COMMITTED=true; }
lock_path() { printf '%s/install/.%s.lock\n' "$AF_TEST_ROOT" "$1"; }
remove_lock() { rm -f "$AF_TEST_ROOT/install/.$1.lock"; }
purge_systemd_unit() { :; }
seed_jellyfin_master_user() { :; }
"""
        (self.root / "opt/AetherFlow/packages/common.sh").write_text(
            helpers + "\n" + overrides, encoding="utf-8"
        )

    def cleanup(self):
        self._tmp.cleanup()

    def commands(self) -> list[list[str]]:
        log = self.root / "commands.jsonl"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line.strip()]

    def reset_command_log(self):
        log = self.root / "commands.jsonl"
        if log.exists():
            log.unlink()

    def make_bare_repo(self, name: str, commits: list[dict], default_branch: str = "main") -> tuple[Path, dict[str, str]]:
        """Create a real local bare Git repository with specified commits, tags, and branches."""
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

    def run_package(
        self,
        package: str,
        action: str = "install",
        repo_map: dict[str, Path] | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        prefix = "remove" if action in ("remove", "uninstall") else "install"
        if package == "rutorrent" and prefix == "install":
            mock_rutorrent_backend(self.root / "mock-bin")
        script_path = ROOT / f"packages/package/{prefix}/{prefix}package-{package}"
        rebased = rebase_paths(script_path.read_text(encoding="utf-8"), self.root)
        staged_script = self.root / f"run-{prefix}-{package}.sh"
        staged_script.write_text(rebased, encoding="utf-8")
        staged_script.chmod(0o755)

        env = {
            **os.environ,
            "PATH": f"{self.root}/mock-bin:/usr/bin:/bin",
            "HOME": str(self.root / "home"),
            "TMPDIR": str(self.root / "tmp"),
            "AF_TEST_ROOT": str(self.root),
            "AF_REAL_GIT": REAL_GIT,
            "AF_REAL_PYTHON3": REAL_PYTHON3,
            "AF_TESTS_DIR": str(ROOT / "tests"),
            "AETHERFLOW_INSTALL_ROOT": str(self.root),
            "AETHERFLOW_APACHE_ROOT": str(self.root / "etc/apache2"),
            "AF_LIFECYCLE_ACTION": action,
            "AF_PACKAGE_ACTION": action,
            "DELETE_DATA": "false",
            "AETHERFLOW_SKIP_PROVENANCE_VERIFY": "1",
        }
        env.pop("AF_TARGET_VERSION", None)
        env.pop("AF_ALLOW_DOWNGRADE", None)

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
            ["/bin/bash", str(staged_script)],
            env=env,
            stdin=subprocess.DEVNULL,
            text=True,
            capture_output=True,
            timeout=60,
        )

    def run_helper(self, bash_code: str, extra_env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        env = {
            **os.environ,
            "PATH": f"{self.root}/mock-bin:/usr/bin:/bin",
            "HOME": str(self.root / "home"),
            "TMPDIR": str(self.root / "tmp"),
            "AF_TEST_ROOT": str(self.root),
            "AF_REAL_GIT": REAL_GIT,
            "AF_REAL_PYTHON3": REAL_PYTHON3,
            "AF_TESTS_DIR": str(ROOT / "tests"),
            "LOGFILE": str(self.root / "var/log/aetherflow/helper.log"),
        }
        env.pop("AF_TARGET_VERSION", None)
        if extra_env:
            for k, v in extra_env.items():
                if v is None:
                    env.pop(k, None)
                else:
                    env[k] = v
        script = f'source "{self.root}/opt/AetherFlow/packages/common.sh"\n{bash_code}\n'
        return subprocess.run(
            ["/bin/bash", "-euo", "pipefail", "-c", script],
            env=env,
            stdin=subprocess.DEVNULL,
            text=True,
            capture_output=True,
            timeout=30,
        )


class ExactSourceRevisionTests(unittest.TestCase):
    def setUp(self):
        self.fx = ExactSourceRevisionFixture()
        self.addCleanup(self.fx.cleanup)

    def test_package_automation_urls_match_cloudplow_and_overseerr_installers(self):
        automation = json.loads((ROOT / "config/package_automation.json").read_text(encoding="utf-8"))
        for pkg, source in (("cloudplow", "git"), ("overseerr", "git_tags")):
            with self.subTest(package=pkg):
                self.assertEqual(automation[pkg]["update_source"], source)
                repo_url = automation[pkg]["update_repo_url"]
                installer = (ROOT / f"packages/package/install/installpackage-{pkg}").read_text(encoding="utf-8")
                self.assertIn(f'git_stage_exact_revision "{repo_url}"', installer)
                self.assertNotIn("git checkout \"$LATEST_TAG\" || true", installer)

    def test_git_checkout_version_never_certifies_ancestor_tag_and_handles_exact_tags_and_shas(self):
        repo = self.fx.root / "local-checkout"
        repo.mkdir()
        run_git(repo, "init", "-b", "main")
        (repo / "app.py").write_text("v1.0.0\n", encoding="utf-8")
        run_git(repo, "add", "app.py")
        run_git(repo, "commit", "-m", "release 1.0.0")
        c1 = run_git(repo, "rev-parse", "HEAD")
        run_git(repo, "tag", "-a", "v1.0.0", "-m", "v1.0.0")
        run_git(repo, "tag", "-a", "latest", "-m", "latest alias")

        # 1. Exact commit with both 'latest' and 'v1.0.0': explicit target selects v1.0.0
        res_exact = self.fx.run_helper(
            f'git_checkout_version "{repo}"',
            extra_env={"AF_TARGET_VERSION": "1.0.0"},
        )
        self.assertEqual(res_exact.returncode, 0, res_exact.stderr)
        self.assertEqual(res_exact.stdout.strip(), "v1.0.0")

        # 2. Explicit commit SHA target on a tagged commit returns full SHA (matching commit_app_versions)
        res_sha = self.fx.run_helper(
            f'ver="$(git_checkout_version "{repo}")"\n'
            f'queue_app_version "{self.fx.root}/opt/.af-version" "$ver"\n'
            f'commit_app_versions\n'
            f'printf "%s\\n" "$ver"',
            extra_env={"AF_TARGET_VERSION": c1[:12]},
        )
        self.assertEqual(res_sha.returncode, 0, res_sha.stderr)
        self.assertEqual(res_sha.stdout.strip(), c1)
        self.assertEqual((self.fx.root / "opt/.af-version").read_text(encoding="utf-8").strip(), c1)

        # 3. Untagged commit ahead of v1.0.0: must return c2 SHA, NEVER ancestor tag v1.0.0
        (repo / "app.py").write_text("untagged-main\n", encoding="utf-8")
        run_git(repo, "commit", "-am", "untagged ahead")
        c2 = run_git(repo, "rev-parse", "HEAD")

        res_untagged = self.fx.run_helper(f'git_checkout_version "{repo}"')
        self.assertEqual(res_untagged.returncode, 0, res_untagged.stderr)
        self.assertEqual(res_untagged.stdout.strip(), c2)
        self.assertNotEqual(res_untagged.stdout.strip(), "v1.0.0")

        # 4. Ancestor tag cannot satisfy AF_TARGET_VERSION=1.0.0 in commit_app_versions
        res_ancestor_fail = self.fx.run_helper(
            f'ver="$(git_checkout_version "{repo}")"\n'
            f'queue_app_version "{self.fx.root}/opt/ancestor/.af-version" "$ver"\n'
            f'commit_app_versions',
            extra_env={"AF_TARGET_VERSION": "1.0.0"},
        )
        self.assertNotEqual(res_ancestor_fail.returncode, 0)
        self.assertFalse((self.fx.root / "opt/ancestor/.af-version").exists())

    def test_git_stage_exact_revision_resolves_annotated_lightweight_collision_and_rejects_bad_targets(self):
        bare, shas = self.fx.make_bare_repo(
            "helper-fixture",
            [
                {"id": "c1", "message": "v1.0.0", "files": {"app.txt": "1.0.0\n"}, "annotated_tags": ["v1.0.0"]},
                {"id": "c2", "message": "v1.1.0", "files": {"app.txt": "1.1.0\n"}, "tags": ["v1.1.0"]},
                {"id": "c3", "message": "rc", "files": {"app.txt": "2.0.0-rc1\n"}, "annotated_tags": ["v2.0.0-rc1"]},
                {
                    "id": "c4",
                    "message": "untagged main + branch colliding with v1.1.0",
                    "files": {"app.txt": "untagged-main\n"},
                    "branches": ["v1.1.0"],
                },
            ],
        )
        url = f"file://{bare}"

        # Unpinned: selects highest stable tag v1.1.0 -> c2 (ignores prerelease c3, branch collision c4, untagged main c4)
        b_latest = self.fx.root / "stage-latest"
        b_latest.mkdir()
        res = self.fx.run_helper(
            f'git_stage_exact_revision "{url}" "{b_latest}" ""\n'
            'printf "%s|%s|%s\\n" "$AF_STAGED_GIT_VERSION" "$AF_STAGED_GIT_REF" "$AF_STAGED_GIT_COMMIT"'
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertEqual(res.stdout.strip(), f"v1.1.0|refs/tags/v1.1.0|{shas['c2']}")
        self.assertEqual(run_git(b_latest, "rev-parse", "HEAD"), shas["c2"])
        self.assertEqual((b_latest / "app.txt").read_text(encoding="utf-8").strip(), "1.1.0")

        # Explicit unprefixed target 1.0.0 resolves annotated tag v1.0.0^{} -> c1
        b_ann = self.fx.root / "stage-ann"
        b_ann.mkdir()
        res_ann = self.fx.run_helper(
            f'git_stage_exact_revision "{url}" "{b_ann}" "1.0.0"\n'
            'printf "%s|%s\\n" "$AF_STAGED_GIT_VERSION" "$AF_STAGED_GIT_COMMIT"'
        )
        self.assertEqual(res_ann.returncode, 0, res_ann.stderr)
        self.assertEqual(res_ann.stdout.strip(), f"v1.0.0|{shas['c1']}")
        self.assertEqual(run_git(b_ann, "rev-parse", "HEAD"), shas["c1"])

        # Explicit prerelease target 2.0.0-rc1 resolves annotated tag -> c3
        b_rc = self.fx.root / "stage-rc"
        b_rc.mkdir()
        res_rc = self.fx.run_helper(
            f'git_stage_exact_revision "{url}" "{b_rc}" "2.0.0-rc1"\n'
            'printf "%s|%s\\n" "$AF_STAGED_GIT_VERSION" "$AF_STAGED_GIT_COMMIT"'
        )
        self.assertEqual(res_rc.returncode, 0, res_rc.stderr)
        self.assertEqual(res_rc.stdout.strip(), f"v2.0.0-rc1|{shas['c3']}")

        # Explicit commit SHA target resolves exact commit -> c4
        b_sha = self.fx.root / "stage-sha"
        b_sha.mkdir()
        res_sha = self.fx.run_helper(
            f'git_stage_exact_revision "{url}" "{b_sha}" "{shas["c4"][:12]}"\n'
            'printf "%s|%s\\n" "$AF_STAGED_GIT_VERSION" "$AF_STAGED_GIT_COMMIT"'
        )
        self.assertEqual(res_sha.returncode, 0, res_sha.stderr)
        self.assertEqual(res_sha.stdout.strip(), f"{shas['c4']}|{shas['c4']}")
        self.assertEqual(run_git(b_sha, "rev-parse", "HEAD"), shas["c4"])

        # Invalid & missing targets all fail closed
        for bad_target in ("latest", "main", "HEAD", "--upload-pack=evil", "../escape", "v1.0.0;id", "   ", "9.9.9", "deadbeefdeadbeef"):
            with self.subTest(bad_target=bad_target):
                b_bad = self.fx.root / f"stage-bad-{abs(hash(bad_target))}"
                b_bad.mkdir()
                res_bad = self.fx.run_helper(
                    f'git_stage_exact_revision "{url}" "{b_bad}" "$BAD_TARGET"',
                    extra_env={"BAD_TARGET": bad_target},
                )
                self.assertNotEqual(res_bad.returncode, 0, f"Expected failure for {bad_target!r}")

        # Ambiguous alias tags pointing to different commits fail closed
        amb_bare, _ = self.fx.make_bare_repo(
            "ambiguous-tags",
            [
                {"id": "a1", "message": "v1.5.0", "files": {"app.txt": "a1\n"}, "tags": ["v1.5.0"]},
                {"id": "a2", "message": "V1.5.0", "files": {"app.txt": "a2\n"}, "tags": ["V1.5.0"]},
            ],
        )
        b_amb = self.fx.root / "stage-amb"
        b_amb.mkdir()
        res_amb = self.fx.run_helper(f'git_stage_exact_revision "file://{amb_bare}" "{b_amb}" "1.5.0"')
        self.assertNotEqual(res_amb.returncode, 0)

        # Repository with zero stable tags fails closed on unpinned install
        notag_bare, _ = self.fx.make_bare_repo(
            "no-stable-tags",
            [
                {"id": "n1", "message": "rc only", "files": {"app.txt": "rc\n"}, "tags": ["v1.0.0-rc1"]},
            ],
        )
        b_notag = self.fx.root / "stage-notag"
        b_notag.mkdir()
        res_notag = self.fx.run_helper(f'git_stage_exact_revision "file://{notag_bare}" "{b_notag}" ""')
        self.assertNotEqual(res_notag.returncode, 0)

    def test_cloudplow_fresh_install_update_rollback_and_retained_reinstall_with_local_git(self):
        bare, shas = self.fx.make_bare_repo(
            "cloudplow",
            [
                {
                    "id": "v1_2_0",
                    "message": "cloudplow 1.2.0",
                    "files": {
                        "cloudplow.py": "VERSION = '1.2.0'\n",
                        "requirements.txt": "requests\n",
                    },
                    "annotated_tags": ["v1.2.0"],
                },
                {
                    "id": "v1_3_2",
                    "message": "cloudplow 1.3.2",
                    "files": {
                        "cloudplow.py": "VERSION = '1.3.2'\n",
                        "requirements.txt": "requests\n",
                    },
                    "tags": ["v1.3.2"],
                },
                {
                    "id": "v2_0_0_rc1",
                    "message": "cloudplow 2.0.0-rc1",
                    "files": {
                        "cloudplow.py": "VERSION = '2.0.0-rc1'\n",
                        "requirements.txt": "requests\n",
                    },
                    "tags": ["v2.0.0-rc1"],
                },
                {
                    "id": "main_untagged",
                    "message": "untagged default branch commit ahead of v1.3.2",
                    "files": {
                        "cloudplow.py": "VERSION = 'untagged-main'\n",
                        "requirements.txt": "requests\n",
                    },
                },
            ],
        )
        repo_map = {"https://github.com/l3uddz/cloudplow.git": bare}

        # 1. Fresh install with explicit older target 1.2.0
        res_install = self.fx.run_package(
            "cloudplow", "install", repo_map=repo_map, extra_env={"AF_TARGET_VERSION": "1.2.0"}
        )
        self.assertEqual(res_install.returncode, 0, res_install.stdout + res_install.stderr)
        app_dir = self.fx.root / "opt/cloudplow"
        self.assertEqual(run_git(app_dir, "rev-parse", "HEAD"), shas["v1_2_0"])
        self.assertIn("1.2.0", (app_dir / "cloudplow.py").read_text(encoding="utf-8"))
        self.assertEqual((app_dir / ".af-version").read_text(encoding="utf-8").strip(), "v1.2.0")

        # Write operator config and retained state
        custom_cfg = json.dumps({"remotes": {"media": {"sync_remote": "gd:media"}}}) + "\n"
        (app_dir / "config.json").write_text(custom_cfg, encoding="utf-8")
        retained_state = self.fx.root / "var/lib/cloudplow/retained.sentinel"
        retained_state.parent.mkdir(parents=True, exist_ok=True)
        retained_state.write_text("operator-cloudplow-state\n", encoding="utf-8")

        # 2. Update with AF_TARGET_VERSION=1.3.2 (unprefixed, as emitted by af-services/af-runner)
        res_update = self.fx.run_package(
            "cloudplow", "update", repo_map=repo_map, extra_env={"AF_TARGET_VERSION": "1.3.2"}
        )
        self.assertEqual(res_update.returncode, 0, res_update.stdout + res_update.stderr)
        self.assertEqual(run_git(app_dir, "rev-parse", "HEAD"), shas["v1_3_2"])
        self.assertIn("1.3.2", (app_dir / "cloudplow.py").read_text(encoding="utf-8"))
        self.assertEqual((app_dir / ".af-version").read_text(encoding="utf-8").strip(), "v1.3.2")
        self.assertEqual((app_dir / "config.json").read_text(encoding="utf-8"), custom_cfg)
        self.assertEqual(retained_state.read_text(encoding="utf-8"), "operator-cloudplow-state\n")

        # 3. Disallowed downgrade without AF_ALLOW_DOWNGRADE fails before stopping service or building venv
        self.fx.reset_command_log()
        res_down_blocked = self.fx.run_package(
            "cloudplow",
            "update",
            repo_map=repo_map,
            extra_env={"AF_TARGET_VERSION": "1.2.0", "AF_ALLOW_DOWNGRADE": "0"},
        )
        self.assertNotEqual(res_down_blocked.returncode, 0)
        cmds = self.fx.commands()
        self.assertFalse(any(c[0] == "systemctl" and len(c) > 1 and c[1] == "stop" for c in cmds))
        self.assertFalse(any(c[0] == "pip" for c in cmds))
        self.assertEqual((app_dir / ".af-version").read_text(encoding="utf-8").strip(), "v1.3.2")

        # 4. Explicit rollback with AF_ALLOW_DOWNGRADE=1 succeeds to exact v1.2.0
        res_rollback = self.fx.run_package(
            "cloudplow",
            "reinstall",
            repo_map=repo_map,
            extra_env={"AF_TARGET_VERSION": "1.2.0", "AF_ALLOW_DOWNGRADE": "1"},
        )
        self.assertEqual(res_rollback.returncode, 0, res_rollback.stdout + res_rollback.stderr)
        self.assertEqual(run_git(app_dir, "rev-parse", "HEAD"), shas["v1_2_0"])
        self.assertEqual((app_dir / ".af-version").read_text(encoding="utf-8").strip(), "v1.2.0")
        self.assertEqual((app_dir / "config.json").read_text(encoding="utf-8"), custom_cfg)

        # 5. Failed pip build during update rolls back cleanly to v1.2.0 and restarts service
        res_pip_fail = self.fx.run_package(
            "cloudplow",
            "update",
            repo_map=repo_map,
            extra_env={"AF_TARGET_VERSION": "1.3.2", "AF_FAIL_STAGE": "pip"},
        )
        self.assertNotEqual(res_pip_fail.returncode, 0)
        self.assertEqual(run_git(app_dir, "rev-parse", "HEAD"), shas["v1_2_0"])
        self.assertEqual((app_dir / ".af-version").read_text(encoding="utf-8").strip(), "v1.2.0")
        self.assertEqual((app_dir / "config.json").read_text(encoding="utf-8"), custom_cfg)
        self.assertTrue((self.fx.root / "service_active_cloudplow").exists())

        # 6. Retained uninstall and unpinned reinstall select the advertised default-branch commit.
        res_remove = self.fx.run_package("cloudplow", "remove", extra_env={"DELETE_DATA": "false"})
        self.assertEqual(res_remove.returncode, 0, res_remove.stdout + res_remove.stderr)
        self.assertEqual(retained_state.read_text(encoding="utf-8"), "operator-cloudplow-state\n")

        res_reinstall = self.fx.run_package("cloudplow", "install", repo_map=repo_map)
        self.assertEqual(res_reinstall.returncode, 0, res_reinstall.stdout + res_reinstall.stderr)
        self.assertEqual(run_git(app_dir, "rev-parse", "HEAD"), shas["main_untagged"])
        self.assertIn("untagged-main", (app_dir / "cloudplow.py").read_text(encoding="utf-8"))
        self.assertEqual((app_dir / ".af-version").read_text(encoding="utf-8").strip(), shas["main_untagged"])
        self.assertEqual(retained_state.read_text(encoding="utf-8"), "operator-cloudplow-state\n")

    def test_cloudplow_installs_and_updates_an_untagged_remote_by_commit(self):
        bare, shas = self.fx.make_bare_repo(
            "cloudplow-untagged",
            [
                {
                    "id": revision,
                    "message": f"Cloudplow {revision}",
                    "files": {"cloudplow.py": f"# Cloudplow {revision}\n", "requirements.txt": "requests\n"},
                }
                for revision in ("approved", "current")
            ],
        )
        repo_map = {"https://github.com/l3uddz/cloudplow.git": bare}
        app_dir = self.fx.root / "opt/cloudplow"

        installed = self.fx.run_package("cloudplow", "install", repo_map=repo_map)
        self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
        self.assertEqual(run_git(app_dir, "rev-parse", "HEAD"), shas["current"])
        self.assertEqual((app_dir / ".af-version").read_text().strip(), shas["current"])

        updated = self.fx.run_package(
            "cloudplow", "update", repo_map=repo_map, extra_env={"AF_TARGET_VERSION": shas["approved"]},
        )
        self.assertEqual(updated.returncode, 0, updated.stdout + updated.stderr)
        self.assertEqual(run_git(app_dir, "rev-parse", "HEAD"), shas["approved"])
        self.assertEqual((app_dir / ".af-version").read_text().strip(), shas["approved"])

    def test_cloudplow_missing_and_mismatched_target_fail_closed_before_build_or_mutation(self):
        bare, shas = self.fx.make_bare_repo(
            "cloudplow-fail",
            [
                {
                    "id": "v1_2_0",
                    "message": "cloudplow 1.2.0",
                    "files": {"cloudplow.py": "VERSION = '1.2.0'\n", "requirements.txt": "requests\n"},
                    "tags": ["v1.2.0"],
                },
                {
                    "id": "v1_3_2",
                    "message": "cloudplow 1.3.2",
                    "files": {"cloudplow.py": "VERSION = '1.3.2'\n", "requirements.txt": "requests\n"},
                    "tags": ["v1.3.2"],
                },
                {
                    "id": "main_untagged",
                    "message": "untagged main",
                    "files": {"cloudplow.py": "VERSION = 'untagged-main'\n", "requirements.txt": "requests\n"},
                },
            ],
        )
        repo_map = {"https://github.com/l3uddz/cloudplow.git": bare}

        res_init = self.fx.run_package(
            "cloudplow", "install", repo_map=repo_map, extra_env={"AF_TARGET_VERSION": "1.2.0"}
        )
        self.assertEqual(res_init.returncode, 0, res_init.stdout + res_init.stderr)
        app_dir = self.fx.root / "opt/cloudplow"
        (app_dir / "config.json").write_text('{"keep":true}\n', encoding="utf-8")

        # Case A: Missing explicit target fails closed before stop/venv/pip
        self.fx.reset_command_log()
        res_missing = self.fx.run_package(
            "cloudplow", "update", repo_map=repo_map, extra_env={"AF_TARGET_VERSION": "9.9.9"}
        )
        self.assertNotEqual(res_missing.returncode, 0)
        cmds = self.fx.commands()
        self.assertFalse(any(c[0] == "systemctl" and len(c) > 1 and c[1] == "stop" for c in cmds))
        self.assertFalse(any(c[0] == "pip" for c in cmds))
        self.assertFalse(any(c[0] == "python3" and len(c) >= 3 and c[1:3] == ["-m", "venv"] for c in cmds))
        self.assertEqual(run_git(app_dir, "rev-parse", "HEAD"), shas["v1_2_0"])
        self.assertEqual((app_dir / ".af-version").read_text(encoding="utf-8").strip(), "v1.2.0")
        self.assertEqual((app_dir / "config.json").read_text(encoding="utf-8"), '{"keep":true}\n')
        self.assertTrue((self.fx.root / "service_active_cloudplow").exists())

        # Case B: Mismatched staged HEAD fails closed before stop/venv/pip
        self.fx.reset_command_log()
        res_mismatch = self.fx.run_package(
            "cloudplow",
            "update",
            repo_map=repo_map,
            extra_env={
                "AF_TARGET_VERSION": "1.3.2",
                "AF_GIT_FAULT": "head_mismatch_after_checkout",
            },
        )
        self.assertNotEqual(res_mismatch.returncode, 0)
        cmds = self.fx.commands()
        self.assertFalse(any(c[0] == "systemctl" and len(c) > 1 and c[1] == "stop" for c in cmds))
        self.assertFalse(any(c[0] == "pip" for c in cmds))
        self.assertEqual(run_git(app_dir, "rev-parse", "HEAD"), shas["v1_2_0"])
        self.assertEqual((app_dir / ".af-version").read_text(encoding="utf-8").strip(), "v1.2.0")
        self.assertTrue((self.fx.root / "service_active_cloudplow").exists())

    def test_overseerr_fresh_update_checkout_failure_mismatch_and_rollback_with_local_git(self):
        bare, shas = self.fx.make_bare_repo(
            "overseerr",
            [
                {
                    "id": "v1_33_1",
                    "message": "overseerr 1.33.1",
                    "files": {"package.json": json.dumps({"name": "overseerr", "version": "1.33.1"}) + "\n"},
                    "annotated_tags": ["v1.33.1"],
                },
                {
                    "id": "v1_33_2",
                    "message": "overseerr 1.33.2",
                    "files": {"package.json": json.dumps({"name": "overseerr", "version": "1.33.2"}) + "\n"},
                    "annotated_tags": ["v1.33.2"],
                },
                {
                    "id": "v1_34_0_dev",
                    "message": "overseerr prerelease",
                    "files": {"package.json": json.dumps({"name": "overseerr", "version": "1.34.0-develop.1"}) + "\n"},
                    "tags": ["v1.34.0-develop.1"],
                },
                {
                    "id": "develop_untagged",
                    "message": "untagged default branch commit ahead of v1.33.2",
                    "files": {"package.json": json.dumps({"name": "overseerr", "version": "0.0.0-develop"}) + "\n"},
                },
            ],
            default_branch="develop",
        )
        repo_map = {"https://github.com/sct/overseerr.git": bare}

        # 1. Explicit target install v1.33.1 (via unprefixed 1.33.1)
        res_install = self.fx.run_package(
            "overseerr", "install", repo_map=repo_map, extra_env={"AF_TARGET_VERSION": "1.33.1"}
        )
        self.assertEqual(res_install.returncode, 0, res_install.stdout + res_install.stderr)
        app_dir = self.fx.root / "opt/overseerr"
        self.assertEqual(run_git(app_dir, "rev-parse", "HEAD"), shas["v1_33_1"])
        self.assertEqual((app_dir / ".af-version").read_text(encoding="utf-8").strip(), "1.33.1")
        self.assertIn("1.33.1", (app_dir / "dist/index.js").read_text(encoding="utf-8"))

        # Plant retained Overseerr data
        retained_settings = self.fx.root / "var/lib/overseerr/settings.json"
        retained_settings.write_text('{"main":{"appTitle":"Operator"}}\n', encoding="utf-8")

        # 2. Checkout failure MUST fail closed BEFORE yarn/npm build or service stop (no `|| true`)
        self.fx.reset_command_log()
        res_co_fail = self.fx.run_package(
            "overseerr",
            "update",
            repo_map=repo_map,
            extra_env={"AF_TARGET_VERSION": "1.33.2", "AF_GIT_FAULT": "checkout_fail"},
        )
        self.assertNotEqual(res_co_fail.returncode, 0)
        cmds = self.fx.commands()
        self.assertFalse(any(c[0] in ("yarn", "npm") for c in cmds), f"Build ran despite checkout failure: {cmds}")
        self.assertFalse(any(c[0] == "systemctl" and len(c) > 1 and c[1] == "stop" for c in cmds))
        self.assertEqual(run_git(app_dir, "rev-parse", "HEAD"), shas["v1_33_1"])
        self.assertEqual((app_dir / ".af-version").read_text(encoding="utf-8").strip(), "1.33.1")
        self.assertEqual(retained_settings.read_text(encoding="utf-8"), '{"main":{"appTitle":"Operator"}}\n')
        self.assertTrue((self.fx.root / "service_active_overseerr").exists())

        # 3. Missing explicit target 9.9.9 fails closed before yarn/npm/stop
        self.fx.reset_command_log()
        res_missing = self.fx.run_package(
            "overseerr", "update", repo_map=repo_map, extra_env={"AF_TARGET_VERSION": "9.9.9"}
        )
        self.assertNotEqual(res_missing.returncode, 0)
        cmds = self.fx.commands()
        self.assertFalse(any(c[0] in ("yarn", "npm") for c in cmds))
        self.assertFalse(any(c[0] == "systemctl" and len(c) > 1 and c[1] == "stop" for c in cmds))
        self.assertEqual((app_dir / ".af-version").read_text(encoding="utf-8").strip(), "1.33.1")

        # 4. Mismatched staged HEAD fails closed before yarn/npm/stop
        self.fx.reset_command_log()
        res_mismatch = self.fx.run_package(
            "overseerr",
            "update",
            repo_map=repo_map,
            extra_env={
                "AF_TARGET_VERSION": "1.33.2",
                "AF_GIT_FAULT": "head_mismatch_after_checkout",
            },
        )
        self.assertNotEqual(res_mismatch.returncode, 0)
        cmds = self.fx.commands()
        self.assertFalse(any(c[0] in ("yarn", "npm") for c in cmds))
        self.assertFalse(any(c[0] == "systemctl" and len(c) > 1 and c[1] == "stop" for c in cmds))
        self.assertEqual((app_dir / ".af-version").read_text(encoding="utf-8").strip(), "1.33.1")

        # 5. Failed yarn build preserves live 1.33.1 and active service
        res_build_fail = self.fx.run_package(
            "overseerr",
            "update",
            repo_map=repo_map,
            extra_env={"AF_TARGET_VERSION": "1.33.2", "AF_FAIL_STAGE": "build"},
        )
        self.assertNotEqual(res_build_fail.returncode, 0)
        self.assertEqual(run_git(app_dir, "rev-parse", "HEAD"), shas["v1_33_1"])
        self.assertEqual((app_dir / ".af-version").read_text(encoding="utf-8").strip(), "1.33.1")
        self.assertTrue((self.fx.root / "service_active_overseerr").exists())

        # 6. Approved update to 1.33.2 succeeds, records 1.33.2, and retains data
        res_update = self.fx.run_package(
            "overseerr", "update", repo_map=repo_map, extra_env={"AF_TARGET_VERSION": "1.33.2"}
        )
        self.assertEqual(res_update.returncode, 0, res_update.stdout + res_update.stderr)
        self.assertEqual(run_git(app_dir, "rev-parse", "HEAD"), shas["v1_33_2"])
        self.assertEqual((app_dir / ".af-version").read_text(encoding="utf-8").strip(), "1.33.2")
        self.assertIn("1.33.2", (app_dir / "dist/index.js").read_text(encoding="utf-8"))
        self.assertEqual(retained_settings.read_text(encoding="utf-8"), '{"main":{"appTitle":"Operator"}}\n')

        # 7. Retained uninstall + unpinned fresh reinstall selects highest stable v1.33.2 (NOT develop/prerelease)
        res_remove = self.fx.run_package("overseerr", "remove", extra_env={"DELETE_DATA": "false"})
        self.assertEqual(res_remove.returncode, 0, res_remove.stdout + res_remove.stderr)
        self.assertEqual(retained_settings.read_text(encoding="utf-8"), '{"main":{"appTitle":"Operator"}}\n')

        res_reinstall = self.fx.run_package("overseerr", "install", repo_map=repo_map)
        self.assertEqual(res_reinstall.returncode, 0, res_reinstall.stdout + res_reinstall.stderr)
        self.assertEqual(run_git(app_dir, "rev-parse", "HEAD"), shas["v1_33_2"])
        self.assertEqual((app_dir / ".af-version").read_text(encoding="utf-8").strip(), "1.33.2")
        self.assertEqual(retained_settings.read_text(encoding="utf-8"), '{"main":{"appTitle":"Operator"}}\n')

    def test_rutorrent_preserves_git_checkout_version_exact_tag_and_avoids_ancestor_certification(self):
        bare, shas = self.fx.make_bare_repo(
            "rutorrent",
            [
                {
                    "id": "v5_1_0",
                    "message": "rutorrent 5.1.0",
                    "files": {
                        "conf/config.php": '<?php $scgi_port = 15000; $scgi_host = "127.0.0.1";\n',
                        "js/webui.js": "version: '5.1'\n",
                        "index.html": "rutorrent 5.1.0\n",
                    },
                    "annotated_tags": ["v5.1.0"],
                },
                {
                    "id": "master_untagged",
                    "message": "untagged master ahead of v5.1.0",
                    "files": {
                        "conf/config.php": '<?php $scgi_port = 15000; $scgi_host = "127.0.0.1";\n',
                        "js/webui.js": "version: '5.1'\n",
                        "index.html": "rutorrent untagged\n",
                    },
                },
            ],
            default_branch="master",
        )
        repo_map = {"https://github.com/Novik/ruTorrent.git": bare}

        # 1. Explicit target 5.1.0 records exact tag version 5.1.0 and preserves share/conf
        res_tagged = self.fx.run_package(
            "rutorrent", "install", repo_map=repo_map, extra_env={"AF_TARGET_VERSION": "5.1.0"}
        )
        self.assertEqual(res_tagged.returncode, 0, res_tagged.stdout + res_tagged.stderr)
        rut_dir = self.fx.root / "var/www/rutorrent"
        self.assertEqual(run_git(rut_dir, "rev-parse", "HEAD"), shas["v5_1_0"])
        self.assertEqual((rut_dir / ".af-version").read_text(encoding="utf-8").strip(), "5.1.0")

        # 2. Fresh unpinned install on untagged default branch records commit SHA, NEVER ancestor tag 5.1.0
        fx_fresh = ExactSourceRevisionFixture()
        self.addCleanup(fx_fresh.cleanup)
        res_untagged = fx_fresh.run_package("rutorrent", "install", repo_map=repo_map)
        self.assertEqual(res_untagged.returncode, 0, res_untagged.stdout + res_untagged.stderr)
        fresh_rut = fx_fresh.root / "var/www/rutorrent"
        self.assertEqual(run_git(fresh_rut, "rev-parse", "HEAD"), shas["master_untagged"])
        self.assertEqual((fresh_rut / ".af-version").read_text(encoding="utf-8").strip(), shas["master_untagged"])


if __name__ == "__main__":
    unittest.main()
