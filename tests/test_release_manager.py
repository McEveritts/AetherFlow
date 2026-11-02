#!/usr/bin/env python3
import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy" / "release-manager.sh"
REAL_TOOLS = (
    "sqlite3", "flock", "mkdir", "date", "cp", "mv", "ln", "rm", "cat", "tee",
    "find", "awk", "grep", "sed", "mktemp", "readlink", "chmod", "chown", "id",
    "head", "cut", "tr", "sha256sum", "tar", "gzip", "python3", "touch", "sleep",
    "basename", "dirname", "sort", "tail", "runuser", "sh",
)

CURL_MOCK = r'''#!/usr/bin/python3
import hashlib
import os
from pathlib import Path
import shutil
import sys

root = Path(os.environ["TEST_ROOT"])
arguments = sys.argv[1:]
with (root / "commands").open("a") as output:
    output.write("curl " + " ".join(arguments) + "\n")
if os.environ.get("TEST_FORBID_CURL") == "1":
    sys.stderr.write("curl forbidden\n")
    sys.exit(1)

def url_of(args):
    for arg in reversed(args):
        if arg.startswith("http://") or arg.startswith("https://"):
            return arg
    return ""

url = url_of(arguments)
if "api.github.com" in url:
    if os.environ.get("TEST_API_RATE_LIMITED") == "1":
        sys.exit(22)
    print(os.environ.get("TEST_RELEASES_JSON", '[{"tag_name":"v4.0.0","draft":false,"prerelease":false,"target_commitish":"master"}]'))
    sys.exit(0)
if url.endswith("/releases/latest"):
    print(os.environ.get("TEST_LATEST_URL", "https://github.com/McEveritts/AetherFlow/releases/tag/v4.0.0"), end="")
    sys.exit(0)
if url.endswith("/aetherflow-linux-amd64.tar.gz"):
    target = Path(arguments[arguments.index("-o") + 1])
    shutil.copyfile(root / "artifact.tar.gz", target)
    sys.exit(0)
if url.endswith("/SHA256SUMS"):
    target = Path(arguments[arguments.index("-o") + 1])
    shutil.copyfile(root / "SHA256SUMS", target)
    sys.exit(0)
if url.endswith("/health/ready"):
    corrupt = os.environ.get("TEST_CORRUPT_DB", "")
    if corrupt:
        target = Path(corrupt)
        target.write_bytes(b"not a database")
        Path(corrupt + "-wal").write_text("wal")
        Path(corrupt + "-shm").write_text("shm")
    body = os.environ.get("TEST_HEALTH_BODY", '{"database":"ok","redis":"disabled","status":"ready","uptime":"0.0s"}')
    code = os.environ.get("TEST_HEALTH_CODE", "200")
    sys.stdout.write(body)
    if not body.endswith("\n"):
        sys.stdout.write("\n")
    sys.stdout.write(code)
    sys.exit(0)
sys.stderr.write("unexpected curl " + url + "\n")
sys.exit(1)
'''

SYSTEMCTL_MOCK = r'''#!/usr/bin/python3
import os
import sys

root_commands = os.environ["TEST_ROOT"] + "/commands"
arguments = sys.argv[1:]
with open(root_commands, "a") as output:
    output.write("systemctl " + " ".join(arguments) + "\n")
if arguments and arguments[0] == "show":
    if "User" in arguments:
        import pwd
        print(os.environ.get("TEST_SERVICE_USER", pwd.getpwuid(os.getuid()).pw_name))
    else:
        print(os.environ.get("TEST_UNIT_ENV", "Environment="))
sys.exit(0)
'''

SQLITE_WRAPPER = r'''#!/usr/bin/python3
import os
from pathlib import Path
import re
import sys

arguments = sys.argv[1:]
backup_arg = next((arg for arg in arguments if arg.startswith(".backup")), "")
if backup_arg and ".bak" in backup_arg:
    match = re.search(r"'([^']+)'", backup_arg)
    if not match:
        sys.exit(1)
    dest = Path(match.group(1))
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(b"this is not a sqlite database")
    sys.exit(0)
real = os.environ["TEST_REAL_SQLITE"]
os.execv(real, [real, *arguments])
'''


class ReleaseManagerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data = self.root / "var" / "lib" / "aetherflow"
        self.env_dir = self.root / "etc" / "aetherflow"
        self.legacy_root = self.root / "opt" / "AetherFlow"
        self.dry = self.root / "dryrun"
        self.releases = self.root / "releases"
        self.current = self.root / "current"
        self.units = self.root / "etc" / "systemd" / "system"
        self.mock = self.root / "mock-bin"
        self.tools = self.root / "tool-bin"
        for directory in (self.data, self.env_dir, self.legacy_root, self.dry, self.releases, self.units, self.mock, self.tools):
            directory.mkdir(parents=True)
        self.env_file = self.env_dir / "aetherflow.env"
        self.commands = self.root / "commands"
        self.commands.write_text("")
        self.real_sqlite = shutil.which("sqlite3")
        self.bash = shutil.which("bash")
        if not self.real_sqlite or not self.bash:
            self.skipTest("sqlite3 and bash are required")
        search_path = os.environ.get("PATH", "") + ":/usr/sbin:/sbin"
        for name in REAL_TOOLS:
            source = shutil.which(name, path=search_path)
            if source:
                os.symlink(source, self.tools / name)
        self.write_executable(self.mock / "curl", CURL_MOCK)
        self.write_executable(self.mock / "systemctl", SYSTEMCTL_MOCK)
        self.write_executable(self.mock / "chown", "#!/bin/sh\nexit 0\n")
        self.write_artifact()

    def write_executable(self, path, source):
        path.write_text(textwrap.dedent(source).lstrip("\n") if source.startswith("\n") else source)
        path.chmod(0o755)

    def write_db(self, path, marker):
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            path.unlink()
        subprocess.run(
            [self.real_sqlite, str(path),
             "CREATE TABLE marker(kind TEXT); INSERT INTO marker VALUES ('" + marker + "');"],
            check=True, capture_output=True, text=True,
        )

    def marker(self, path):
        result = subprocess.run(
            [self.real_sqlite, str(path), "SELECT kind FROM marker;"],
            check=True, capture_output=True, text=True,
        )
        return result.stdout.strip()

    def write_artifact(self):
        binary = b"#!/bin/bash\necho aetherflow-api\n"
        version = b"v4.0.0\n"
        unit = b"[Service]\nExecStart=/opt/AetherFlow/current/aetherflow-api\nFrom=artifact\n"
        runner = b"[Service]\nExecStart=/opt/AetherFlow/current/aetherflow-api runner\nFrom=artifact\n"
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            directory = tarfile.TarInfo(".")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o700
            directory.uid = directory.gid = 1001
            archive.addfile(directory)
            for name, payload, mode in (
                ("aetherflow-api", binary, 0o755),
                (".version", version, 0o644),
                ("deploy/systemd/aetherflow-api.service", unit, 0o644),
                ("deploy/systemd/aetherflow-runner.service", runner, 0o644),
            ):
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                info.mode = mode
                info.uid = info.gid = 1001
                archive.addfile(info, io.BytesIO(payload))
        data = buffer.getvalue()
        (self.root / "artifact.tar.gz").write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        (self.root / "SHA256SUMS").write_text(digest + "  aetherflow-linux-amd64.tar.gz\n")

    def base_env(self, **extra):
        env = os.environ.copy()
        for key in ("AF_DB_PATH", "AF_OFFLINE", "DB_PATH", "AETHERFLOW_DB_PATH"):
            env.pop(key, None)
        env.update({
            "PATH": f"{self.mock}:{self.tools}",
            "TEST_ROOT": str(self.root),
            "TEST_REAL_SQLITE": self.real_sqlite,
            "DATA_DIR": str(self.data),
            "ENV_DIR": str(self.env_dir),
            "ENV_FILE": str(self.env_file),
            "LOG_FILE": str(self.root / "deploy.log"),
            "RELEASES_DIR": str(self.releases),
            "CURRENT_LINK": str(self.current),
            "REPO_DIR": str(self.root / "repo"),
            "SYSTEMD_UNITS_DST": str(self.units),
            "DRY_RUN_ROOT": str(self.dry),
            "LEGACY_OPT_ROOT": str(self.legacy_root),
            "HEALTH_ENDPOINT": "http://127.0.0.1:9/health/ready",
            "HEALTH_RETRIES": "2",
            "HEALTH_INTERVAL": "0",
            "SNAPSHOT_TIMEOUT": "5",
            "MAX_RELEASES": "3",
        })
        env.update(extra)
        return env

    def run_manager(self, *args, **extra):
        return subprocess.run(
            [self.bash, str(SCRIPT), *args],
            env=self.base_env(**extra),
            text=True, capture_output=True, timeout=30,
        )

    def snapshot(self):
        found = list((self.dry / "releases").glob("*/data-snapshot/aetherflow.sqlite.bak"))
        if not found:
            found = list(self.releases.glob("*/data-snapshot/aetherflow.sqlite.bak"))
        self.assertEqual(len(found), 1, f"expected one snapshot, found {found}")
        return found[0]

    def test_env_file_db_path_wins_over_data_dir_and_unit(self):
        env_db = self.root / "live" / "from-env.sqlite"
        other_db = self.root / "live" / "from-aether.sqlite"
        unit_db = self.root / "live" / "from-unit.sqlite"
        fhs_db = self.data / "aetherflow.sqlite"
        legacy_db = self.legacy_root / "backend" / "data" / "aetherflow.sqlite"
        for path, marker in (
            (env_db, "env"), (other_db, "aether"), (unit_db, "unit"),
            (fhs_db, "fhs"), (legacy_db, "legacy"),
        ):
            self.write_db(path, marker)
        self.env_file.write_text(
            "# comment\nexport UNRELATED=1\n"
            f'DB_PATH="{env_db}"\n'
            f"AETHERFLOW_DB_PATH='{other_db}'\n"
        )
        result = self.run_manager(
            "deploy", "--dry-run", "--offline",
            TEST_UNIT_ENV=f"Environment=DB_PATH={unit_db} AETHERFLOW_DB_PATH={other_db}",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"Resolved database path: {env_db} (source: env-file:{self.env_file}:DB_PATH)", result.stdout)
        self.assertIn("Snapshot integrity check PASSED", result.stdout)
        self.assertEqual(self.marker(self.snapshot()), "env")
        self.assertEqual(self.marker(fhs_db), "fhs")
        self.assertEqual(self.marker(legacy_db), "legacy")
        integrity = subprocess.run(
            [self.real_sqlite, str(self.snapshot()), "PRAGMA integrity_check;"],
            check=True, capture_output=True, text=True,
        )
        self.assertEqual(integrity.stdout.strip(), "ok")

    def test_af_db_path_overrides_env_file(self):
        override = self.root / "live" / "override.sqlite"
        env_db = self.root / "live" / "from-env.sqlite"
        self.write_db(override, "override")
        self.write_db(env_db, "env")
        self.env_file.write_text(f"DB_PATH={env_db}\n")
        result = self.run_manager("deploy", "--dry-run", "--offline", AF_DB_PATH=str(override))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"Resolved database path: {override} (source: AF_DB_PATH)", result.stdout)
        self.assertEqual(self.marker(self.snapshot()), "override")

    def test_unit_environment_fallback(self):
        unit_db = self.root / "live" / "from-unit.sqlite"
        other_db = self.root / "live" / "from-aether.sqlite"
        fhs_db = self.data / "aetherflow.sqlite"
        self.write_db(unit_db, "unit")
        self.write_db(other_db, "aether")
        self.write_db(fhs_db, "fhs")
        self.env_file.write_text("# no database path\nexport OTHER=1\n")
        result = self.run_manager(
            "deploy", "--dry-run", "--offline",
            TEST_UNIT_ENV=f'Environment=GIN_MODE=release DB_PATH="{unit_db}" AETHERFLOW_DB_PATH={other_db}',
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"Resolved database path: {unit_db} (source: systemd:aetherflow-api:DB_PATH)", result.stdout)
        self.assertEqual(self.marker(self.snapshot()), "unit")
        self.assertEqual(self.marker(fhs_db), "fhs")

    def test_unit_aetherflow_db_path_when_db_path_missing(self):
        other_db = self.root / "live" / "from-aether.sqlite"
        self.write_db(other_db, "aether")
        self.env_file.write_text("\n")
        result = self.run_manager(
            "deploy", "--dry-run", "--offline",
            TEST_UNIT_ENV=f"Environment=AETHERFLOW_DB_PATH={other_db}",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("source: systemd:aetherflow-api:AETHERFLOW_DB_PATH", result.stdout)
        self.assertEqual(self.marker(self.snapshot()), "aether")

    def test_data_dir_fallback_when_systemctl_absent(self):
        (self.mock / "systemctl").unlink()
        fhs_db = self.data / "aetherflow.sqlite"
        self.write_db(fhs_db, "fhs")
        self.env_file.write_text("# comment only\n")
        result = self.run_manager("deploy", "--dry-run", "--offline")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"Resolved database path: {fhs_db} (source: DATA_DIR)", result.stdout)
        self.assertEqual(self.marker(self.snapshot()), "fhs")
        self.assertNotIn("systemctl ", self.commands.read_text())

    def test_stage0_does_not_copy_legacy_db_when_live_path_is_elsewhere(self):
        live_db = self.root / "live" / "from-env.sqlite"
        legacy_db = self.legacy_root / "backend" / "data" / "aetherflow.sqlite"
        fhs_db = self.data / "aetherflow.sqlite"
        self.write_db(live_db, "env")
        self.write_db(legacy_db, "legacy")
        self.env_file.write_text(f"DB_PATH={live_db}\n")
        result = self.run_manager("deploy", "--dry-run", "--offline")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"Skipping legacy database copy into {fhs_db}", result.stdout)
        self.assertFalse(fhs_db.exists())
        self.assertEqual(self.marker(legacy_db), "legacy")
        self.assertEqual(self.marker(self.snapshot()), "env")

    def test_bad_snapshot_aborts_before_symlink_swap(self):
        live_db = self.root / "live" / "from-env.sqlite"
        self.write_db(live_db, "env")
        self.env_file.write_text(f"DB_PATH={live_db}\n")
        self.write_executable(self.mock / "sqlite3", SQLITE_WRAPPER)
        result = self.run_manager("deploy", "--dry-run", "--offline")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Snapshot integrity check FAILED", result.stdout)
        self.assertIn("Aborting before symlink swap", result.stdout)
        self.assertFalse(self.current.exists())
        self.assertFalse((self.dry / "current").exists())

    def test_failed_live_copy_does_not_become_a_placeholder(self):
        live_db = self.root / "live" / "from-env.sqlite"
        self.write_db(live_db, "env")
        self.env_file.write_text(f"DB_PATH={live_db}\n")
        self.write_executable(
            self.mock / "sqlite3",
            "#!/usr/bin/python3\nimport sys\nsys.stderr.write('backup refused\\n')\nsys.exit(1)\n",
        )
        result = self.run_manager("deploy", "--dry-run", "--offline")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Failed to copy live database", result.stdout)
        self.assertNotIn("Created placeholder database", result.stdout)
        self.assertNotIn("DRY-RUN SUCCESSFUL", result.stdout)
        self.assertFalse((self.dry / "current").exists())
        self.assertEqual(self.marker(live_db), "env")

    def test_offline_dry_run_simulates_artifact(self):
        missing = self.root / "live" / "missing.sqlite"
        self.env_file.write_text(f"DB_PATH={missing}\n")
        result = self.run_manager("deploy", "--dry-run", "--offline", TEST_FORBID_CURL="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Offline mode", result.stdout)
        self.assertFalse(missing.exists())
        versions = list((self.dry / "releases").glob("*/.version"))
        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0].read_text().strip(), "v3.1.7-dryrun")
        self.assertNotIn("curl ", self.commands.read_text())
        self.assertTrue((self.dry / "current").is_symlink())

    def test_env_file_aetherflow_db_path_when_db_path_missing(self):
        other_db = self.root / "live" / "from-aether.sqlite"
        self.write_db(other_db, "aether")
        self.env_file.write_text(f"export AETHERFLOW_DB_PATH={other_db}\n")
        result = self.run_manager(
            "deploy", "--dry-run", "--offline",
            TEST_UNIT_ENV="Environment=DB_PATH=/should/not/win.sqlite",
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"source: env-file:{self.env_file}:AETHERFLOW_DB_PATH", result.stdout)
        self.assertEqual(self.marker(self.snapshot()), "aether")

    def prepare_live_units(self):
        (self.units / "aetherflow-api.service").write_text("LIVE-UNIT\n")
        (self.units / "aetherflow-runner.service").write_text("LIVE-RUNNER\n")

    def test_health_probe_accepts_rust_ready_body_and_keeps_units(self):
        live_db = self.root / "live" / "from-env.sqlite"
        self.write_db(live_db, "env")
        self.env_file.write_text(f"DB_PATH={live_db}\n")
        self.prepare_live_units()
        previous = self.releases / "100"
        previous.mkdir()
        (previous / "aetherflow-api").write_text("previous")
        self.current.symlink_to(previous)
        body = '{\n  "uptime" : "0.0s" ,\n  "redis" : "disabled" ,\n  "database" : "ok" ,\n  "status" : "ready"\n}\n'
        result = self.run_manager("deploy", "--channel", "stable", TEST_HEALTH_BODY=body)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Health probe PASSED", result.stdout)
        self.assertIn("status=ready", result.stdout)
        self.assertIn("SHA-256 OK", result.stdout)
        self.assertEqual((self.units / "aetherflow-api.service").read_text(), "LIVE-UNIT\n")
        self.assertEqual((self.units / "aetherflow-runner.service").read_text(), "LIVE-RUNNER\n")
        self.assertIn("Keeping installed systemd unit", result.stdout)
        self.assertIn("systemctl restart aetherflow-api.service", self.commands.read_text())
        self.assertTrue(self.current.is_symlink())
        self.assertNotEqual(self.current.resolve(), previous.resolve())
        self.assertEqual(self.marker(self.snapshot()), "env")

    def test_archive_permissions_are_normalized_before_swap(self):
        self.prepare_live_units()
        result = self.run_manager("deploy", "--channel", "stable")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        release = self.current.resolve()
        self.assertEqual(release.stat().st_mode & 0o777, 0o755)
        self.assertEqual((release / "aetherflow-api").stat().st_mode & 0o777, 0o755)
        self.assertEqual(release.stat().st_uid, os.getuid())
        self.assertIn("service access verified", result.stdout)
        self.assertLess(result.stdout.index("service access verified"), result.stdout.index("Atomic Symlink Swap"))

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0, "requires root")
    def test_inaccessible_release_aborts_before_swap(self):
        self.prepare_live_units()
        result = self.run_manager("deploy", "--channel", "stable", TEST_SERVICE_USER="nobody")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing symlink swap", result.stdout)
        self.assertFalse(self.current.exists())
        self.assertNotIn("systemctl restart", self.commands.read_text())

    def test_stable_tag_falls_back_without_github_api(self):
        result = self.run_manager("deploy", "--dry-run", TEST_API_RATE_LIMITED="1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("releases/download/v4.0.0/", self.commands.read_text())

    def test_stable_redirect_must_belong_to_expected_repository(self):
        result = self.run_manager("deploy", "--dry-run", TEST_API_RATE_LIMITED="1", TEST_LATEST_URL="https://example.com/releases/tag/v9.9.9")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("releases/download/", self.commands.read_text())

    def test_not_ready_rolls_back_without_replacing_units(self):
        live_db = self.root / "live" / "from-env.sqlite"
        self.write_db(live_db, "env")
        self.env_file.write_text(f"DB_PATH={live_db}\n")
        self.prepare_live_units()
        previous = self.releases / "100"
        previous.mkdir()
        (previous / "aetherflow-api").write_text("previous")
        self.current.symlink_to(previous)
        result = self.run_manager(
            "deploy", "--channel", "stable",
            TEST_HEALTH_CODE="503",
            TEST_HEALTH_BODY='{"uptime":"0.0s","database":"unreachable","redis":"disabled","status":"not_ready"}',
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("ROLLBACK COMPLETE", result.stdout)
        self.assertEqual(self.current.resolve(), previous.resolve())
        self.assertEqual((self.units / "aetherflow-api.service").read_text(), "LIVE-UNIT\n")
        self.assertEqual(self.marker(live_db), "env")

    def test_failed_probe_restores_preswap_snapshot_of_resolved_db(self):
        live_db = self.root / "live" / "from-env.sqlite"
        self.write_db(live_db, "env")
        self.env_file.write_text(f"DB_PATH={live_db}\n")
        self.prepare_live_units()
        previous = self.releases / "100"
        previous.mkdir()
        (previous / "aetherflow-api").write_text("previous")
        self.current.symlink_to(previous)
        result = self.run_manager(
            "deploy", "--channel", "stable",
            TEST_HEALTH_CODE="503",
            TEST_HEALTH_BODY='{"status":"not_ready","database":"unreachable","redis":"disabled","uptime":"1.0s"}',
            TEST_CORRUPT_DB=str(live_db),
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("ROLLBACK COMPLETE", result.stdout)
        self.assertEqual(self.current.resolve(), previous.resolve())
        snapshots = list(self.releases.glob("*/data-snapshot/aetherflow.sqlite.bak"))
        self.assertEqual(len(snapshots), 1)
        self.assertNotIn("/100/data-snapshot/", result.stdout.replace("\\", "/"))
        self.assertIn(f"Database recovery snapshot release: {snapshots[0].parents[1]}", result.stdout)
        self.assertFalse(Path(str(live_db) + "-wal").exists())
        self.assertFalse(Path(str(live_db) + "-shm").exists())
        self.assertEqual(self.marker(live_db), "env")
        self.assertTrue(list(live_db.parent.glob(live_db.name + ".corrupted.*")))
        self.assertIn("systemctl stop aetherflow-api.service aetherflow-runner.service", self.commands.read_text())



    def test_nightly_channel_resolves_versioned_v4_release(self):
        live_db = self.root / "live" / "from-env.sqlite"
        self.write_db(live_db, "env")
        self.env_file.write_text(f"DB_PATH={live_db}\n")
        releases_json = (
            '[{"tag_name":"v4.0.0-experimental","draft":false,"prerelease":true,"target_commitish":"experimental"},'
            '{"tag_name":"v4.0.0-nightly.124.1","draft":true,"prerelease":true,"target_commitish":"ignored"},'
            '{"tag_name":"v4.0.0-nightly.123.1","draft":false,"prerelease":true,"target_commitish":"abc1234"},'
            '{"tag_name":"v3.2.7","draft":false,"prerelease":false,"target_commitish":"master"}]'
        )
        result = self.run_manager(
            "deploy", "--channel", "nightly", "--dry-run",
            TEST_RELEASES_JSON=releases_json,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Resolved release tag v4.0.0-nightly.123.1 for channel nightly.", result.stdout)
        self.assertIn("releases/download/v4.0.0-nightly.123.1/aetherflow-linux-amd64.tar.gz", self.commands.read_text())

    def test_experimental_channel_resolves_prerelease_tag(self):
        live_db = self.root / "live" / "from-env.sqlite"
        self.write_db(live_db, "env")
        self.env_file.write_text(f"DB_PATH={live_db}\n")
        releases_json = (
            '[{"tag_name":"experimental","draft":false,"prerelease":true,"target_commitish":"experimental"},'
            '{"tag_name":"v3.2.6","draft":false,"prerelease":false,"target_commitish":"master"}]'
        )
        result = self.run_manager(
            "deploy", "--channel", "experimental", "--dry-run",
            TEST_RELEASES_JSON=releases_json,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Resolved release tag experimental for channel experimental.", result.stdout)
        self.assertIn("releases/download/experimental/aetherflow-linux-amd64.tar.gz", self.commands.read_text())


if __name__ == "__main__":
    unittest.main()
