import ast
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import zipfile
try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 compatibility (ubuntu-22.04)
    tomllib = None
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import common_functions

ROOT = Path(__file__).resolve().parents[1]
PACKAGES_DIR = ROOT / "packages" / "package"
INSTALL_DIR = PACKAGES_DIR / "install"
REMOVE_DIR = PACKAGES_DIR / "remove"

COHORT_APPS = [
    "dispatcharr",
    "duplicati",
    "filebot",
    "listenarr",
    "notifiarr",
    "novnc",
    "pyload",
    "quassel",
    "requestrr",
    "seedcross",
    "unmanic",
    "x2go",
]

FORBIDDEN_HELPERS = [
    "setup_log",
    "apt_update",
    "apt_install",
    "ensure_service_user",
    "ensure_master_credentials",
    "stop_disable_service",
]


class MarketplaceHelperContractsTest(unittest.TestCase):

    def test_zip_members_are_checked_before_staging(self):
        helper = common_functions("af_extract_zip_archive") + '\naf_extract_zip_archive "$@"'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = root / "fixture.zip"
            destination = root / "staged"
            destination.mkdir()
            valid = zipfile.ZipInfo("app/tool")
            valid.create_system = 3
            valid.external_attr = (stat.S_IFREG | 0o4755) << 16
            linked = zipfile.ZipInfo("app/link")
            linked.create_system = 3
            linked.external_attr = (stat.S_IFLNK | 0o777) << 16
            for invalid in (linked, "../unmanaged.txt"):
                with self.subTest(member=invalid):
                    with zipfile.ZipFile(archive_path, "w") as bundle:
                        bundle.writestr(valid, b"fixture")
                        bundle.writestr(invalid, b"fixture")
                    result = subprocess.run(
                        ["bash", "-c", helper, "extract", archive_path, destination],
                        capture_output=True, text=True, timeout=10,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertIn("disallowed ZIP entry", result.stderr)
                    self.assertEqual(list(destination.iterdir()), [])
                    self.assertFalse((root / "unmanaged.txt").exists())

            with zipfile.ZipFile(archive_path, "w") as bundle:
                bundle.writestr(valid, b"fixture")
            result = subprocess.run(
                ["bash", "-c", helper, "extract", archive_path, destination],
                capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            installed = destination / "app/tool"
            self.assertEqual(installed.read_bytes(), b"fixture")
            self.assertEqual(stat.S_IMODE(installed.stat().st_mode) & 0o4111, 0o111)

    def test_marketplace_version_probes_use_package_fallback_and_native_scrutiny(self):
        automation = json.loads((ROOT / "config/package_automation.json").read_text())
        self.assertEqual(
            automation["mergerfs"]["version_command"],
            ["dpkg-query", "-W", "-f=${Version}", "mergerfs"],
        )
        for package, executable, deb in (
            ("tailscale", "tailscale", "tailscale"),
            ("rtorrent", "rtorrent", "rtorrent"),
            ("quassel", "quasselcore", "quassel-core"),
            ("x2go", "x2goversion", "x2goserver"),
        ):
            for output, expected in (
                ("return 1", "2.0.0-1"),
                ("return 0", "2.0.0-1"),
                (r"printf '3.0.0\nsecond line\n'", "3.0.0"),
            ):
                with self.subTest(package=package, output=output):
                    fixture = f"{executable}() {{ {output}; }}\n" + r"""
dpkg-query() {
    [[ "$1" == '-W' && "$2" == '-f=${Version}' && "$3" == "$1_expected" ]] || return 1
    printf '2.0.0-1'
}
"""
                    fixture = fixture.replace("$1_expected", deb)
                    result = subprocess.run(
                        ["bash", "-c", fixture + automation[package]["version_command"][-1]],
                        capture_output=True, text=True,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), expected)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            probe = automation["scrutiny"]["version_command"][-1].replace("/opt/scrutiny/bin", directory)
            for name in ("scrutiny-web-linux-arm64", "scrutiny-web-linux-amd64"):
                binary = root / name
                binary.write_text(f"#!/bin/sh\nprintf '%s\\n' '{name}'\n")
                binary.chmod(0o700)
            link = root / "scrutiny-web"
            link.symlink_to("scrutiny-web-linux-arm64")
            for expected in ("scrutiny-web-linux-arm64", "scrutiny-web-linux-amd64"):
                result = subprocess.run(["bash", "-c", probe], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)
                link.unlink(missing_ok=True)

    def test_postgresql_restore_reads_private_backup_through_inherited_stdin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backup = root / "backup"
            backup.mkdir(mode=0o700)
            (backup / ".af-database-ready").write_text("invidious\n")
            database_sql = "DROP DATABASE invidious;\nCREATE DATABASE invidious;\n"
            (backup / "invidious.sql").write_text(database_sql)
            (backup / "invidious.sql").chmod(0o600)
            script = common_functions("restore_postgresql_database") + r'''
runuser() {
    if [[ "$*" == *" -f "* ]]; then
        [[ "${@: -1}" == "-" ]] || return 61
        cat > "$RESTORED_SQL"
    else
        cat >/dev/null
    fi
}
restore_postgresql_database "$DATABASE_BACKUP" invidious
'''
            restored = root / "restored.sql"
            result = subprocess.run(["bash", "-euc", script], capture_output=True, text=True, env={
                **os.environ, "DATABASE_BACKUP": str(backup), "RESTORED_SQL": str(restored),
                "LOGFILE": str(root / "restore.log"),
            })
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(restored.read_text(), database_sql)
            self.assertEqual(backup.stat().st_mode & 0o777, 0o700)
            self.assertEqual((backup / "invidious.sql").stat().st_mode & 0o777, 0o600)
    def test_common_sourcing_prefers_script_release_then_current_release(self):
        scripts = [path for action in ("install", "remove", "update")
                   for path in (PACKAGES_DIR / action).glob(f"{action}package-*")
                   if path.name != "installpackage-template"]
        self.assertGreaterEqual(len(scripts), 150)
        for path in scripts:
            with self.subTest(script=path.name):
                source = path.read_text(encoding="utf-8")
                relative = source.index('source "${SELF_DIR}/../../common.sh"')
                if 'source /opt/AetherFlow/current/packages/common.sh' not in source:
                    # A release-relative source with no fallbacks cannot select
                    # stale helpers from a different installed release.
                    self.assertIn('\nsource "${SELF_DIR}/../../common.sh"\n', source)
                    self.assertNotIn('source /opt/AetherFlow/packages/common.sh', source)
                    continue
                current = source.index('source /opt/AetherFlow/current/packages/common.sh')
                legacy = source.index('source /opt/AetherFlow/packages/common.sh')
                self.assertLess(relative, current)
                self.assertLess(current, legacy)

    def test_dispatcharr_v033_runtime_contract(self):
        source = (INSTALL_DIR / "installpackage-dispatcharr").read_text(encoding="utf-8")
        self.assertIn("v0.33.0", source)
        self.assertIn("--extra-index-url https://download.pytorch.org/whl/cpu", source)
        self.assertIn("u.user_level = 10", source)
        self.assertIn("u.is_staff = True", source)
        self.assertIn("u.is_superuser = True", source)
        self.assertIn("u.is_active = True", source)
        self.assertIn("aetherflow_asgi:application", source)
        for variable in ("USER", "PASS", "EMAIL"):
            self.assertIn(f'os.environ["AF_ADMIN_{variable}"]', source)
        self.assertNotIn("u.set_password('${ADMIN_PASS}')", source)
        self.assertEqual(source.count('Environment="PYTHONPATH=${INSTALL_DIR}"'), 3)
        self.assertEqual(source.count('Environment="PATH=${INSTALL_DIR}/env/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"'), 3)
        self.assertEqual(source.count('WorkingDirectory=${INSTALL_DIR}'), 3)

    def test_catalog_audit_fail_fast_and_debian_contracts(self):
        homeassistant = (INSTALL_DIR / "installpackage-homeassistant").read_text()
        self.assertIn("libopenblas-dev", homeassistant)
        self.assertNotIn("libatlas-base-dev", homeassistant)
        for package, commands in (
            ("paperless-ngx", ("manage.py migrate", "manage.py collectstatic --no-input")),
            ("seedcross", ("manage.py migrate --noinput",)),
            ("filebot", ("npm install --include=dev",)),
        ):
            source = (INSTALL_DIR / ("installpackage-" + package)).read_text()
            for command in commands:
                line = next(line for line in source.splitlines() if command in line)
                self.assertNotIn("|| true", line, (package, command))
        pihole = (INSTALL_DIR / "installpackage-pihole").read_text()
        self.assertIn('"${APP_PORT}o"', pihole)

    def test_seedcross_credentials_are_literal_environment_values(self):
        source = (INSTALL_DIR / "installpackage-seedcross").read_text()
        snippet = source.split("<<'PYEOF'\n", 1)[1].split("\nPYEOF", 1)[0]
        for variable in ("USER", "PASS", "EMAIL"):
            self.assertIn(f'os.environ["ADMIN_{variable}"]', snippet)
        self.assertNotIn("${ADMIN_PASS}", snippet)
        password = "single' double\" slash\\ dollar$ `not-executed`\nnewline"
        fixture = '''import json, os, sys, types
class User:
    def set_password(self, password): self.password = password
    def save(self): print(json.dumps(vars(self)))
user = User()
def get_or_create(**values):
    user.username = values["username"]
    return user, True
auth = types.ModuleType("django.contrib.auth")
auth.get_user_model = lambda: types.SimpleNamespace(objects=types.SimpleNamespace(get_or_create=get_or_create, filter=lambda **values: types.SimpleNamespace(exists=lambda: False)))
sys.modules["django.contrib.auth"] = auth
'''
        result = subprocess.run([sys.executable, "-c", fixture + snippet], capture_output=True, text=True,
                                env={**os.environ, "ADMIN_USER": "admin'\"", "ADMIN_PASS": password, "ADMIN_EMAIL": "admin@localhost"})
        self.assertEqual(result.returncode, 0, result.stderr)
        user = json.loads(result.stdout)
        self.assertEqual(user["password"], password)
        self.assertEqual(user["username"], "admin'\"")
        self.assertEqual(user["email"], "admin@localhost")

    def test_catalog_dependency_and_migration_failures_abort_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            failing_python = root / "python"
            failing_python.write_text("#!/bin/bash\nexit 17\n")
            failing_python.chmod(0o755)
            for package, command in (
                ("paperless-ngx", "manage.py migrate"),
                ("paperless-ngx", "manage.py collectstatic --no-input"),
                ("seedcross", "manage.py migrate --noinput"),
                ("filebot", "npm install --include=dev"),
            ):
                with self.subTest(package=package, command=command):
                    source = (INSTALL_DIR / ("installpackage-" + package)).read_text()
                    line = next(line for line in source.splitlines() if command in line)
                    line = line.replace("/opt/paperless/.venv/bin/python", str(failing_python))
                    result = subprocess.run(["bash", "-euc", common_functions("node_build") + "\nsu() { return 17; }; npm() { return 17; };\n" + line + "\nexit 0"],
                                            capture_output=True, text=True,
                                            env={**os.environ, "LOGFILE": str(root / "log"), "INSTALL_DIR": str(root), "APP_USER": "seedcross"})
                    self.assertEqual(result.returncode, 17, result.stderr)

    def test_notifiarr_credentials_are_literal_toml_strings(self):
        source = (INSTALL_DIR / 'installpackage-notifiarr').read_text(encoding='utf-8')
        start = source.index('NOTIFIARR_UI_CREDENTIALS=')
        python_code = source[start:].split("<<'PYEOF'\n", 1)[1].split('\nPYEOF', 1)[0]
        credentials = 'admin:p|a&ss\\word"with\nnewline'
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'notifiarr.conf'
            config.write_text('ui_password = "old"\napi_key = "retain"\n')
            adapter = common_functions("safe_config_python") + '\nsafe_config_python "$1" <<\'PYEOF\'\n' + python_code + '\nPYEOF\n'
            result = subprocess.run(['bash', '-euc', adapter, 'fixture', str(config)],
                                    text=True, capture_output=True,
                                    env={**os.environ, 'NOTIFIARR_UI_CREDENTIALS': credentials})
            self.assertEqual(result.returncode, 0, result.stderr)
            raw_toml = config.read_text()
            if tomllib is not None:
                parsed = tomllib.loads(raw_toml)
            else:
                parsed = {}
                for line in raw_toml.splitlines():
                    if "=" in line and not line.lstrip().startswith("#"):
                        k, v = line.split("=", 1)
                        parsed[k.strip()] = ast.literal_eval(v.strip())
            self.assertEqual(parsed['ui_password'], credentials)
            self.assertEqual(parsed['api_key'], 'retain')

    def test_cohort_files_exist(self):
        for app in COHORT_APPS:
            inst_file = INSTALL_DIR / f"installpackage-{app}"
            rem_file = REMOVE_DIR / f"removepackage-{app}"
            self.assertTrue(inst_file.exists(), f"Missing install script for {app}")
            self.assertTrue(rem_file.exists(), f"Missing remove script for {app}")

    def test_p01_no_forbidden_undefined_helpers(self):
        for app in COHORT_APPS:
            for kind, path in [
                ("install", INSTALL_DIR / f"installpackage-{app}"),
                ("remove", REMOVE_DIR / f"removepackage-{app}"),
            ]:
                text = path.read_text(encoding="utf-8")
                for helper in FORBIDDEN_HELPERS:
                    pattern = r"(?m)^\s*" + re.escape(helper) + r"\b"
                    match = re.search(pattern, text)
                    self.assertIsNone(
                        match,
                        f"Found forbidden undefined helper '{helper}' in {path.name}",
                    )

    def test_p01_logfile_contract(self):
        for app in COHORT_APPS:
            for kind, path in [
                ("install", INSTALL_DIR / f"installpackage-{app}"),
                ("remove", REMOVE_DIR / f"removepackage-{app}"),
            ]:
                text = path.read_text(encoding="utf-8")
                self.assertNotIn(
                    "${LOG_FILE}",
                    text,
                    f"Found obsolete variable ${{LOG_FILE}} in {path.name}",
                )
                self.assertNotIn(
                    '"$LOG_FILE"',
                    text,
                    f"Found obsolete variable $LOG_FILE in {path.name}",
                )
                self.assertIn(
                    "LOGFILE=",
                    text,
                    f"LOGFILE definition missing in {path.name}",
                )

    def test_p01_lock_contracts(self):
        for app in COHORT_APPS:
            inst_path = INSTALL_DIR / f"installpackage-{app}"
            inst_text = inst_path.read_text(encoding="utf-8")
            self.assertNotIn(
                'write_lock "${LOCK_FILE}"',
                inst_text,
                f"write_lock must take package name not LOCK_FILE in {inst_path.name}",
            )
            write_lock_match = re.search(r'write_lock\s+([^\s]+)', inst_text)
            self.assertIsNotNone(write_lock_match, f"write_lock call missing in {inst_path.name}")
            arg = write_lock_match.group(1).strip('"').strip("'")
            self.assertIn(arg, ('${PACKAGE_NAME}', app))

            rem_path = REMOVE_DIR / f"removepackage-{app}"
            rem_text = rem_path.read_text(encoding="utf-8")
            self.assertNotIn(
                'remove_lock "${LOCK_FILE}"',
                rem_text,
                f"remove_lock must take package name not LOCK_FILE in {rem_path.name}",
            )
            remove_lock_match = re.search(r'remove_lock\s+([^\s]+)', rem_text)
            self.assertIsNotNone(remove_lock_match, f"remove_lock call missing in {rem_path.name}")
            rem_arg = remove_lock_match.group(1).strip('"').strip("'")
            self.assertIn(rem_arg, ('${PACKAGE_NAME}', app))

    def test_p01_noninteractive_apt(self):
        for app in COHORT_APPS:
            for kind, path in [
                ("install", INSTALL_DIR / f"installpackage-{app}"),
                ("remove", REMOVE_DIR / f"removepackage-{app}"),
            ]:
                text = path.read_text(encoding="utf-8")
                for line in text.splitlines():
                    if "apt-get " in line:
                        self.assertIn(
                            "DEBIAN_FRONTEND=noninteractive",
                            line,
                            f"apt-get called without DEBIAN_FRONTEND=noninteractive in {path.name}: {line}",
                        )

    def test_p01_remove_uses_purge_systemd_unit(self):
        for app in COHORT_APPS:
            rem_path = REMOVE_DIR / f"removepackage-{app}"
            rem_text = rem_path.read_text(encoding="utf-8")
            self.assertIn(
                "purge_systemd_unit",
                rem_text,
                f"Expected purge_systemd_unit in {rem_path.name}",
            )

    def test_p02_latent_destructive_config_retention(self):
        for app, cfg_dir in [
            ("dispatcharr", "${CONFIG_DIR}"),
            ("duplicati", "${CONFIG_DIR}"),
            ("novnc", "${CONFIG_DIR}"),
        ]:
            rem_path = REMOVE_DIR / f"removepackage-{app}"
            rem_text = rem_path.read_text(encoding="utf-8")
            pattern = re.compile(
                r'if\s+\[\[\s*"\$\{DELETE_DATA:-false\}"\s*==\s*"true"\s*\]\];\s*then[\s\S]*?'
                + re.escape(cfg_dir)
                + r'[\s\S]*?fi'
            )
            self.assertTrue(
                pattern.search(rem_text),
                f"{app} remove script must only purge {cfg_dir} when DELETE_DATA is true",
            )
            outside_pattern = re.compile(
                r'rm\s+-[rf]+\s+.*' + re.escape(cfg_dir)
            )
            lines_outside = []
            delete_data_depth = 0
            for line in rem_text.splitlines():
                if 'if [[ "${DELETE_DATA:-false}" == "true" ]]' in line:
                    delete_data_depth = 1
                elif delete_data_depth and line.strip().startswith("if "):
                    delete_data_depth += 1
                elif delete_data_depth and line.strip() == "fi":
                    delete_data_depth -= 1
                elif not delete_data_depth and outside_pattern.search(line):
                    lines_outside.append(line)
            self.assertEqual(
                lines_outside,
                [],
                f"{app} contains unconditional config deletion outside DELETE_DATA block: {lines_outside}",
            )

    def test_p06_pip_upgrade_flags(self):
        for app in ["pyload", "unmanic"]:
            inst_path = INSTALL_DIR / f"installpackage-{app}"
            inst_text = inst_path.read_text(encoding="utf-8")
            pattern = rf'pip"\s+install\s+--upgrade\s+.*{app}'
            self.assertTrue(
                re.search(pattern, inst_text),
                f"{app} pip installer missing --upgrade flag in {inst_path.name}",
            )

    def test_p10_novnc_apt_and_version(self):
        inst_path = INSTALL_DIR / "installpackage-novnc"
        inst_text = inst_path.read_text(encoding="utf-8")
        self.assertIn("apt-get install", inst_text)
        self.assertIn("novnc", inst_text)
        self.assertTrue(re.search(r"apt-get install.*novnc", inst_text, re.DOTALL))
        self.assertIn(".af-version", inst_text)
        self.assertIn("CONFIG_DIR", inst_text)


if __name__ == "__main__":
    unittest.main()
