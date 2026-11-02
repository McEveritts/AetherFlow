import os
import re
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

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
    def test_notifiarr_credentials_are_literal_toml_strings(self):
        source = (INSTALL_DIR / 'installpackage-notifiarr').read_text(encoding='utf-8')
        start = source.index('NOTIFIARR_UI_CREDENTIALS=')
        python_code = source[start:].split("<<'PYEOF'\n", 1)[1].split('\nPYEOF', 1)[0]
        credentials = 'admin:p|a&ss\\word"with\nnewline'
        with tempfile.TemporaryDirectory() as directory:
            config = Path(directory) / 'notifiarr.conf'
            config.write_text('ui_password = "old"\napi_key = "retain"\n')
            result = subprocess.run([sys.executable, '-', str(config)], input=python_code,
                                    text=True, capture_output=True,
                                    env={**os.environ, 'NOTIFIARR_UI_CREDENTIALS': credentials})
            self.assertEqual(result.returncode, 0, result.stderr)
            parsed = tomllib.loads(config.read_text())
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
            in_delete_data_block = False
            for line in rem_text.splitlines():
                if 'if [[ "${DELETE_DATA:-false}" == "true" ]]' in line:
                    in_delete_data_block = True
                elif in_delete_data_block and line.strip() == "fi":
                    in_delete_data_block = False
                elif not in_delete_data_block and outside_pattern.search(line):
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
