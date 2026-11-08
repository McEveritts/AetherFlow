#!/usr/bin/env python3
"""Exercise real npm Git preparation offline, without changing the host."""
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))
from installer_test_helpers import ROOT, common_functions


@unittest.skipUnless(all(shutil.which(cmd) for cmd in ("bash", "git", "node", "npm")),
                     "Requires Bash, Git, Node.js and npm")
class NodeInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="af-node-install-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.app = self.root / "app"
        self.executable = self.root / "bin/fixture-app"
        self.log = self.root / "install.log"
        self.helpers = self.root / "helpers.sh"
        self.helpers.write_text(common_functions("node_build", "install_npm_app", "replace_app_tree"))
        config = self.root / "npmrc"
        config.write_text("global=true\nomit=dev\nignore-scripts=true\n")
        self.env = {
            **os.environ,
            "LOGFILE": str(self.log),
            "NPM_CONFIG_USERCONFIG": str(config),
            "npm_config_cache": str(self.root / "cache"),
            "npm_config_prefix": str(self.root / "global-prefix"),
            "npm_config_registry": "http://127.0.0.1:9",
            "NODE_ENV": "production",
            "npm_config_global": "true", "NPM_CONFIG_GLOBAL": "true",
            "npm_config_production": "true", "NPM_CONFIG_PRODUCTION": "true",
            "npm_config_omit": "dev", "NPM_CONFIG_OMIT": "dev",
            "npm_config_ignore_scripts": "true", "NPM_CONFIG_IGNORE_SCRIPTS": "true",
            "npm_config_optional": "false", "NPM_CONFIG_OPTIONAL": "false",
        }
        # The Git dependency's prepare step requires a CLI declared only in its
        # devDependencies, matching irc-framework's Babel/npm-run-all dependency.
        tool = self.archive("fixture-build-tool", {
            "package.json": json.dumps({"name": "fixture-build-tool", "version": "1.0.0",
                                        "bin": {"fixture-build": "build.js"}}),
            "build.js": ("#!/usr/bin/env node\n"
                         "if (process.env.AF_TEST_BUILD_FAIL) process.exit(37);\n"
                         "require('fs').writeFileSync('built.js', 'module.exports = \"compiled\";');\n"),
        })
        self.optional_dependency = self.archive("fixture-optional", {
            "package.json": json.dumps({"name": "fixture-optional", "version": "1.0.0"}),
            "index.js": 'module.exports = "optional";\n',
        })
        repository = self.root / "git-dependency"
        repository.mkdir()
        (repository / "package.json").write_text(json.dumps({
            "name": "fixture-git-dep", "version": "1.0.0", "main": "built.js",
            "files": ["built.js"], "scripts": {"prepare": "fixture-build"},
            "devDependencies": {"fixture-build-tool": "file:" + str(tool)},
        }))
        for args in (("init", "-q"), ("add", "."),
                     ("-c", "user.name=Fixture", "-c", "user.email=fixture@localhost", "commit", "-qm", "fixture")):
            subprocess.run(["git", "-C", str(repository), *args], check=True, capture_output=True)
        revision = subprocess.check_output(["git", "-C", str(repository), "rev-parse", "HEAD"], text=True).strip()
        self.git_dependency = "git+" + repository.as_uri() + "#" + revision

    def archive(self, name, files):
        target = self.root / (name + ".tgz")
        with tarfile.open(target, "w:gz") as output:
            for relative, text in files.items():
                payload = text.encode()
                info = tarfile.TarInfo("package/" + relative)
                info.size = len(payload)
                info.mode = 0o755 if relative.endswith(".js") else 0o644
                output.addfile(info, io.BytesIO(payload))
        return target

    def package(self, version="1.0.0", with_bin=True, scoped=False):
        package = {"name": "@fixture/app" if scoped else "fixture-app", "version": version,
                   "dependencies": {"fixture-git-dep": self.git_dependency},
                   "optionalDependencies": {"fixture-optional": "file:" + str(self.optional_dependency)}}
        if with_bin:
            package["bin"] = {"fixture-app": "cli.js"}
        return self.archive("app-" + version, {
            "package.json": json.dumps(package),
            "cli.js": ("#!/usr/bin/env node\n"
                       "console.log(require('./package.json').version + ':' + require('fixture-git-dep') + ':' + require('fixture-optional'));\n"),
        })

    def install(self, package=None, **environment):
        script = '''set -euo pipefail
source "$1"
print_error() { printf '%s\\n' "$*" >&2; }
log_info() { printf '%s\\n' "$*"; }
install_npm_app "$2" "$3" "$4"
test "$npm_config_global" = true
test "$NPM_CONFIG_IGNORE_SCRIPTS" = true
test "$NODE_ENV" = production
'''
        return subprocess.run(["bash", "-c", script, "test", str(self.helpers),
                               str(package or self.package()), str(self.app), str(self.executable)],
                              env={**self.env, **environment}, capture_output=True, text=True, timeout=60)

    def assert_installed(self, result, version="1.0.0"):
        self.assertEqual(result.returncode, 0, result.stderr + self.log.read_text())
        self.assertEqual(subprocess.check_output([str(self.executable)], text=True).strip(), version + ":compiled:optional")
        self.assertEqual(self.app.stat().st_mode & 0o777, 0o755)
        self.assertFalse(list(self.root.glob("app.af-build.*")))
        self.assertFalse((self.root / "global-prefix").exists())

    def test_git_dev_tooling_builds_with_production_and_global_settings(self):
        self.assert_installed(self.install())
        self.assertFalse(shutil.which("fixture-build"))

    def test_scoped_npm_application_and_its_git_dependency_build_locally(self):
        self.assert_installed(self.install(self.package(scoped=True)))

    def test_failed_prepare_leaves_existing_application_and_cli_usable(self):
        self.app.mkdir()
        sentinel = self.app / "retained"
        sentinel.write_text("old-code")
        self.executable.parent.mkdir()
        self.executable.write_text("#!/bin/sh\nprintf old-version")
        self.executable.chmod(0o755)
        result = self.install(AF_TEST_BUILD_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_text(), "old-code")
        self.assertEqual(subprocess.check_output([str(self.executable)], text=True), "old-version")
        self.assertFalse(list(self.root.glob("app.af-build.*")))
        self.assertFalse(list(self.root.glob("app.af-backup.*")))

    def test_missing_executable_does_not_activate_incomplete_package(self):
        result = self.install(self.package(with_bin=False))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("did not provide executable", result.stderr)
        self.assertFalse(self.app.exists())
        self.assertFalse(self.executable.exists())
        self.assertFalse(list(self.root.glob("app.af-build.*")))

    def test_successful_upgrade_keeps_previous_application_for_recovery(self):
        self.assert_installed(self.install())
        self.assert_installed(self.install(self.package("2.0.0")), "2.0.0")
        backups = list(self.root.glob("app.af-backup.*/app"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(subprocess.check_output([str(backups[0] / "node_modules/.bin/fixture-app")], text=True).strip(),
                         "1.0.0:compiled:optional")


class NodeInstallerContracts(unittest.TestCase):
    def test_existing_node_runtime_still_provisions_native_build_prerequisites(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            helpers = common_functions("command_exists", "ensure_node")
            result = subprocess.run(["bash", "-euc", helpers + '''
node() { printf v26.0.0; }
apt-get() { printf '%s\\n' "$*" > "$TEST_ROOT/prerequisites"; }
sync_node_global_bins() { :; }
fetch_and_run() { exit 99; }
ensure_node 20
'''], env={**os.environ, "LOGFILE": str(root / "log"), "TEST_ROOT": str(root)},
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            installed = (root / "prerequisites").read_text().split()
            for dependency in ("git", "build-essential", "python3", "python3-setuptools", "pkg-config"):
                self.assertIn(dependency, installed)

    def test_catalog_installers_do_not_use_global_npm_or_bare_build_installs(self):
        for script in (ROOT / "packages/package/install").glob("installpackage-*"):
            with self.subTest(script=script.name):
                source = script.read_text()
                self.assertIsNone(re.search(r"\bnpm\s+install\s+(?:-g\b|--global\b)", source))
                for line in source.splitlines():
                    if not line.lstrip().startswith("#") and re.search(r"\b(?:npm|yarn|pnpm)\s+(?:install|ci|run|build)\b", line):
                        self.assertIn("node_build ", line)


if __name__ == "__main__":
    unittest.main()
