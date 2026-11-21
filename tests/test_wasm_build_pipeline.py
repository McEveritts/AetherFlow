"""Exercise pinned tool discovery and release/frontend build contracts offline."""
import ast
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
VERSIONS = {
    "trunk": "trunk 0.22.1",
    "wasm-bindgen": "wasm-bindgen 0.2.130",
    "wasm-opt": "wasm-opt version 133",
    "tailwindcss": "tailwindcss v4.3.5",
}
TOOL_PATH = ('${WASM_TOOL_DIR:-/usr/local/lib/aetherflow-wasm-tools}/bin:'
             '${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/aetherflow-wasm-tools/bin:'
             '${HOME:-/root}/.cargo/bin:')


@unittest.skipUnless(os.name == "posix" and shutil.which("bash"), "requires shell tools")
class WasmBuildPipelineTests(unittest.TestCase):
    def test_obsolete_unreferenced_logo_is_not_shipped(self):
        self.assertFalse((ROOT / "frontend-rs/public/img/af-logo.png").exists())
        self.assertFalse((ROOT / "frontend-rs/public/icon.svg").exists())
        self.assertTrue((ROOT / "frontend-rs/public/img/aetherflow-icon.svg").is_file())
        self.assertTrue((ROOT / "frontend-rs/public/img/aetherflow-mark.svg").is_file())

    def test_wsl_helpers_use_the_rust_and_wasm_build_pipeline(self):
        for filename in ["build_wsl.ps1", "setup_wsl_dev.sh"]:
            with self.subTest(script=filename):
                script = (ROOT / "scripts" / filename).read_text()
                self.assertIn("bash scripts/install_wasm_build_tools.sh --ensure", script)
                self.assertIn("bash scripts/build_wasm_frontend.sh --stage", script)
                self.assertIn(
                    "cargo build --release --locked --manifest-path backend-rs/Cargo.toml "
                    "--bin aetherflow-api --bin af", script,
                )
                self.assertNotIn("npm run build", script)
                self.assertNotRegex(script, r"\bgo (?:build|test|version)\b")

    def test_vm_builder_delegates_architecture_and_version_pins_to_installer(self):
        script = (ROOT / "scripts/v4_vm_matrix.py").read_text()
        self.assertIn("bash scripts/install_wasm_build_tools.sh --ensure", script)
        self.assertNotIn("-x scripts/install_wasm_build_tools.sh", script)
        for duplicate in [
            "trunk-x86_64-unknown-linux-musl.tar.gz",
            "wasm-bindgen-0.2.130-x86_64-unknown-linux-musl.tar.gz",
            "binaryen-version_133-x86_64-linux.tar.gz",
            "tailwindcss-linux-x64",
            "x86_64-unknown-linux-gnu/rustup-init",
        ]:
            with self.subTest(duplicate=duplicate):
                self.assertNotIn(duplicate, script)

    def test_build_and_embedded_entrypoints_are_executable(self):
        for filename in ["build_gold.sh", "run_embedded_e2e.sh", "setup_wsl_dev.sh"]:
            with self.subTest(script=filename):
                self.assertTrue(os.access(ROOT / "scripts" / filename, os.X_OK))

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="af-wasm-pipeline-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.bin = self.root / "tools/bin"
        self.bin.mkdir(parents=True)
        self.fixtures = self.root / "fixtures"
        self.fixtures.mkdir()
        self.environment = os.environ.copy()
        self.environment.pop("RUSTUP_TOOLCHAIN", None)
        self.environment.update({
            "PATH": f"{self.bin}:/usr/bin:/bin",
            "WASM_TOOL_DIR": str(self.bin.parent),
            "TEST_DOWNLOAD_LOG": str(self.root / "downloads.log"),
            "TEST_VERSION_LOG": str(self.root / "versions.log"),
            "TEST_RUSTUP_LOG": str(self.root / "rustup.log"),
            "TEST_CHECKSUM_LOG": str(self.root / "checksums.log"),
            "TEST_FIXTURES": str(self.fixtures),
            "TEST_INSTALLED_TARGETS": "wasm32-unknown-unknown",
            "CARGO_TARGET_DIR": "/tmp/af-bs1-target",
        })
        self.write_tool("uname", '#!/bin/sh\ncase "$1" in -s) echo Linux ;; -m) echo "${TEST_ARCH:-x86_64}" ;; esac\n')
        self.write_tool("cargo", "#!/bin/sh\nexit 0\n")
        self.write_tool("rustup", '''#!/bin/sh
printf '%s\n' "$*" >> "$TEST_RUSTUP_LOG"
if [ "$*" = 'target list --installed' ]; then
    printf 'x86_64-unknown-linux-gnu\n%s\n' "$TEST_INSTALLED_TARGETS"
fi
''')
        # Network and checksum I/O are isolated; archive extraction and installation
        # use the actual shell tools against locally generated executable fixtures.
        self.write_tool("curl", '''#!/usr/bin/python3
import os
from pathlib import Path
import shutil
import sys
args = sys.argv[1:]
url = args[-1]
destination = args[args.index('--output') + 1]
with Path(os.environ['TEST_DOWNLOAD_LOG']).open('a') as log:
    log.write(url + '\\n')
if '/trunk-' in url:
    fixture = 'trunk.tar.gz'
elif '/wasm-bindgen-' in url:
    fixture = 'bindgen.tar.gz'
elif '/binaryen-' in url:
    fixture = 'binaryen.tar.gz'
elif url.endswith('/rustup-init'):
    fixture = 'rustup-init'
else:
    fixture = 'tailwindcss'
shutil.copyfile(Path(os.environ['TEST_FIXTURES']) / fixture, destination)
''')
        self.write_tool("sha256sum", '#!/bin/sh\ncat >> "$TEST_CHECKSUM_LOG"\n')
        for tool, version in VERSIONS.items():
            self.write_tool(tool, self.version_script(tool, version))

    def write_tool(self, name, source):
        path = self.bin / name
        path.write_text(source)
        path.chmod(0o755)

    @staticmethod
    def version_script(tool, version):
        return (f'#!/bin/sh\nprintf "%s\\n" "{tool} $*" >> "$TEST_VERSION_LOG"\n'
                f'printf "%s\\n" "{version}"\n')

    def archive(self, name, members):
        with tarfile.open(self.fixtures / name, "w:gz") as archive:
            for path, source in members.items():
                data = source.encode()
                info = tarfile.TarInfo(path)
                info.size = len(data)
                info.mode = 0o755
                archive.addfile(info, io.BytesIO(data))

    def prepare_archives(self, arch):
        triple = "x86_64-unknown-linux-musl" if arch == "x86_64" else "aarch64-unknown-linux-gnu"
        self.archive("trunk.tar.gz", {"trunk": self.version_script("trunk", VERSIONS["trunk"])})
        self.archive("bindgen.tar.gz", {
            f"wasm-bindgen-0.2.130-{triple}/wasm-bindgen":
                self.version_script("wasm-bindgen", VERSIONS["wasm-bindgen"]),
        })
        self.archive("binaryen.tar.gz", {
            "binaryen-version_133/bin/wasm-opt": self.version_script("wasm-opt", VERSIONS["wasm-opt"]),
            "binaryen-version_133/lib/libbinaryen.so": "test shared library",
        })
        (self.fixtures / "tailwindcss").write_text(self.version_script("tailwindcss", VERSIONS["tailwindcss"]))

    def install(self, *arguments):
        return subprocess.run(["bash", str(ROOT / "scripts/install_wasm_build_tools.sh"),
                               "--ensure", *arguments], env=self.environment,
                              capture_output=True, text=True, timeout=30)

    def test_matching_versions_skip_downloads_and_check_installed_wasm_target(self):
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "downloads.log").exists())
        self.assertEqual(set((self.root / "versions.log").read_text().splitlines()),
                         {f"{tool} --version" for tool in VERSIONS})
        self.assertEqual((self.root / "rustup.log").read_text(), "target list --installed\n")

    def test_each_mismatched_version_is_replaced_with_its_pin(self):
        self.prepare_archives("x86_64")
        for tool in VERSIONS:
            with self.subTest(tool=tool):
                (self.root / "downloads.log").unlink(missing_ok=True)
                self.write_tool(tool, self.version_script(tool, f"{tool} obsolete"))
                result = self.install()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len((self.root / "downloads.log").read_text().splitlines()), 1)
                version = subprocess.check_output([str(self.bin / tool), "--version"],
                                                  env=self.environment, text=True).strip()
                self.assertEqual(version, VERSIONS[tool])

    def test_prefix_colliding_versions_are_replaced_with_exact_pins(self):
        self.prepare_archives("x86_64")
        for tool, version in [
            ("trunk", "trunk 0.22.10"),
            ("wasm-bindgen", "wasm-bindgen 0.2.1300"),
            ("wasm-opt", "wasm-opt version 1330"),
            ("tailwindcss", "tailwindcss v4.3.50"),
        ]:
            with self.subTest(tool=tool):
                (self.root / "downloads.log").unlink(missing_ok=True)
                self.write_tool(tool, self.version_script(tool, version))
                result = self.install()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(len((self.root / "downloads.log").read_text().splitlines()), 1)
                installed = subprocess.check_output([str(self.bin / tool), "--version"],
                                                    env=self.environment, text=True).strip()
                self.assertEqual(installed, VERSIONS[tool])

    def test_tailwind_version_can_include_its_cli_banner(self):
        self.write_tool("tailwindcss", self.version_script("tailwindcss", "≈ tailwindcss v4.3.5"))
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "downloads.log").exists())

    def test_linux_cpu_variants_select_pinned_upstream_archives(self):
        for arch in ["x86_64", "aarch64", "arm64"]:
            with self.subTest(arch=arch):
                self.environment["TEST_ARCH"] = arch
                self.prepare_archives(arch)
                for tool in VERSIONS:
                    self.write_tool(tool, self.version_script(tool, "obsolete"))
                for log in ["downloads.log", "checksums.log"]:
                    (self.root / log).unlink(missing_ok=True)
                result = self.install()
                self.assertEqual(result.returncode, 0, result.stderr)
                urls = (self.root / "downloads.log").read_text()
                checksums = (self.root / "checksums.log").read_text()
                triple = "x86_64-unknown-linux-musl" if arch == "x86_64" else "aarch64-unknown-linux-gnu"
                self.assertIn(f"trunk-{triple}.tar.gz", urls)
                self.assertIn(f"wasm-bindgen-0.2.130-{triple}.tar.gz", urls)
                self.assertIn(f"binaryen-version_133-{'x86_64' if arch == 'x86_64' else 'aarch64'}-linux.tar.gz", urls)
                self.assertIn(f"tailwindcss-linux-{'x64' if arch == 'x86_64' else 'arm64'}", urls)
                if arch != "x86_64":
                    for digest in [
                        "b4017d1e0bfcffb4f4bee2be37c48def21e6e6896c3d0f503c43c42f714e57ea",
                        "cc8dd8e90aa9111758168d30c63a14b7f0276997d9d60d3e160a1fb5e7d3b919",
                        "89c07ea56faf38d0fbecf36ca8ec0721756716185f265b568e133d427f299bf8",
                        "ffcd0d21dbd7c605dc12743ff0c0b47debc963c86b399674084c1c8f2c96ecad",
                    ]:
                        self.assertIn(digest, checksums)

    def test_ensure_installs_missing_wasm_target(self):
        self.environment["TEST_INSTALLED_TARGETS"] = ""
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "rustup.log").read_text(),
                         "target list --installed\ntarget add wasm32-unknown-unknown\n")

    def test_with_rust_installs_missing_target_for_an_existing_toolchain(self):
        self.prepare_archives("x86_64")
        self.environment["TEST_INSTALLED_TARGETS"] = ""
        result = subprocess.run(["bash", str(ROOT / "scripts/install_wasm_build_tools.sh"),
                                 "--with-rust"], env=self.environment,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.root / "rustup.log").read_text(),
                         "target list --installed\ntarget add wasm32-unknown-unknown\n")
        self.assertNotIn("rustup-init", (self.root / "downloads.log").read_text())

    def test_missing_rust_toolchain_uses_the_cpu_specific_rustup_pin(self):
        (self.fixtures / "rustup-init").write_text('#!/bin/sh\nprintf "%s\\n" "bootstrap $*" >> "$TEST_RUSTUP_LOG"\n')
        wrapper = '''
command() {
    if [[ "$1" == -v && "$2" == cargo ]]; then return 1; fi
    builtin command "$@"
}
source "$1" --ensure
'''
        for arch, digest, toolchain in [
            ("x86_64", "a3339fb004c3d0bb9862ba0bce001861fe5cbde9c10d16591eb3f39ee6cd3e7f", "1.99.1"),
            ("aarch64", "c64b33db2c6b9385817ec0e49a84bcfe018ed6e328fe755c3c809580cc70ce7a", "stable"),
        ]:
            with self.subTest(arch=arch):
                self.environment["TEST_ARCH"] = arch
                if toolchain == "stable":
                    self.environment.pop("RUSTUP_TOOLCHAIN", None)
                else:
                    self.environment["RUSTUP_TOOLCHAIN"] = toolchain
                for log in ["downloads.log", "checksums.log", "rustup.log"]:
                    (self.root / log).unlink(missing_ok=True)
                result = subprocess.run(["bash", "-c", wrapper, "bootstrap-test",
                                         str(ROOT / "scripts/install_wasm_build_tools.sh")],
                                        env=self.environment, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"/1.28.1/{arch}-unknown-linux-gnu/rustup-init", (self.root / "downloads.log").read_text())
                self.assertIn(digest, (self.root / "checksums.log").read_text())
                self.assertIn(f"bootstrap -y --profile minimal --default-toolchain {toolchain}",
                              (self.root / "rustup.log").read_text())

    def test_ensure_installs_a_missing_pinned_toolchain_before_adding_target(self):
        self.environment["RUSTUP_TOOLCHAIN"] = "1.99.1"
        self.write_tool("rustup", '''#!/bin/sh
printf '%s\n' "$*" >> "$TEST_RUSTUP_LOG"
case "$*" in
    'run 1.99.1 rustc --version') exit 1 ;;
    'toolchain install 1.99.1 --profile minimal') exit 0 ;;
    'target list --installed') echo x86_64-unknown-linux-gnu ;;
    'target add wasm32-unknown-unknown') exit 0 ;;
    *) exit 2 ;;
esac
''')
        result = self.install()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "downloads.log").exists())
        self.assertEqual((self.root / "rustup.log").read_text().splitlines(), [
            "run 1.99.1 rustc --version", "toolchain install 1.99.1 --profile minimal",
            "target list --installed", "target add wasm32-unknown-unknown",
        ])

    def test_builder_discovers_tool_directory_with_minimal_path(self):
        (self.root / "scripts").mkdir()
        (self.root / "frontend-rs").mkdir()
        shutil.copyfile(ROOT / "scripts/build_wasm_frontend.sh", self.root / "scripts/build_wasm_frontend.sh")
        (self.root / "scripts/finalize_wasm_assets.py").write_text("import sys\nassert sys.argv[1] == '--locales-only'\n")
        self.write_tool("trunk", '#!/bin/sh\nprintf "%s\\n" "trunk $*" >> "$TEST_VERSION_LOG"\nmkdir -p dist\n')
        self.write_tool("cargo", '#!/bin/sh\nprintf "%s\\n" "cargo $*" >> "$TEST_VERSION_LOG"\n')
        self.environment["PATH"] = "/usr/bin:/bin"
        result = subprocess.run(["bash", str(self.root / "scripts/build_wasm_frontend.sh")],
                                env=self.environment, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        log = (self.root / "versions.log").read_text()
        self.assertIn("trunk build --release", log)
        self.assertIn("cargo run --quiet --release --locked", log)

    def test_stage_copies_external_assets_to_the_neutral_directory(self):
        (self.root / "scripts").mkdir()
        (self.root / "frontend-rs").mkdir()
        shutil.copyfile(ROOT / "scripts/build_wasm_frontend.sh", self.root / "scripts/build_wasm_frontend.sh")
        (self.root / "scripts/finalize_wasm_assets.py").write_text("pass\n")
        self.write_tool("trunk", '''#!/bin/sh
mkdir -p dist/locales
printf '<html>app</html>' > dist/index.html
printf 'wasm' > dist/app.wasm
printf 'locale' > dist/locales/en.json.gz
''')
        self.write_tool("cargo", "#!/bin/sh\nexit 0\n")
        primary = self.root / "web/dist"
        legacy = self.root / "backend/web/dist"
        primary.mkdir(parents=True)
        (primary / "obsolete.js").write_text("old")
        result = subprocess.run(["bash", str(self.root / "scripts/build_wasm_frontend.sh"), "--stage"],
                                env=self.environment, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((primary / "app.wasm").read_bytes(), b"wasm")
        self.assertEqual((primary / "locales/en.json.gz").read_text(), "locale")
        self.assertFalse((primary / "obsolete.js").exists())
        self.assertFalse(legacy.exists())
        # Selecting Trunk's output preserves it. Reject overlapping destinations before cleanup.
        source = self.root / "frontend-rs/dist"
        descendant = source / "existing-stage"
        descendant.mkdir()
        sentinel = descendant / "keep-me"
        sentinel.write_text("existing output")
        for destination, expected_status in ((source, 0), (source.parent, 2), (descendant, 2)):
            with self.subTest(destination=destination):
                result = subprocess.run(
                    ["bash", str(self.root / "scripts/build_wasm_frontend.sh"), "--stage"],
                    env={**self.environment, "FRONTEND_DIST_DIR": str(destination)},
                    capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, expected_status, result.stderr)
                self.assertEqual((source / "app.wasm").read_bytes(), b"wasm")
                self.assertEqual(sentinel.read_text(), "existing output")
                self.assertTrue((self.root / "scripts/build_wasm_frontend.sh").is_file())

    def test_gold_package_contains_external_assets_and_rejects_incomplete_ui(self):
        (self.root / "scripts").mkdir()
        shutil.copyfile(ROOT / "scripts/build_gold.sh", self.root / "scripts/build_gold.sh")
        for path in ("backend-rs/crates/af-cli", "config", "packages", "deploy", "web/dist/locales"):
            (self.root / path).mkdir(parents=True)
        for path, content in (("backend-rs/Cargo.toml", "[workspace]\n"),
                              ("backend-rs/Cargo.lock", "# lock\n"),
                              ("backend-rs/crates/af-cli/Cargo.toml", "[package]\n"),
                              ("deploy/release-manager.sh", "#!/bin/sh\n"),
                              (".version", "v4.0.0\n")):
            (self.root / path).write_text(content)
        self.write_tool("cargo", '''#!/usr/bin/python3
import os, pathlib, sys
args = sys.argv[1:]
target = args[args.index('--target') + 1]
binary = args[args.index('--bin') + 1]
directory = pathlib.Path(os.environ['CARGO_TARGET_DIR']) / target / 'release'
directory.mkdir(parents=True, exist_ok=True)
(directory / binary).write_bytes(('binary:' + binary).encode())
''')
        # Use the real checksum program, not the installer fixture's checksum stub.
        (self.bin / "sha256sum").unlink()
        env = {**self.environment, "BUILD_FRONTEND": "0", "RUN_TESTS": "0", "PACKAGE_RELEASE": "1",
               "CARGO_TARGET_DIR": str(self.root / "cargo-target"), "OUTPUT_DIR": str(self.root / "output")}
        for var in ("FRONTEND_DIST_DIR", "EMBED_DIST_DIR", "BACKEND_RS_DIR", "BACKEND_DIR", "CONFIG_DIR"):
            env.pop(var, None)
        index = self.root / "web/dist/index.html"
        wasm = self.root / "web/dist/app.wasm"
        for index_data, wasm_data in ((None, None), (b"<html>", b""), (b"", b"wasm")):
            index.unlink(missing_ok=True)
            wasm.unlink(missing_ok=True)
            if index_data is not None:
                index.write_bytes(index_data)
            if wasm_data is not None:
                wasm.write_bytes(wasm_data)
            result = subprocess.run(["bash", str(self.root / "scripts/build_gold.sh")], env=env,
                                    capture_output=True, text=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("full release requires non-empty index.html", result.stderr)
            self.assertFalse(list((self.root / "output").glob("*.tar.gz")))
        index.unlink(missing_ok=True)
        wasm.unlink(missing_ok=True)
        result = subprocess.run(["bash", str(self.root / "scripts/build_gold.sh")],
                                env={**env, "PACKAGE_RELEASE": "0", "OUTPUT_DIR": str(self.root / "binary-only")},
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.root / "binary-only/linux-amd64/aetherflow-api").is_file())
        self.assertFalse((self.root / "binary-only/linux-amd64/web/dist").exists())
        index.write_bytes(b"<html>app</html>")
        wasm.write_bytes(b"wasm-bytes")
        (self.root / "web/dist/locales/en.json.gz").write_bytes(b"compressed")
        result = subprocess.run(["bash", str(self.root / "scripts/build_gold.sh")], env=env,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        archive_path = self.root / "output/aetherflow-linux-amd64.tar.gz"
        with tarfile.open(archive_path) as archive:
            for name, expected in (("./web/dist/index.html", b"<html>app</html>"),
                                   ("./web/dist/app.wasm", b"wasm-bytes"),
                                   ("./web/dist/locales/en.json.gz", b"compressed"),
                                   ("./af", b"binary:af")):
                self.assertEqual(archive.extractfile(name).read(), expected)
        self.assertFalse((self.root / "backend/web/dist").exists())

    def test_trunk_hook_discovers_tailwind_in_tool_directory(self):
        config = (ROOT / "frontend-rs/Trunk.toml").read_text()
        hooks = re.split(r"(?m)^\s*\[\[hooks\]\]\s*$", config)[1:]
        hook, = [block for block in hooks if re.search(r'(?m)^stage\s*=\s*"pre_build"\s*$', block)]
        command = ast.literal_eval(re.search(r"(?m)^command\s*=\s*(.+)$", hook).group(1))
        arguments = ast.literal_eval(re.search(r"(?m)^command_arguments\s*=\s*(.+)$", hook).group(1))
        self.environment["PATH"] = "/usr/bin:/bin"
        result = subprocess.run([command, *arguments],
                                cwd=self.root, env=self.environment, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("tailwindcss -i styles/input.css", (self.root / "versions.log").read_text())

    def test_source_release_bootstraps_tools_before_staging(self):
        release = (ROOT / "deploy/release-manager.sh").read_text()
        source = release.split("build_from_source() {", 1)[1].split("\nsimulate_offline_artifact()", 1)[0]
        self.assertIn(f'export PATH="{TOOL_PATH}${{PATH}}"', source)
        bootstrap = source.index('scripts/install_wasm_build_tools.sh" --ensure')
        self.assertLess(bootstrap, source.index('scripts/build_wasm_frontend.sh" --stage'))
        self.assertIn('return 1', source[bootstrap:source.index('scripts/build_wasm_frontend.sh" --stage')])
        self.assertIn("--exclude='target/'", source)
        self.assertIn("--exclude='/packages/ui/'", source)
        self.assertGreater(source.index('"${RELEASE_DIR}/frontend-rs"'),
                           source.index('scripts/build_wasm_frontend.sh" --stage'))

    @unittest.skipUnless(shutil.which("rsync"), "requires rsync")
    def test_source_release_excludes_targets_and_retires_frontend_sources(self):
        repo = self.root / "repo"
        release = self.root / "release"
        for relative in (
            "scripts", "deploy/.pytest_cache", "frontend-rs/target", "backend-rs/target",
            "packages/ui/src", "packages/package", "docs", "tests", "e2e", "apps/website",
            "setup", "plugins", ".github",
        ):
            (repo / relative).mkdir(parents=True)
        (release).mkdir()
        for relative in (
            "frontend-rs/target/cache", "backend-rs/target/cache", "packages/ui/src/unused",
            "docs/guide.md", "tests/test_sample.py", "e2e/spec.ts", "apps/website/page.tsx",
            "setup/AetherFlow-Setup", "plugins/sample.json", ".github/ci.yml",
            "packages/README.md", "CHANGELOG.md",
        ):
            (repo / relative).write_text("host-generated")
        (repo / "rust-toolchain.toml").write_text((ROOT / "rust-toolchain.toml").read_text())
        (repo / "backend-rs/Cargo.lock").write_text("# lock\n")
        (repo / "packages/package/install").write_text("runtime package script")
        (repo / "deploy/.pytest_cache/unused").write_text("host-generated")
        for name in ("verify-provenance.py", "log-retention.py"):
            (repo / "deploy" / name).write_text("runtime helper")
            (repo / "deploy" / name).chmod(0o644)
        (repo / "scripts/install_wasm_build_tools.sh").write_text("exit 0\n")
        (repo / "scripts/build_wasm_frontend.sh").write_text('''set -eu
test ! -e "$RELEASE_DIR/frontend-rs/target"
test ! -e "$RELEASE_DIR/backend-rs/target"
test ! -e "$RELEASE_DIR/packages/ui"
mkdir -p "$RELEASE_DIR/frontend-rs/target" "$FRONTEND_DIST_DIR/locales"
printf index > "$FRONTEND_DIST_DIR/index.html"
printf wasm > "$FRONTEND_DIST_DIR/app.wasm"
printf sidecar > "$FRONTEND_DIST_DIR/locales/en.json.gz"
''')
        source = (ROOT / "deploy/release-manager.sh").read_text().split("build_from_source() {", 1)[1].split("\nsimulate_offline_artifact()", 1)[0]
        harness = '''set -euo pipefail
log_info() { :; }
log_error() { printf '%s\\n' "$*" >&2; }
log_fatal() { log_error "$*"; exit 1; }
git() { if [[ "$1" == rev-parse ]]; then printf abcdef0; fi; }
cargo() {
  mkdir -p "$RELEASE_DIR/backend-rs/target/release"
  printf api > "$RELEASE_DIR/backend-rs/target/release/aetherflow-api"
  printf cli > "$RELEASE_DIR/backend-rs/target/release/af"
}
''' + "build_from_source() {" + source + "\nbuild_from_source\n"
        env = {**self.environment, "REPO_DIR": str(repo), "RELEASE_DIR": str(release),
               "LOG_FILE": str(self.root / "release.log"), "GIT_BRANCH": "master",
               "GIT_REMOTE": "origin", "CHANNEL": "stable"}
        env.pop("CARGO_TARGET_DIR", None)
        result = subprocess.run(["bash", "-c", harness], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((release / "web/dist/locales/en.json.gz").read_text(), "sidecar")
        self.assertEqual((release / "packages/package/install").read_text(), "runtime package script")
        self.assertEqual((release / "bin/af").read_text(), "cli")
        self.assertFalse((release / "frontend-rs").exists())
        self.assertFalse((release / "backend-rs").exists())
        self.assertFalse((release / "scripts").exists())
        self.assertFalse((release / "rust-toolchain.toml").exists())
        self.assertFalse((release / "packages/README.md").exists())
        for excluded in ("docs", "tests", "e2e", "apps", "setup", "plugins", ".github", "CHANGELOG.md"):
            self.assertFalse((release / excluded).exists(), f"{excluded} must not remain in release slot")
        self.assertFalse((release / "deploy/.pytest_cache").exists())
        for name in ("verify-provenance.py", "log-retention.py"):
            self.assertEqual((release / "deploy" / name).stat().st_mode & 0o777, 0o755)
            self.assertEqual((repo / "deploy" / name).stat().st_mode & 0o777, 0o644)
        self.assertTrue((repo / "frontend-rs/target/cache").exists())

    def test_modern_source_build_always_ensures_tools_before_staging(self):
        (self.root / "scripts").mkdir()
        (self.root / "frontend-rs").mkdir()
        (self.root / "frontend-rs/Cargo.toml").touch()
        (self.root / "scripts/install_wasm_build_tools.sh").write_text(
            'printf "%s\\n" "ensure $*" >> "$TEST_VERSION_LOG"\n'
            'exit "$TEST_ENSURE_STATUS"\n'
        )
        (self.root / "scripts/build_wasm_frontend.sh").write_text(
            'printf "%s\\n" "stage $*" >> "$TEST_VERSION_LOG"\nexit 1\n'
        )
        self.environment["AF_INSTALL_ROOT"] = str(self.root)
        for status, expected in [
            ("0", ["ensure --ensure", "stage --stage"]),
            ("1", ["ensure --ensure"]),
        ]:
            with self.subTest(ensure_status=status):
                (self.root / "versions.log").unlink(missing_ok=True)
                self.environment["TEST_ENSURE_STATUS"] = status
                result = subprocess.run(
                    ["bash", "-c", 'source "$1"\n_build_modern_stack_from_source',
                     "modern-stack-test", str(ROOT / "setup/modules/modern_stack.sh")],
                    env=self.environment, capture_output=True, text=True, timeout=30,
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual((self.root / "versions.log").read_text().splitlines(), expected)

    def test_security_runs_frontend_workspace_unit_tests_from_backend_directory(self):
        security = (ROOT / ".github/workflows/security.yml").read_text()
        job = security.split("  rust-security:\n", 1)[1].split("\n  security-checks:\n", 1)[0]
        self.assertIn("working-directory: backend-rs", job)
        self.assertIn("cargo test --manifest-path ../frontend-rs/Cargo.toml --workspace --locked", job)

    def test_ensure_has_unprivileged_cache_fallback_and_pinned_rustup(self):
        installer = (ROOT / "scripts/install_wasm_build_tools.sh").read_text()
        self.assertIn('-d /usr/local/lib/aetherflow-wasm-tools/bin || -w /usr/local/lib', installer)
        self.assertIn('${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/aetherflow-wasm-tools', installer)
        self.assertIn('rustup_target=aarch64-unknown-linux-gnu', installer)
        self.assertIn('c64b33db2c6b9385817ec0e49a84bcfe018ed6e328fe755c3c809580cc70ce7a', installer)


if __name__ == "__main__":
    unittest.main()
