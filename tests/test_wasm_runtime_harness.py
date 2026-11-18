"""Non-server regression tests for the external WASM E2E harness."""

import base64
import hashlib
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / "scripts/run_embedded_e2e.sh"
WASM_HEADER = b"\x00asm\x01\x00\x00\x00"


class ExternalWasmHarnessTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="af-harness-regression-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root / "release bin" / "aetherflow-api"
        self.binary.parent.mkdir()
        self.marker = self.root / "api-environment"
        # This executable records its environment and exits; it never starts a server.
        self.binary.write_text(f"#!/bin/sh\nenv > {shlex.quote(str(self.marker))}\nexit 1\n")
        self.binary.chmod(0o755)
        self.default_dist = self.binary.parent / "web/dist"
        self.make_dist(self.default_dist)
        self.env = os.environ.copy()
        for variable in ("STATIC_DIR", "E2E_BIND_ADDR", "E2E_PORT", "AETHERFLOW_BIN"):
            self.env.pop(variable, None)
        self.env.update({"START_RUNNER": "0", "TMPDIR": str(self.root)})

    @staticmethod
    def make_dist(directory):
        directory.mkdir(parents=True)
        (directory / "index.html").write_text(
            '<!doctype html><html><head>'
            '<meta name="af-worker-url" content="/worker_loader-0123456789abcdef.js">'
            '<script src="/bootstrap-0123456789abcdef.js"></script>'
            '<link href="/app-0123456789abcdef.wasm">'
            '</head></html>'
        )
        (directory / "bootstrap-0123456789abcdef.js").write_text("export {};\n")
        (directory / "app-0123456789abcdef.wasm").write_bytes(WASM_HEADER)
        (directory / "worker_loader-0123456789abcdef.js").write_text(
            "import init from './worker-0123456789abcdef.js'; init();\n"
        )
        (directory / "worker-0123456789abcdef.js").write_text(
            "const wasm = new URL('worker_bg-0123456789abcdef.wasm', import.meta.url);\n"
        )
        (directory / "worker_bg-0123456789abcdef.wasm").write_bytes(WASM_HEADER)

    def run_harness(self, *arguments, env=None):
        return subprocess.run(
            ["bash", str(HARNESS), "--binary", str(self.binary), *arguments],
            cwd=self.root, env=env or self.env, capture_output=True, text=True, timeout=20,
        )

    def test_default_playwright_selection_covers_every_live_suite_and_preserves_overrides(self):
        assignment = next(line.strip() for line in HARNESS.read_text().splitlines()
                          if line.strip().startswith('PLAYWRIGHT_SPECS="'))
        env = {key: value for key, value in self.env.items() if key != "E2E_PLAYWRIGHT_SPECS"}
        command = assignment + '\nprintf "%s\\n" "$PLAYWRIGHT_SPECS"'
        result = subprocess.run(["bash", "-eu", "-c", command], env=env,
                                capture_output=True, text=True, check=True)
        selector = result.stdout.strip()
        specs = {p.name for p in (ROOT / "frontend/tests/e2e").glob("*.spec.ts")}
        selected = {name for name in specs if re.search(selector, f"tests/e2e/{name}")}
        self.assertEqual(selected, {name for name in specs if name.endswith(".live.spec.ts")})
        self.assertTrue({"embedded.live.spec.ts", "wasm.worker.live.spec.ts", "wasm.upload.live.spec.ts"} <= selected)
        self.assertRegex("tests/e2e/future.live.spec.ts", selector)
        override = "wasm.session.spec.ts --project=webkit --retries=0"
        result = subprocess.run(["bash", "-eu", "-c", command],
                                env={**env, "E2E_PLAYWRIGHT_SPECS": override},
                                capture_output=True, text=True, check=True)
        self.assertEqual(result.stdout.strip(), override)

    def test_cli_wins_over_inherited_static_dir_and_resolves_relative_paths(self):
        explicit = self.root / "custom assets"
        inherited = self.root / "inherited assets"
        self.make_dist(explicit)
        self.make_dist(inherited)
        for value in (str(inherited), "", "missing"):
            with self.subTest(inherited=value):
                env = {**self.env, "STATIC_DIR": value}
                result = self.run_harness("--static-dir", "custom assets", "--verify-assets-only", env=env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"validated: {explicit.resolve()}", result.stdout)
                self.assertFalse(self.marker.exists())

    def test_inherited_path_and_empty_override_are_deterministic(self):
        inherited = self.root / "inherited assets"
        self.make_dist(inherited)
        env = {**self.env, "STATIC_DIR": "inherited assets"}
        result = self.run_harness("--verify-assets-only", env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"validated: {inherited.resolve()}", result.stdout)
        result = self.run_harness("--verify-assets-only", env={**self.env, "STATIC_DIR": ""})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("STATIC_DIR is set but empty", result.stderr)
        self.assertFalse(self.marker.exists())

        result = self.run_harness("--verify-assets-only", env=self.env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"validated: {self.default_dist.resolve()}", result.stdout)

    def test_default_follows_the_resolved_executable_not_symlink_location(self):
        symlink = self.root / "api-link"
        symlink.symlink_to(self.binary)
        result = subprocess.run(
            ["bash", str(HARNESS), "--binary", str(symlink), "--verify-assets-only"],
            cwd=self.root, env=self.env, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"validated: {self.default_dist.resolve()}", result.stdout)

        result = subprocess.run(
            ["bash", str(HARNESS), "--binary", "release bin/aetherflow-api", "--verify-assets-only"],
            cwd=self.root, env=self.env, capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"validated: {self.default_dist.resolve()}", result.stdout)

    def test_invalid_external_bundles_fail_before_launch(self):
        worker_wasm = self.default_dist / "worker_bg-0123456789abcdef.wasm"
        worker_wasm.unlink()
        result = self.run_harness("--verify-assets-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid external WASM frontend", result.stderr)
        self.assertFalse(self.marker.exists())

        worker_wasm.write_bytes(b"not wasm")
        result = self.run_harness("--verify-assets-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid worker WASM header", result.stderr)
        self.assertFalse(self.marker.exists())

        worker_wasm.unlink()
        external = self.root / "outside.wasm"
        external.write_bytes(WASM_HEADER)
        worker_wasm.symlink_to(external)
        result = self.run_harness("--verify-assets-only")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("symbolic link below the asset directory", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_application_metadata_is_bound_to_the_bootstrap_and_valid_wasm(self):
        app = "/app-0123456789abcdef.wasm"
        bootstrap = "bootstrap-0123456789abcdef.js"
        module = "/app-0123456789abcdef.js"
        link = f'<link href="{app}">'
        metadata = f'<meta name="af-app-wasm-url" content="{app}">'
        modulepreload = f'<link rel="modulepreload" href="{module}">'

        def write_bootstrap(directory, reference=app):
            data = (directory / reference.lstrip("/")).read_bytes()
            digest = base64.b64encode(hashlib.sha384(data).digest()).decode("ascii")
            (directory / bootstrap).write_text(
                'const [wasmResponse, { default: init }] = await Promise.all([\n'
                f'  fetch("{reference}", {{ integrity: "sha384-{digest}" }}),\n'
                f'  import("{module}")\n'
                ']);\nconst wasm = await init({ module_or_path: wasmResponse });\n'
            )

        def prepare(directory):
            self.make_dist(directory)
            index = directory / "index.html"
            index.write_text(index.read_text().replace(link, metadata + modulepreload))
            (directory / module.lstrip("/")).write_text('export default function init() {}\n')
            write_bootstrap(directory)

        valid = self.root / "valid-metadata"
        prepare(valid)
        result = self.run_harness("--static-dir", str(valid), "--verify-assets-only")
        self.assertEqual(result.returncode, 0, result.stderr)

        cases = {
            "missing": "Invalid external WASM frontend",
            "malformed": "invalid application WASM header",
            "unrelated": "Invalid external WASM frontend",
            "bootstrap-mismatch": "bootstrap does not initialize",
            "stray-fetch": "bootstrap does not initialize",
            "bad-integrity": "bootstrap does not initialize",
            "missing-module": "Invalid external WASM frontend",
            "missing-modulepreload": "application module is not referenced",
            "duplicate": "exactly one valid application WASM metadata",
            "empty": "exactly one valid application WASM metadata",
            "worker": "application and worker must reference separate WASM modules",
        }
        for case, error in cases.items():
            with self.subTest(case=case):
                directory = self.root / case
                prepare(directory)
                index = directory / "index.html"
                app_file = directory / app.lstrip("/")
                if case == "missing":
                    app_file.unlink()
                elif case == "malformed":
                    app_file.write_bytes(b"not a WASM module")
                elif case == "unrelated":
                    app_file.unlink()
                    (directory / "unrelated.wasm").write_bytes(WASM_HEADER)
                elif case == "bootstrap-mismatch":
                    (directory / bootstrap).write_text('fetch("/unrelated.wasm", {});')
                    (directory / "unrelated.wasm").write_bytes(WASM_HEADER)
                elif case == "stray-fetch":
                    text = (directory / bootstrap).read_text()
                    (directory / bootstrap).write_text(text.replace('module_or_path: wasmResponse',
                                                                   'module_or_path: "/missing.wasm"'))
                elif case == "bad-integrity":
                    app_file.write_bytes(WASM_HEADER + b"different bytes")
                elif case == "missing-module":
                    (directory / module.lstrip("/")).unlink()
                elif case == "missing-modulepreload":
                    index.write_text(index.read_text().replace(modulepreload, ""))
                elif case == "duplicate":
                    index.write_text(index.read_text().replace(metadata, metadata * 2))
                elif case == "empty":
                    index.write_text(index.read_text().replace(metadata, '<meta name="af-app-wasm-url" content="">'))
                else:
                    worker = "/worker_bg-0123456789abcdef.wasm"
                    index.write_text(index.read_text().replace(app, worker))
                    write_bootstrap(directory, worker)
                result = self.run_harness("--static-dir", str(directory), "--verify-assets-only")
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(error, result.stderr)
                self.assertFalse(self.marker.exists())

    def test_legacy_link_rejects_missing_or_malformed_app_even_if_other_wasm_exists(self):
        app = self.default_dist / "app-0123456789abcdef.wasm"
        for content in (None, b"not wasm"):
            with self.subTest(content=content):
                if content is None:
                    app.unlink(missing_ok=True)
                else:
                    app.write_bytes(content)
                result = self.run_harness("--verify-assets-only")
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn("Invalid external WASM frontend", result.stderr)
                self.assertFalse(self.marker.exists())

    def test_resolved_root_is_allowed_but_linked_or_oversized_assets_are_rejected(self):
        alias = self.root / "asset root alias"
        alias.symlink_to(self.default_dist, target_is_directory=True)
        result = self.run_harness("--static-dir", str(alias), "--verify-assets-only")
        self.assertEqual(result.returncode, 0, result.stderr)

        app = self.default_dist / "app-0123456789abcdef.wasm"
        real = app.with_name("real.wasm")
        app.rename(real)
        def make_oversized_asset():
            with app.open("wb") as handle:
                handle.truncate(32 * 1024 * 1024 + 1)

        for make_asset, error in (
            (lambda: app.symlink_to(real.name), "symbolic link"),
            (lambda: os.link(real, app), "regular file with one link"),
            (make_oversized_asset, "exceeds 32 MiB"),
        ):
            with self.subTest(error=error):
                make_asset()
                result = self.run_harness("--verify-assets-only")
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(error, result.stderr)
                self.assertFalse(self.marker.exists())
                app.unlink()

    def test_binary_only_mode_remains_independent_of_frontend_assets(self):
        result = self.run_harness("--verify-binary-only", env={**self.env, "STATIC_DIR": "missing"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.marker.exists())

    def test_runner_and_unsafe_bind_are_rejected(self):
        for arguments, environment in (
            (("--with-runner", "--verify-assets-only"), self.env),
            (("--verify-assets-only",), {**self.env, "START_RUNNER": "1"}),
            (("--bind-addr", "0.0.0.0"), self.env),
            (("--port", "0"), self.env),
            (("--port", "65536"), self.env),
        ):
            with self.subTest(arguments=arguments, start_runner=environment.get("START_RUNNER")):
                result = self.run_harness(*arguments, env=environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.marker.exists())

    def test_occupied_port_fails_before_launch(self):
        with socket.socket() as held:
            held.bind(("127.0.0.1", 0))
            port = held.getsockname()[1]
            result = self.run_harness("--port", str(port))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Refusing to reuse occupied E2E listener", result.stderr)
        self.assertFalse(self.marker.exists())

    def test_api_receives_only_selected_assets_and_isolated_environment(self):
        fake_tools = self.root / "fake-tools"
        fake_tools.mkdir()
        fake_curl = fake_tools / "curl"
        fake_curl.write_text("#!/bin/sh\nexit 1\n")
        fake_curl.chmod(0o755)
        env = {
            **self.env,
            "PATH": f"{fake_tools}:/usr/bin:/bin",
            "STATIC_DIR": str(self.default_dist),
            "OPENAI_API_KEY": "host-secret-must-not-leak",
            "GOOGLE_CLIENT_SECRET": "host-secret-must-not-leak",
            "AETHERFLOW_INTERNAL_API_URL": "http://host-service.invalid",
        }
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        result = self.run_harness("--port", str(port), env=env)
        self.assertNotEqual(result.returncode, 0)  # the non-server stub deliberately exits
        self.assertTrue(self.marker.exists(), result.stderr)
        api_env = dict(line.split("=", 1) for line in self.marker.read_text().splitlines())
        self.assertEqual(api_env["STATIC_DIR"], str(self.default_dist.resolve()))
        self.assertEqual(api_env["PRIVILEGED_RUNNER_ENABLED"], "false")
        self.assertEqual(api_env["AETHERFLOW_SKIP_ENV_FILES"], "1")
        self.assertTrue(Path(api_env["DB_PATH"]).is_relative_to(self.root))
        for key in ("OPENAI_API_KEY", "GOOGLE_CLIENT_SECRET", "AETHERFLOW_INTERNAL_API_URL"):
            self.assertNotIn(key, api_env)


if __name__ == "__main__":
    unittest.main()
