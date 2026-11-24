#!/usr/bin/env python3
"""
Unit and regression tests for OPUS-004 and OPUS-009:
- OPUS-004: modern_stack env defaults (loopback bind 127.0.0.1, COOKIE_SECURE=true with TLS/domain,
  no public direct :8080 origins unless explicit opt-in, preservation of existing operator env choices,
  alternate AETHERFLOW_DB_PATH, quote semantics, partial env files under set -euo pipefail, and idempotent re-runs).
- OPUS-009: packaged systemd unit portability (no personal home/group names, generic hardening,
  while preserving optional -/home/hdd in media client unit templates).
"""

import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
MODERN_STACK_SH = REPO_ROOT / "setup" / "modules" / "modern_stack.sh"
PACKAGED_API_UNIT = REPO_ROOT / "deploy" / "systemd" / "aetherflow-api.service"
PACKAGED_RUNNER_UNIT = REPO_ROOT / "deploy" / "systemd" / "aetherflow-runner.service"
RETIRED_TEMPLATE_API_UNIT = REPO_ROOT / "setup" / "templates" / "sysd" / "aetherflow-api.template"
RETIRED_TEMPLATE_RUNNER_UNIT = REPO_ROOT / "setup" / "templates" / "sysd" / "aetherflow-runner.template"
RETIRED_QBIT_UNIT = REPO_ROOT / "setup" / "templates" / "sysd" / "qbittorrent.template"
RETIRED_RTORRENT_UNIT = REPO_ROOT / "setup" / "templates" / "sysd" / "rtorrent.template"


class ModernStackSourceBuildTests(unittest.TestCase):
    def test_source_build_has_no_legacy_next_or_npm_install(self):
        content = MODERN_STACK_SH.read_text(encoding="utf-8")
        self.assertNotIn("NEXT_STATIC_EXPORT", content)
        self.assertNotIn("npm install", content)
        self.assertIn('bash "${af_root}/scripts/build_wasm_frontend.sh" --stage || return 1', content)

    def test_source_build_requires_wasm_manifest_even_with_legacy_frontend(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "frontend").mkdir()
            result = subprocess.run(
                ["bash", "-c", 'source "$1"; AF_INSTALL_ROOT="$2"; _build_modern_stack_from_source',
                 "bash", str(MODERN_STACK_SH), str(root)],
                capture_output=True, text=True,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Missing Rust WASM frontend manifest", result.stderr)
            self.assertFalse((root / "releases").exists())

    def test_source_build_requires_nonempty_index_and_wasm(self):
        for index, wasm in ((b"", b"wasm"), (b"<html>app</html>", b"")):
            with self.subTest(index=index, wasm=wasm), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "frontend-rs").mkdir()
                (root / "frontend-rs/Cargo.toml").touch()
                (root / "scripts").mkdir()
                (root / "scripts/install_wasm_build_tools.sh").write_text(
                    '#!/usr/bin/env bash\nexit 0\n', encoding="utf-8"
                )
                (root / "scripts/build_wasm_frontend.sh").write_text(
                    '#!/usr/bin/env bash\nprintf "%s" "$1" > "${AF_INSTALL_ROOT}/invoked"\n',
                    encoding="utf-8",
                )
                (root / "web/dist").mkdir(parents=True)
                (root / "web/dist/index.html").write_bytes(index)
                (root / "web/dist/app.wasm").write_bytes(wasm)
                result = subprocess.run(
                    ["bash", "-c", 'source "$1"; export AF_INSTALL_ROOT="$2"; _build_modern_stack_from_source',
                     "bash", str(MODERN_STACK_SH), str(root)],
                    env={**os.environ, "AF_OFFLINE": "1"}, capture_output=True, text=True,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual((root / "invoked").read_text(), "--stage")
                self.assertIn("frontend staging missing non-empty index.html or .wasm", result.stderr)
                self.assertFalse((root / "releases").exists())

    def test_source_build_copies_external_ui_into_current_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for path in ("scripts", "frontend-rs", "backend-rs/crates/af-librespeed", "config", "packages", "tools/bin"):
                (root / path).mkdir(parents=True)
            (root / "frontend-rs/Cargo.toml").write_text("[workspace]\n")
            (root / "backend-rs/Cargo.lock").write_text("# lock\n")
            (root / "backend-rs/crates/af-librespeed/Cargo.toml").touch()
            (root / "config/packages.json").write_text("[]\n")
            (root / "packages/common.sh").write_text("# runtime helper\n")
            (root / "packages/README.md").write_text("# developer docs\n")
            for pdir in (
                "plugins/telemetry-inspector/backend/hooks",
                "plugins/telemetry-inspector/frontend/dist",
                "plugins/sdk-template-rust/backend",
            ):
                (root / pdir).mkdir(parents=True, exist_ok=True)
            (root / "plugins/README.md").write_text("# plugin docs\n")
            (root / "plugins/sdk-template-rust/backend/Cargo.toml").write_text("[package]\n")
            (root / "plugins/telemetry-inspector/plugin.manifest.json").write_text('{"id":"telemetry-inspector"}\n')
            (root / "plugins/telemetry-inspector/backend/hooks/start.sh").write_text("#!/usr/bin/env bash\nexit 0\n")
            (root / "plugins/telemetry-inspector/backend/hooks/start.sh").chmod(0o644)
            (root / "plugins/telemetry-inspector/backend/runtime.py").write_text("print('ok')\n")
            (root / "plugins/telemetry-inspector/frontend/dist/index.html").write_text("<html>plugin</html>\n")
            (root / "scripts/install_wasm_build_tools.sh").write_text("exit 0\n")
            (root / "scripts/build_wasm_frontend.sh").write_text(
                'mkdir -p "$FRONTEND_DIST_DIR/locale"\n'
                'printf "<html>test</html>" > "$FRONTEND_DIST_DIR/index.html"\n'
                'printf wasm > "$FRONTEND_DIST_DIR/app.wasm"\n'
                'printf locale > "$FRONTEND_DIST_DIR/locale/en.json.gz"\n'
            )
            cargo = root / "tools/bin/cargo"
            cargo.write_text('#!/bin/sh\nmkdir -p "$CARGO_TARGET_DIR/release"\n'
                             'printf api > "$CARGO_TARGET_DIR/release/aetherflow-api"\n'
                             'printf cli > "$CARGO_TARGET_DIR/release/af"\n'
                             'case " $* " in\n'
                             '  *" --bin speedtest-backend "*) printf speedtest > "$CARGO_TARGET_DIR/release/speedtest-backend";;\n'
                             'esac\n')
            cargo.chmod(0o755)
            env = {**os.environ, "AF_INSTALL_ROOT": str(root), "WASM_TOOL_DIR": str(root / "tools"),
                   "CARGO_TARGET_DIR": "custom-target", "AF_OFFLINE": "1", "AF_SKIP_SYSTEMCTL": "1"}
            result = subprocess.run(["bash", "-c", 'source "$1"; _build_modern_stack_from_source',
                                     "bash", str(MODERN_STACK_SH)], env=env,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "current/web/dist/index.html").read_text(), "<html>test</html>")
            self.assertEqual((root / "current/web/dist/app.wasm").read_text(), "wasm")
            self.assertEqual((root / "current/web/dist/locale/en.json.gz").read_text(), "locale")
            self.assertEqual((root / "current/bin/af").read_text(), "cli")
            self.assertFalse((root / "current/af").exists())
            self.assertEqual(os.readlink(root / "backend/af"), str(root / "current/bin/af"))
            self.assertEqual((root / "current/config/packages.json").read_text(), "[]\n")
            self.assertEqual((root / "current/packages/common.sh").read_text(), "# runtime helper\n")
            self.assertFalse((root / "current/packages/README.md").exists())
            self.assertTrue((root / "packages/README.md").exists())
            self.assertEqual((root / "current/plugins/telemetry-inspector/plugin.manifest.json").read_text(), '{"id":"telemetry-inspector"}\n')
            self.assertEqual((root / "current/plugins/telemetry-inspector/backend/hooks/start.sh").stat().st_mode & 0o777, 0o755)
            self.assertFalse((root / "current/plugins/sdk-template-rust").exists())
            self.assertFalse((root / "current/plugins/README.md").exists())
            companion = root / "current/bin/speedtest-backend"
            self.assertEqual(companion.read_text(), "speedtest")
            self.assertEqual(companion.stat().st_mode & 0o777, 0o755)
            self.assertFalse((root / "current/speedtest-backend").exists())
            self.assertFalse((root / "backend/web/dist").exists())

    def test_prebuilt_staging_rejects_missing_ui_and_keeps_valid_assets(self):
        for index, wasm, valid in ((b"", b"wasm", False), (b"<html>", b"", False),
                                   (b"<html>", b"wasm", True)):
            with self.subTest(index=index, wasm=wasm), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive = root / "release.tar.gz"
                with tarfile.open(archive, "w:gz") as tar:
                    for name, data in (
                        ("aetherflow-api", b"api"),
                        ("bin/af", b"cli"),
                        ("bin/speedtest-backend", b"speedtest"),
                        ("plugins/telemetry-inspector/plugin.manifest.json", b'{"id":"telemetry-inspector"}\n'),
                        ("plugins/telemetry-inspector/backend/hooks/start.sh", b"#!/usr/bin/env bash\nexit 0\n"),
                        (".version", b"v4.0.0\n"),
                        ("web/dist/index.html", index),
                        ("web/dist/app.wasm", wasm),
                    ):
                        info = tarfile.TarInfo(name)
                        info.size = len(data)
                        info.mode = 0o755 if name == "aetherflow-api" else 0o644
                        tar.addfile(info, io.BytesIO(data))
                digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                env = {**os.environ, "AF_INSTALL_ROOT": str(root / "install"),
                       "AETHERFLOW_SKIP_PROVENANCE_VERIFY": "1"}
                result = subprocess.run(["bash", "-c", 'source "$1"; _stage_prebuilt_release_archive "$2" "" "$3" v4.0.0',
                                         "bash", str(MODERN_STACK_SH), str(archive), digest],
                                        env=env, capture_output=True, text=True)
                self.assertEqual(result.returncode == 0, valid, result.stderr)
                current = root / "install/current"
                if valid:
                    self.assertEqual((current / "web/dist/app.wasm").read_bytes(), wasm)
                    self.assertEqual((current / "web/dist/index.html").read_bytes(), index)
                    self.assertFalse((current / "af").exists())
                    self.assertFalse((current / "speedtest-backend").exists())
                    for relpath, expected_bytes in (
                        ("bin/af", b"cli"),
                        ("bin/speedtest-backend", b"speedtest"),
                        ("plugins/telemetry-inspector/backend/hooks/start.sh", b"#!/usr/bin/env bash\nexit 0\n"),
                    ):
                        companion = current / relpath
                        self.assertEqual(companion.read_bytes(), expected_bytes)
                        self.assertEqual(companion.stat().st_mode & 0o777, 0o755)
                    self.assertEqual(os.readlink(root / "install/backend/af"), str(current / "bin/af"))
                else:
                    self.assertIn("missing external frontend assets", result.stderr)
                    self.assertFalse(current.exists())

    def test_prebuilt_staging_preserves_legacy_root_only_archive_compatibility(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "legacy-release.tar.gz"
            with tarfile.open(archive, "w:gz") as tar:
                for name, data in (
                    ("aetherflow-api", b"api"),
                    ("af", b"legacy-cli"),
                    ("speedtest-backend", b"legacy-speedtest"),
                    (".version", b"v4.0.0\n"),
                    ("web/dist/index.html", b"<html>legacy</html>"),
                    ("web/dist/app.wasm", b"wasm"),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(data)
                    info.mode = 0o755 if name == "aetherflow-api" else 0o644
                    tar.addfile(info, io.BytesIO(data))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            env = {**os.environ, "AF_INSTALL_ROOT": str(root / "install"),
                   "AETHERFLOW_SKIP_PROVENANCE_VERIFY": "1"}
            result = subprocess.run(["bash", "-c", 'source "$1"; _stage_prebuilt_release_archive "$2" "" "$3" v4.0.0',
                                     "bash", str(MODERN_STACK_SH), str(archive), digest],
                                    env=env, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            current = root / "install/current"
            self.assertEqual((current / "af").read_bytes(), b"legacy-cli")
            self.assertEqual((current / "af").stat().st_mode & 0o777, 0o755)
            self.assertEqual((current / "speedtest-backend").read_bytes(), b"legacy-speedtest")
            self.assertEqual((current / "speedtest-backend").stat().st_mode & 0o777, 0o755)
            self.assertFalse((current / "bin/af").exists())
            self.assertFalse((current / "bin/speedtest-backend").exists())
            self.assertEqual(os.readlink(root / "install/backend/af"), str(current / "af"))


class ModernStackEnvGenerationTests(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="af_test_env_")
        self.install_root = Path(self.test_dir) / "opt_aetherflow"
        self.env_dir = Path(self.test_dir) / "etc_aetherflow"
        self.data_dir = Path(self.test_dir) / "var_lib_aetherflow"
        self.sysd_dst = Path(self.test_dir) / "etc_systemd"
        self.run_dir = Path(self.test_dir) / "run_aetherflow"
        self.env_dir.mkdir(parents=True, exist_ok=True)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.sysd_dst.mkdir(parents=True, exist_ok=True)
        self.run_dir.mkdir(parents=True, exist_ok=True)

        # Stage canonical deploy/systemd units and remaining templates into isolated install_root so REPO_ROOT is never mutated
        deploy_sysd_dst = self.install_root / "deploy" / "systemd"
        deploy_sysd_dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(REPO_ROOT / "deploy" / "systemd", deploy_sysd_dst,
                        copy_function=shutil.copyfile)
        templates_dst = self.install_root / "setup" / "templates" / "sysd"
        templates_dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(REPO_ROOT / "setup" / "templates" / "sysd", templates_dst,
                        copy_function=shutil.copyfile)
        templates_dst.chmod(templates_dst.stat().st_mode | 0o700)

    def test_duplicate_assignments_preserve_last_effective_keys_across_reruns(self):
        existing = (
            'AES_MASTER_KEY=earlier-aes-value\n'
            'JWT_SECRET=earlier-jwt-value\n'
            'AES_MASTER_KEY="0123456789abcdef0123456789abcdef"\n'
            "JWT_SECRET='later-synthetic-jwt-value-at-least-32-characters'\n"
            'BIND_ADDR=0.0.0.0\nBIND_ADDR="127.0.0.1"\n'
        )
        first = self._run_env_generation(existing_env_content=existing)
        second = self._run_env_generation()
        for _, output in (first, second):
            self.assertIn('AES_MASTER_KEY="0123456789abcdef0123456789abcdef"', output)
            self.assertIn("JWT_SECRET='later-synthetic-jwt-value-at-least-32-characters'", output)
            self.assertIn('BIND_ADDR="127.0.0.1"', output)
            self.assertNotIn('earlier-', output)

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def _run_env_generation(self, env_vars=None, existing_env_content=None, mock_load_config=None):
        if existing_env_content is not None:
            (self.env_dir / "aetherflow.env").write_text(existing_env_content, encoding="utf-8")

        mock_helpers = """
_af_modern_from_source_enabled() { return 1; }
_pull_prebuilt_v4_release() { return 0; }
_af_resolve_release_channel() { echo "nightly"; }
_safe_overlay_config() { cp "$1" "$2"; }
"""
        if mock_load_config:
            mock_helpers += f"\n{mock_load_config}\n"

        # Source modern_stack.sh FIRST, then define mock_helpers so _pull_prebuilt_v4_release
        # is never invoked against live GitHub releases or the checkout root.
        script = f"""#!/usr/bin/env bash
set -euo pipefail
AF_INSTALL_ROOT="{self.install_root}"
AF_ENV_DIR="{self.env_dir}"
AF_DATA_DIR="{self.data_dir}"
AF_SYSTEMD_DIR="{self.sysd_dst}"
AF_RUN_DIR="{self.run_dir}"
AF_LOG_DIR="{self.test_dir}/log_aetherflow"
AF_SKIP_SYSTEMCTL=1
AF_OFFLINE=1

source "{MODERN_STACK_SH}"
{mock_helpers}

_build_modern_stack
"""
        runner_path = Path(self.test_dir) / "run_test.sh"
        runner_path.write_text(script, encoding="utf-8")
        runner_path.chmod(0o755)

        run_env = os.environ.copy()
        for k in list(run_env.keys()):
            if k.startswith(("AF_", "AETHERFLOW_")) or k in {
                "BIND_ADDR",
                "PORT",
                "COOKIE_SECURE",
                "DB_PATH",
                "SSL_ENABLED",
            }:
                run_env.pop(k, None)
        run_env["AF_SKIP_SYSTEMCTL"] = "1"
        run_env["AF_OFFLINE"] = "1"
        if env_vars:
            run_env.update(env_vars)

        res = subprocess.run(
            ["bash", str(runner_path)],
            capture_output=True,
            text=True,
            env=run_env,
        )
        self.assertEqual(res.returncode, 0, f"Script failed:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")

        # Verify checkout root was not polluted by release/current staging
        self.assertFalse((REPO_ROOT / "current").exists(), "Checkout root must not contain 'current' symlink")
        self.assertFalse((REPO_ROOT / "releases").exists(), "Checkout root must not contain 'releases' directory")

        env_file = self.env_dir / "aetherflow.env"
        self.assertTrue(env_file.exists(), "aetherflow.env was not generated")
        parsed = {}
        with open(env_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    parsed[k.strip()] = v.strip()
        return parsed, env_file.read_text(encoding="utf-8")

    def test_fresh_install_keeps_proxy_port_when_parent_shell_sets_port(self):
        parsed, _ = self._run_env_generation(env_vars={"PORT": "45678"})
        self.assertEqual(parsed.get("PORT"), "8080")

    def test_default_ingress_binds_loopback_and_sets_secure_cookie_with_domain(self):
        """Default install with a configured domain must bind 127.0.0.1, COOKIE_SECURE=true, and no direct :8080 domain origins."""
        parsed, _ = self._run_env_generation(
            env_vars={"AETHERFLOW_BASE_DOMAIN": "panel.example.com"}
        )
        self.assertEqual(parsed.get("BIND_ADDR"), "127.0.0.1")
        self.assertEqual(parsed.get("COOKIE_SECURE"), "true")
        self.assertEqual(parsed.get("PORT"), "8080")
        self.assertEqual(parsed.get("AETHERFLOW_BASE_DOMAIN"), "panel.example.com")

        # Must not contain direct public 8080 origins for the domain
        cors = parsed.get("ALLOWED_CORS_ORIGIN", "")
        hosts = parsed.get("ALLOWED_HOSTS", "")
        self.assertIn("https://panel.example.com", cors)
        self.assertNotIn("panel.example.com:8080", cors)
        self.assertNotIn("panel.example.com:8080", hosts)
        self.assertIn("panel.example.com", hosts)

        # Loopback entries are present for reverse proxy and health checks
        self.assertIn("127.0.0.1", hosts)
        self.assertIn("localhost", hosts)

    def test_default_ingress_without_domain_defaults_to_loopback_and_insecure_cookie(self):
        """Local HTTP test setup without domain/TLS binds loopback and keeps COOKIE_SECURE=false."""
        parsed, _ = self._run_env_generation(
            env_vars={"AETHERFLOW_BASE_DOMAIN": ""}
        )
        self.assertEqual(parsed.get("BIND_ADDR"), "127.0.0.1")
        self.assertEqual(parsed.get("COOKIE_SECURE"), "false")
        cors = parsed.get("ALLOWED_CORS_ORIGIN", "")
        self.assertNotIn(":8080", cors.replace("http://localhost:8080", "").replace("http://127.0.0.1:8080", ""))

    def test_explicit_direct_8080_opt_in_binds_all_and_adds_8080_origins(self):
        """When operator explicitly requests direct port 8080 access, BIND_ADDR=0.0.0.0 and :8080 origins are added."""
        parsed, _ = self._run_env_generation(
            env_vars={
                "AETHERFLOW_BASE_DOMAIN": "direct.example.com",
                "AF_ALLOW_DIRECT_8080": "1",
            }
        )
        self.assertEqual(parsed.get("BIND_ADDR"), "0.0.0.0")
        self.assertEqual(parsed.get("COOKIE_SECURE"), "true")
        cors = parsed.get("ALLOWED_CORS_ORIGIN", "")
        hosts = parsed.get("ALLOWED_HOSTS", "")
        self.assertIn("http://direct.example.com:8080", cors)
        self.assertIn("direct.example.com:8080", hosts)

    def test_existing_operator_env_choices_and_secrets_are_preserved(self):
        """Existing operator choices (keys, custom BIND_ADDR, PORT, COOKIE_SECURE, alternate AETHERFLOW_DB_PATH, and custom vars) must be preserved."""
        existing_content = """# Existing AetherFlow Config
AES_MASTER_KEY=existing-secret-aes-key-exactly-32!
JWT_SECRET=existing-jwt-secret-64-bytes-string-for-operator-session-continuity!!
PORT=9090
BIND_ADDR=10.0.0.42
ALLOWED_HOSTS=custom.domain.local,10.0.0.42
ALLOWED_CORS_ORIGIN=https://custom.domain.local
AETHERFLOW_BASE_DOMAIN=custom.domain.local
DB_PATH=/custom/data/legacy.sqlite
AETHERFLOW_DB_PATH=/mnt/nvme/aetherflow-v4.sqlite
AETHERFLOW_RUNNER_SOCK=/custom/run/runner.sock
PRIVILEGED_RUNNER_ENABLED=true
COOKIE_SECURE=false
GIN_MODE=release
CUSTOM_OPERATOR_FLAG=keep_this_setting
"""
        parsed, _ = self._run_env_generation(
            existing_env_content=existing_content,
            env_vars={"AETHERFLOW_BASE_DOMAIN": "custom.domain.local"},
        )

        self.assertEqual(parsed.get("AES_MASTER_KEY"), "existing-secret-aes-key-exactly-32!")
        self.assertEqual(parsed.get("JWT_SECRET"), "existing-jwt-secret-64-bytes-string-for-operator-session-continuity!!")
        self.assertEqual(parsed.get("BIND_ADDR"), "10.0.0.42")
        self.assertEqual(parsed.get("PORT"), "9090")
        self.assertEqual(parsed.get("COOKIE_SECURE"), "false")
        self.assertEqual(parsed.get("DB_PATH"), "/custom/data/legacy.sqlite")
        self.assertEqual(parsed.get("AETHERFLOW_DB_PATH"), "/mnt/nvme/aetherflow-v4.sqlite")
        self.assertEqual(parsed.get("AETHERFLOW_RUNNER_SOCK"), "/custom/run/runner.sock")
        self.assertEqual(parsed.get("CUSTOM_OPERATOR_FLAG"), "keep_this_setting")

    def test_partial_env_and_quote_semantics_and_idempotent_reruns(self):
        """Partial existing aetherflow.env must not fail under set -euo pipefail, must preserve quotes, and must survive re-runs."""
        partial_env = """AES_MASTER_KEY="quoted-aes-key-32-bytes-long-ok!!"
AETHERFLOW_BASE_DOMAIN="quoted.example.org"
BIND_ADDR="0.0.0.0"
AETHERFLOW_DB_PATH="/srv/custom/af.sqlite"
AETHERFLOW_GOOGLE_ALLOWED_DOMAINS="example.org, sub.example.org"
"""
        parsed1, raw1 = self._run_env_generation(existing_env_content=partial_env)
        self.assertEqual(parsed1.get("AES_MASTER_KEY"), '"quoted-aes-key-32-bytes-long-ok!!"')
        self.assertEqual(parsed1.get("AETHERFLOW_BASE_DOMAIN"), '"quoted.example.org"')
        self.assertEqual(parsed1.get("BIND_ADDR"), '"0.0.0.0"')
        self.assertEqual(parsed1.get("DB_PATH"), '"/srv/custom/af.sqlite"')
        self.assertEqual(parsed1.get("AETHERFLOW_DB_PATH"), '"/srv/custom/af.sqlite"')
        self.assertEqual(parsed1.get("COOKIE_SECURE"), "true")
        self.assertEqual(parsed1.get("AETHERFLOW_GOOGLE_ALLOWED_DOMAINS"), '"example.org, sub.example.org"')
        # Unquoted domain must be used inside generated CORS URLs
        self.assertIn("https://quoted.example.org", parsed1.get("ALLOWED_CORS_ORIGIN", ""))
        self.assertIn("http://quoted.example.org:8080", parsed1.get("ALLOWED_CORS_ORIGIN", ""))
        self.assertNotIn('https://"quoted.example.org"', parsed1.get("ALLOWED_CORS_ORIGIN", ""))

        # Re-run against the generated aetherflow.env without passing existing_env_content
        parsed2, raw2 = self._run_env_generation()
        self.assertEqual(parsed2, parsed1)
        self.assertEqual(raw2.count("# Preserved Operator Custom Configurations"), 1)


class PackagedSystemdUnitPortabilityTests(unittest.TestCase):
    def test_packaged_api_unit_contains_no_personal_names_or_home_paths(self):
        """OPUS-009: Packaged unit deploy/systemd/aetherflow-api.service must be portable."""
        self.assertTrue(PACKAGED_API_UNIT.exists(), "Packaged aetherflow-api.service missing")
        content = PACKAGED_API_UNIT.read_text(encoding="utf-8")

        self.assertNotIn("betheenvy", content, "Personal username 'betheenvy' found in packaged unit")
        self.assertNotIn("qbittorrent", content.split("#")[0], "Specific non-default group found in unit directives")
        self.assertNotIn("/home/", content.split("#")[0], "Personal /home/ path found in unit directives")

        # Verify standard hardening and service definitions remain intact
        self.assertIn("User=aetherflow", content)
        self.assertIn("Group=aetherflow", content)
        self.assertIn("SupplementaryGroups=systemd-journal adm", content)
        self.assertIn("ProtectSystem=strict", content)
        self.assertIn("ProtectHome=read-only", content)
        self.assertIn("PrivateTmp=yes", content)
        self.assertIn("StateDirectory=aetherflow", content)
        self.assertIn("ReadWritePaths=/var/lib/aetherflow /var/log/aetherflow /run/aetherflow", content)

    def test_canonical_systemd_units_consolidated_and_duplicate_templates_retired(self):
        """Canonical deploy/systemd units must be the single source of truth without duplicate .template files."""
        self.assertFalse(RETIRED_TEMPLATE_API_UNIT.exists(), "Duplicate setup/templates/sysd/aetherflow-api.template should be removed")
        self.assertFalse(RETIRED_TEMPLATE_RUNNER_UNIT.exists(), "Duplicate setup/templates/sysd/aetherflow-runner.template should be removed")

        for unit_path in (PACKAGED_API_UNIT, PACKAGED_RUNNER_UNIT):
            self.assertTrue(unit_path.exists(), f"Canonical unit missing: {unit_path}")
            content = unit_path.read_text(encoding="utf-8")
            self.assertNotIn("COOKIE_SECURE=false", content, f"{unit_path.name} should not set COOKIE_SECURE=false")
            self.assertNotIn("betheenvy", content)
            self.assertNotIn("/home/hdd", content)

        modern = MODERN_STACK_SH.read_text(encoding="utf-8")
        finalize = (REPO_ROOT / "setup" / "modules" / "05-finalize.sh").read_text(encoding="utf-8")
        self.assertNotIn("aetherflow-api.template", modern)
        self.assertNotIn("aetherflow-runner.template", modern)
        self.assertNotIn("aetherflow-api.template", finalize)
        self.assertNotIn("aetherflow-runner.template", finalize)
        self.assertIn("deploy/systemd", modern)
        self.assertIn("deploy/systemd/aetherflow-api.service", finalize)
        self.assertIn("deploy/systemd/aetherflow-runner.service", finalize)

    def test_retired_quickbox_media_unit_templates_stay_removed(self):
        """Obsolete QuickBox killall-based qbittorrent/rtorrent unit templates must remain retired."""
        for unit_path in (RETIRED_QBIT_UNIT, RETIRED_RTORRENT_UNIT):
            self.assertFalse(unit_path.exists(), f"Retired template {unit_path} should not exist")

    def test_finalize_harden_permissions_restores_af_transcode_exec_bits(self):
        """setup/modules/05-finalize.sh must preserve execute bits on af-transcode in current and releases."""
        finalize = (REPO_ROOT / "setup" / "modules" / "05-finalize.sh").read_text(encoding="utf-8")
        self.assertIn('${af_root}/current/af-transcode', finalize)
        self.assertIn('${af_root}/current/bin/af-transcode', finalize)
        self.assertIn('-name "af-transcode"', finalize)


if __name__ == "__main__":
    unittest.main()
