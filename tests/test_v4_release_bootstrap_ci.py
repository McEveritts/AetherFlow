#!/usr/bin/env python3
"""
Regression and contract tests for v4 release packaging, bootstrap installer,
OS preflight matrix, CI/Release/Security workflow DAG & runner baseline,
canonical root config/ parity, deployment documentation, and embedded E2E
isolation safety invariants.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_CLIPPY = "cargo clippy --workspace --all-targets --locked -- -D warnings"
STRICT_CORE_CLIPPY = "cargo clippy --no-deps -p af-models -p af-host -p af-release -p af-cli -p af-librespeed --all-targets --locked -- -D warnings"


def parse_workflow_jobs(workflow_text: str) -> dict[str, str]:
    """Extracts top-level job blocks under `jobs:` from a GitHub Actions workflow YAML file."""
    lines = workflow_text.splitlines()
    in_jobs = False
    jobs: dict[str, list[str]] = {}
    current_job: str | None = None

    for line in lines:
        if not in_jobs:
            if re.match(r"^jobs:\s*$", line):
                in_jobs = True
            continue
        if re.match(r"^\S", line):
            break
        job_match = re.match(r"^  ([a-zA-Z0-9_-]+):\s*$", line)
        if job_match:
            current_job = job_match.group(1)
            jobs[current_job] = []
        elif current_job is not None:
            jobs[current_job].append(line)

    return {k: "\n".join(v) for k, v in jobs.items()}


class V4ReleaseBootstrapCiTests(unittest.TestCase):
    def test_cli_provision_steps_match_bootstrap(self) -> None:
        shell = (ROOT / "setup/modules/06-state.sh").read_text()
        rust = (ROOT / "backend-rs/crates/af-cli/src/provision.rs").read_text()
        shell_steps = shell.split("\nALL_STEPS=(\n", 1)[1].split("\n)", 1)[0].split()
        rust_catalog = rust.split("pub const CANONICAL_ALL_STEPS: &[&str] = &[", 1)[1].split("];", 1)[0]
        self.assertEqual(re.findall(r'"([a-z0-9_]+)"', rust_catalog), shell_steps)

    @unittest.skipUnless(os.name == "posix", "Bash state behavior requires the remote Linux test environment")
    def test_load_config_missing_keys_are_empty_under_strict_shell(self):
        cases = (
            ("absent_file", None, False, ""),
            ("initialized_empty_file", None, True, ""),
            ("missing_key", 'release_channel=stable\n', False, ""),
            ("explicit_empty", 'hostname_value=""\n', False, ""),
            ("saved_value", 'hostname_value="example.test"\n', False, "example.test"),
        )
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config"
            environment = os.environ.copy()
            environment.update({
                "STATE_FILE": str(Path(directory) / "state"),
                "CONFIG_FILE": str(config_path),
                "STATE_MODULE_PATH": str(ROOT / "setup/modules/06-state.sh"),
            })
            for label, content, initialize, expected in cases:
                with self.subTest(label=label):
                    config_path.unlink(missing_ok=True)
                    if content is not None:
                        config_path.write_text(content, encoding="utf-8")
                    probe = 'set -euo pipefail\nsource "$STATE_MODULE_PATH"\n'
                    if initialize:
                        probe += "_init_state\n"
                    probe += 'loaded_value="$(_load_config hostname_value)"\nprintf "%s" "$loaded_value"\n'
                    outcome = subprocess.run(["bash", "-c", probe], env=environment, capture_output=True, text=True)
                    self.assertEqual(outcome.returncode, 0, outcome.stderr)
                    self.assertEqual(outcome.stdout, expected)

    @unittest.skipUnless(os.name == "posix", "Bash package setup requires the remote Linux test environment")
    def test_package_dependencies_do_not_prefetch_node(self):
        probe = r"""
set -euo pipefail
PATH="$PWD"
source "$1"
source "$2"
mkdir() { command -p mkdir "$@"; }
dirname() { command -p dirname "$@"; }
curl() { printf '%s\n' "$@" >> downloads; return 1; }
wget() { curl "$@"; }
apt-cache() { return 1; }
apt-get() { printf '%s\n' "$@" >> apt-args; return "$APT_STATUS"; }
_depends
"""
        for distro, codename in (("Debian", "bookworm"), ("Ubuntu", "jammy")):
            for from_source, apt_status in (("0", 0), ("1", 0), ("1", 1)):
                with self.subTest(distro=distro, from_source=from_source, apt_status=apt_status):
                    with tempfile.TemporaryDirectory() as directory:
                        scratch = Path(directory)
                        environment = {
                            "DISTRO": distro,
                            "CODENAME": codename,
                            "PHP_VER": "8.2",
                            "OUTTO": str(scratch / "setup.log"),
                            "APT_STATUS": str(apt_status),
                            "AETHERFLOW_BUILD_FROM_SOURCE": from_source,
                            "AF_RUNTIME_CACHE_DIR": str(scratch / "runtime-cache"),
                        }
                        outcome = subprocess.run(
                            ["/bin/bash", "-c", probe, "package-fixture",
                             str(ROOT / "setup/modules/00-core.sh"), str(ROOT / "setup/modules/02-packages.sh")],
                            env=environment, cwd=scratch, capture_output=True, text=True,
                        )
                        downloads = scratch / "downloads"
                        self.assertFalse(downloads.exists(), downloads.read_text() if downloads.exists() else "")
                        self.assertFalse((scratch / "runtime-cache").exists())
                        self.assertEqual(outcome.returncode, apt_status, outcome.stderr)
                        apt_args = (scratch / "apt-args").read_text().splitlines()
                        self.assertIn("install", apt_args)
                        for package in ("build-essential", "curl", "xz-utils"):
                            self.assertIn(package, apt_args)
                        self.assertTrue({"node", "nodejs", "npm"}.isdisjoint(apt_args))

    @unittest.skipUnless(os.name == "posix", "Bash state behavior requires the remote Linux test environment")
    def test_installer_ignores_legacy_node_checkpoint(self):
        probe = 'set -euo pipefail\nsource "$1"\n_detect_previous_install\n_list_steps\n'
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            state = scratch / "state"
            legacy_state = "# STATE_VERSION=2\ninstall_node\ndepends\n"
            state.write_text(legacy_state, encoding="utf-8")
            outcome = subprocess.run(
                ["bash", "-c", probe, "state-fixture", str(ROOT / "setup/modules/06-state.sh")],
                env={"PATH": os.defpath, "STATE_FILE": str(state), "CONFIG_FILE": str(scratch / "config")},
                cwd=scratch, capture_output=True, text=True,
            )
            self.assertEqual(outcome.returncode, 0, outcome.stderr)
            self.assertRegex(outcome.stdout, r"Progress: 1/\d+ steps completed")
            self.assertIn(" depends\n", outcome.stdout)
            self.assertIn("  [ ] build_modern\n", outcome.stdout)
            self.assertNotIn("install_node", outcome.stdout)
            self.assertEqual(state.read_text(encoding="utf-8"), legacy_state)

    @unittest.skipUnless(os.name == "posix", "Bash retry behavior requires the remote Linux test environment")
    def test_boot_readiness_retry_survives_strict_shell_and_stays_bounded(self):
        source = (ROOT / "setup/modules/05-finalize.sh").read_text(encoding="utf-8")
        loop = "local _api_try=0" + source.split("local _api_try=0", 1)[1].split("AF_SETUP_USER=", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            for ready_after, expected_attempts in ((3, 3), (40, 20)):
                probe = (
                    "set -euo pipefail\ncurl_calls=0\n"
                    f'curl() {{ curl_calls=$((curl_calls + 1)); test "$curl_calls" -ge {ready_after}; }}\n'
                    "sleep() { :; }\nprobe() {\n"
                    + loop
                    + 'printf "CURL_CALLS=%s\\n" "$curl_calls"\n}\nprobe\n'
                )
                with self.subTest(ready_after=ready_after):
                    outcome = subprocess.run(["bash", "-c", probe], cwd=directory, capture_output=True, text=True)
                    self.assertEqual(outcome.returncode, 0, outcome.stderr)
                    self.assertEqual(outcome.stdout.strip(), f"CURL_CALLS={expected_attempts}")

    @unittest.skipUnless(os.name == "posix", "Installation modes require the remote Linux test environment")
    def test_permission_hardening_preserves_bundled_librespeed_executables(self):
        source = (ROOT / "setup/modules/05-finalize.sh").read_text(encoding="utf-8")
        body = source.split("_harden_permissions() {", 1)[1].split("# Database & runtime state directories", 1)[0]
        with tempfile.TemporaryDirectory() as directory:
            scratch = Path(directory)
            release = scratch / "releases" / "1"
            binaries = [release / name for name in ("speedtest-backend", "bin/speedtest-backend")]
            snapshot = release / "data-snapshot" / "speedtest-backend"
            for path in [*binaries, snapshot]:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
                path.chmod(0o600)
            (scratch / "current").symlink_to(release, target_is_directory=True)
            mock_bin = scratch / "mock-bin"
            mock_bin.mkdir()
            chown = mock_bin / "chown"
            chown.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            chown.chmod(0o755)
            body = body.replace('"/opt/AetherFlow"', '"$1"', 1)
            probe = 'set -euo pipefail\nOUTTO=/dev/null\n_ensure_aetherflow_user() { :; }\n'
            probe += f'_harden_permissions() {{{body}\nfi\n}}\n_harden_permissions "$1"\n'
            outcome = subprocess.run(
                ["bash", "-c", probe, "permissions-fixture", directory],
                env={**os.environ, "PATH": f"{mock_bin}:{os.environ['PATH']}"},
                capture_output=True, text=True,
            )
            self.assertEqual(outcome.returncode, 0, outcome.stderr)
            self.assertEqual([path.stat().st_mode & 0o777 for path in binaries], [0o755, 0o755])
            self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)

    def test_embedded_harness_owns_process_groups_and_rejects_occupied_listeners(self):
        harness = (ROOT / "scripts/run_embedded_e2e.sh").read_text(encoding="utf-8")
        self.assertIn('exec setsid "${EXEC_PREFIX[@]}" env -i "${API_ENV[@]}" "${BINARY_PATH}"', harness)
        self.assertIn('kill -TERM -- "-${API_PID}"', harness)
        self.assertIn('kill -TERM -- "-${RUNNER_PID}"', harness)
        self.assertIn("Refusing to reuse occupied E2E listener", harness)
        self.assertLess(harness.index("probe.bind((host, port))"), harness.index('API_PID=$!'))
        self.assertNotIn('--socket "${RUNNER_SOCK}"', harness)

    def test_release_workflow_enforces_ubuntu_2204_and_security_gate_dag_before_publish(self):
        release_yml = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        jobs = parse_workflow_jobs(release_yml)

        expected_2204_jobs = (
            "validate-release",
            "security-python",
            "security-frontend",
            "security-gate",
            "build-wasm",
            "package-amd64",
            "package-arm64",
            "package-armv7-speedtest",
            "release-build",
            "release-e2e-amd64",
            "release-publish",
        )
        for job_name in expected_2204_jobs:
            self.assertIn(job_name, jobs)
        self.assertIn("release-arm64-runtime", jobs)

        sec_job = jobs["security-gate"]
        sec_fe_job = jobs["security-frontend"]
        sec_py_job = jobs["security-python"]
        wasm_job = jobs["build-wasm"]
        amd64_job = jobs["package-amd64"]
        arm64_job = jobs["package-arm64"]
        build_job = jobs["release-build"]
        e2e_job = jobs["release-e2e-amd64"]
        pub_job = jobs["release-publish"]

        # 1. All x86_64 release pipeline jobs must run on ubuntu-22.04 (GLIBC 2.35 baseline), never ubuntu-latest
        for job_name in expected_2204_jobs:
            with self.subTest(job=job_name):
                self.assertIn("runs-on: ubuntu-22.04", jobs[job_name])
        self.assertNotIn("runs-on: ubuntu-latest", release_yml)

        # 2. Only release-publish may hold write permissions; release-build must depend on all security gates
        # and parallel build artifacts; release-publish must depend on every security, build, and E2E gate.
        for job_name, job_text in jobs.items():
            if job_name == "release-publish":
                continue
            with self.subTest(readonly_job=job_name):
                self.assertIn("contents: read", job_text)
                self.assertNotIn("contents: write", job_text)

        self.assertRegex(
            build_job,
            r"needs:\s*\[.*security-gate.*security-frontend.*security-python.*package-amd64.*package-arm64.*package-armv7-speedtest.*\]",
        )
        self.assertRegex(amd64_job, r"needs:\s*\[.*build-wasm.*\]")
        self.assertRegex(arm64_job, r"needs:\s*\[.*build-wasm.*\]")
        self.assertRegex(e2e_job, r"needs:\s*\[.*release-build.*\]")
        self.assertRegex(
            pub_job,
            r"needs:\s*\[.*security-gate.*security-frontend.*security-python.*release-build.*release-e2e-amd64.*release-arm64-runtime.*\]",
        )

        # 3. Security gates must cover sharded Python tests, frontend WASM + Playwright typecheck,
        # and Gitleaks dir + git, cargo-deny, cargo-audit, clippy, locked workspace tests, and updater survival.
        self.assertIn("tests/run_parallel_tests.py --shard", sec_py_job)
        self.assertIn("tests/check_shell_hygiene.py", sec_py_job)
        self.assertIn("gitleaks dir . --verbose --redact", sec_job)
        self.assertIn("gitleaks git . --verbose --redact", sec_job)
        self.assertIn("cargo deny --locked check advisories bans licenses sources", sec_job)
        self.assertIn("cargo audit --file Cargo.lock", sec_job)
        self.assertIn(WORKSPACE_CLIPPY, sec_job)
        self.assertIn("cargo test --workspace --locked", sec_job)
        self.assertIn("updater_survives_caller_restart", sec_job)
        self.assertLess(sec_job.index(WORKSPACE_CLIPPY), sec_job.index("cargo test --workspace --locked"))
        self.assertIn('node-version: "24.22.2"', sec_fe_job)
        self.assertIn("cargo deny --manifest-path frontend-rs/Cargo.toml --locked", sec_fe_job)

        # 4. Build, assembly, live E2E, and attestation stages enforce strict ordering and packaging invariants.
        self.assertIn("bash scripts/build_wasm_frontend.sh --stage", wasm_job)
        self.assertIn("BUILD_FRONTEND=0 RUN_TESTS=0 PACKAGE_RELEASE=1 BUILD_CLI=1 BUILD_SPEEDTEST=1", amd64_job)
        self.assertIn("bash scripts/build_gold.sh", amd64_job)
        self.assertIn("BUILD_FRONTEND=0 RUN_TESTS=0 PACKAGE_RELEASE=1 BUILD_CLI=1 BUILD_SPEEDTEST=1", arm64_job)
        self.assertIn("release-dist/SHA256SUMS", build_job)
        self.assertLess(
            build_job.index("- name: Build and Package Standalone Rust LibreSpeed Archives"),
            build_job.index("- name: Upload Release Bundle Artifact"),
        )
        self.assertIn('node-version: "24.22.2"', e2e_job)
        self.assertIn("aetherflow-api bin/af bin/speedtest-backend", e2e_job)
        self.assertIn("- name: Execute Live E2E Against Extracted Release Artifact", e2e_job)

        attest_idx = pub_job.index("actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8")
        publish_idx = pub_job.index("- name: Publish to GitHub Releases")
        self.assertLess(attest_idx, publish_idx)

        self.assertNotIn("actions/setup-go", sec_job)
        self.assertNotIn("Legacy Go", sec_job)

    def test_ci_workflow_runs_locked_rust_build_and_embedded_e2e_and_smoke_gate(self):
        ci_yml = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        jobs = parse_workflow_jobs(ci_yml)
        self.assertNotIn("backend", jobs)
        self.assertIn("release-lifecycle-smoke", jobs)
        self.assertIn("node-installers", jobs)
        self.assertIn("frontend-rs-checks", jobs)
        self.assertIn("frontend-rs", jobs)
        self.assertIn("backend-rs-checks", jobs)
        self.assertIn("backend-rs", jobs)
        self.assertIn("embedded-e2e", jobs)

        self.assertIn("runs-on: ubuntu-22.04", jobs["backend-rs"])
        self.assertIn("runs-on: ubuntu-22.04", jobs["backend-rs-checks"])
        self.assertIn("runs-on: ubuntu-22.04", jobs["frontend-rs"])
        self.assertIn("runs-on: ubuntu-22.04", jobs["frontend-rs-checks"])
        self.assertIn("runs-on: ubuntu-22.04", jobs["embedded-e2e"])
        self.assertIn("needs: [backend-rs, frontend-rs]", jobs["embedded-e2e"])
        self.assertIn("browser: [chromium, firefox, webkit]", jobs["embedded-e2e"])
        self.assertIn("tests/run_parallel_tests.py --shard", jobs["node-installers"])
        self.assertIn('node-version: "24.22.2"', ci_yml)
        self.assertIn("bash scripts/smoke_v4_release_lifecycle.sh", jobs["release-lifecycle-smoke"])
        self.assertIn("git ls-files '*.go' '*go.mod' '*go.sum'", jobs["backend-rs"])
        self.assertIn("git ls-files '*.go' '*go.mod' '*go.sum'", jobs["backend-rs-checks"])
        self.assertIn("cargo test --workspace --locked", jobs["backend-rs-checks"])
        self.assertIn("cargo build --release --locked --bin aetherflow-api --bin af --bin speedtest-backend", jobs["backend-rs"])
        self.assertIn("bash scripts/run_embedded_e2e.sh", jobs["embedded-e2e"])

    def test_security_workflow_covers_nightly_and_retires_experimental(self):
        sec_yml = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        self.assertNotIn("- experimental", sec_yml)
        self.assertIn("- nightly", sec_yml)
        self.assertIn("rust-security:", sec_yml)
        self.assertIn("frontend-rs-security:", sec_yml)
        self.assertNotIn("security-checks:", sec_yml)
        self.assertNotIn("actions/setup-go", sec_yml)
        self.assertIn("cargo deny --locked check advisories bans licenses sources", sec_yml)
        self.assertIn("cargo audit --file Cargo.lock", sec_yml)
        self.assertIn(WORKSPACE_CLIPPY, sec_yml)
        self.assertIn(STRICT_CORE_CLIPPY, sec_yml)
        self.assertNotIn("|| true", sec_yml)
        self.assertTrue((ROOT / "backend-rs/deny.toml").is_file())

    def test_advisory_policy_uses_supported_scope_values(self):
        policy = (ROOT / "backend-rs/deny.toml").read_text(encoding="utf-8")
        self.assertIn('unmaintained = "all"', policy)
        self.assertIn('unsound = "all"', policy)
        self.assertNotIn('unmaintained = "warn"', policy)
        self.assertNotIn('unsound = "deny"', policy)

    def test_advisory_tools_use_separate_database_roots(self):
        policy = (ROOT / "backend-rs/deny.toml").read_text(encoding="utf-8")
        self.assertIn('db-path = "~/.cargo/advisory-dbs"', policy)
        self.assertNotIn('db-path = "~/.cargo/advisory-db"', policy)

    def test_local_workspace_dependencies_are_explicitly_versioned(self):
        workspace_manifest = (ROOT / "backend-rs/Cargo.toml").read_text(encoding="utf-8")
        local_dependencies = [
            line for line in workspace_manifest.splitlines()
            if re.match(r"^af-[a-z]+ = \{ path =", line)
        ]
        self.assertGreaterEqual(len(local_dependencies), 8)
        for dependency in local_dependencies:
            self.assertIn('version = "=4.0.0"', dependency)

    def test_build_gold_and_source_builders_require_cargo_lock_by_default(self):
        gold = (ROOT / "scripts/build_gold.sh").read_text(encoding="utf-8")
        modern = (ROOT / "setup/modules/modern_stack.sh").read_text(encoding="utf-8")
        rm = (ROOT / "deploy/release-manager.sh").read_text(encoding="utf-8")

        self.assertIn('CLI_BINARY_NAME="${CLI_BINARY_NAME:-af}"', gold)
        self.assertIn('CARGO_LOCKED="${CARGO_LOCKED:-1}"', gold)
        self.assertNotIn('CARGO_LOCKED="${CARGO_LOCKED:-auto}"', gold)
        self.assertIn("Cargo.lock is required for reproducible locked builds", gold)
        self.assertIn('--bin "${CARGO_CLI_BIN_NAME}"', gold)
        self.assertIn('--bin "${CARGO_SPEEDTEST_BIN_NAME}"', gold)
        self.assertIn('${target_dir}/bin/${dest_name}', gold)
        self.assertIn('stage_companion_binary "${cargo_target_dir}/${rust_target}/release/${CARGO_CLI_BIN_NAME}" "${target_dir}" "${CLI_BINARY_NAME}"', gold)
        self.assertIn('stage_companion_binary "${compiled_speedtest}" "${target_dir}" "${SPEEDTEST_BINARY_NAME}"', gold)

        self.assertIn("Refusing unlocked source build.", modern)
        self.assertIn("Refusing unlocked source build.", rm)

    def test_canonical_root_config_exists_without_legacy_go_config(self):
        for filename in ("packages.json", "package_automation.json"):
            canonical_path = ROOT / "config" / filename
            legacy_path = ROOT / "backend" / "config" / filename
            self.assertTrue(canonical_path.is_file(), f"Missing canonical {canonical_path}")
            self.assertFalse(legacy_path.exists(), f"Legacy Go config path must not exist: {legacy_path}")

        pkgs = json.loads((ROOT / "config/packages.json").read_text(encoding="utf-8"))
        auto = json.loads((ROOT / "config/package_automation.json").read_text(encoding="utf-8"))
        pkg_ids = {p.get("id") or p.get("name") for p in pkgs}
        auto_ids = set(auto["packages"].keys()) if isinstance(auto, dict) and "packages" in auto else set(auto.keys())

    def test_openapi_embed_uses_neutral_asset_without_legacy_spec(self):
        canonical = ROOT / "config/openapi-v1.yaml"
        legacy = ROOT / "backend/api/spec/openapi-v1.yaml"
        self.assertTrue(canonical.is_file())
        self.assertFalse(legacy.exists(), f"Legacy Go OpenAPI spec must not exist: {legacy}")
        ignored_assets = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn("!/config/openapi-v1.yaml", ignored_assets)
        routes = (ROOT / "backend-rs/crates/af-api/src/routes.rs").read_text(encoding="utf-8")
        self.assertIn('include_str!("../../../../config/openapi-v1.yaml")', routes)
        self.assertNotIn('include_str!("../../../../backend/', routes)

    def test_deployment_checklist_matches_v4_rust_architecture_and_forbids_insecure_fallbacks(self):
        checklist = (ROOT / "docs/deployment_checklist.md").read_text(encoding="utf-8")
        self.assertIn("/opt/AetherFlow/current/aetherflow-api", checklist)
        self.assertIn("/usr/local/bin/af", checklist)
        self.assertIn("revoked_tokens", checklist)
        self.assertIn("aetherflow-runner.service", checklist)
        self.assertIn("Ubuntu 22.04", checklist)
        self.assertIn("Cargo.lock", checklist)
        self.assertIn("2026-11-03", checklist)
        self.assertIn("validate_startup_jwt_secret", checklist)
        self.assertIn("64 hex characters", checklist)
        self.assertIn("AETHERFLOW_ENV=production", checklist)

        for forbidden in (
            "redis-cli",
            "blacklist:$JTI",
            "degrades to plaintext mode",
            "fails-open if Redis goes down",
            "2026-04-02",
        ):
            self.assertNotIn(forbidden, checklist)

    def test_installer_pulls_prebuilt_v4_by_default_and_forbids_implicit_downgrade(self):
        setup = (ROOT / "setup/AetherFlow-Setup").read_text(encoding="utf-8")
        modern = (ROOT / "setup/modules/modern_stack.sh").read_text(encoding="utf-8")

        self.assertIn("--from-source", setup)
        self.assertIn("--channel", setup)
        self.assertIn("af_detect_default_channel", setup)
        self.assertIn("_pull_prebuilt_v4_release", modern)
        self.assertIn("_af_is_v4_release_tag", modern)
        self.assertIn("Refusing pre-v4 or malformed release tag", modern)
        self.assertIn("Refusing implicit source-build or legacy v3 downgrade", modern)
        self.assertNotIn("_install_go", modern)
        self.assertNotIn("AF_GO_VERSION", modern)

    def test_systemd_templates_and_packaged_units_share_data_root_without_db_override(self):
        self.assertFalse((ROOT / "setup/templates/sysd/aetherflow-api.template").exists())
        self.assertFalse((ROOT / "setup/templates/sysd/aetherflow-runner.template").exists())
        pkg_api = (ROOT / "deploy/systemd/aetherflow-api.service").read_text(encoding="utf-8")
        pkg_runner = (ROOT / "deploy/systemd/aetherflow-runner.service").read_text(encoding="utf-8")

        self.assertIn("ExecStart=/opt/AetherFlow/current/aetherflow-api", pkg_api)
        self.assertIn("ExecStart=/opt/AetherFlow/current/aetherflow-api runner", pkg_runner)
        for unit in (pkg_api, pkg_runner):
            self.assertIn("Environment=DATA_DIR=/var/lib/aetherflow", unit)
            self.assertNotRegex(unit, r"(?m)^Environment=(?:AF_DB_PATH|DB_PATH|AETHERFLOW_DB_PATH)=")

    def test_release_manager_syncs_cli_entrypoints_on_swap_and_rollback(self):
        rm = (ROOT / "deploy/release-manager.sh").read_text(encoding="utf-8")
        self.assertIn("sync_cli_entrypoints()", rm)
        self.assertGreaterEqual(rm.count("sync_cli_entrypoints"), 3)

    def test_release_manager_validates_tarball_and_fails_closed_and_locks(self):
        rm = (ROOT / "deploy/release-manager.sh").read_text(encoding="utf-8")
        self.assertIn("validate_release_tarball()", rm)
        self.assertIn("Refusing to stage release-manager into symlinked deploy path", rm)
        self.assertIn("Refusing implicit source-build fallback", rm)
        self.assertIn("Refusing implicit fallback to ${GIT_BRANCH}", rm)
        self.assertNotIn('git checkout -f "${GIT_REMOTE}/${target_branch}" >> "${LOG_FILE}" 2>&1 || true', rm)
        self.assertIn('release_lock="${RELEASES_DIR}/.release.lock"', rm)
        self.assertIn('shared_db_lock="${AETHERFLOW_MAINTENANCE_LOCK_PATH:-}"', rm)
        self.assertIn('shared_db_lock="/run/aetherflow/.snapshot.lock"', rm)
        self.assertIn('shared_db_lock="${EFFECTIVE_RELEASE_ROOT}/run/aetherflow/.snapshot.lock"', rm)
        self.assertLess(rm.index('exec 199<'), rm.index('exec 201>'))

    def test_bootstrap_verifies_and_stages_before_replacing_opt_aetherflow(self):
        setup = (ROOT / "setup/AetherFlow-Setup").read_text(encoding="utf-8")
        self.assertIn("Existing /opt/AetherFlow preserved", setup)
        self.assertIn('bootstrap_backup="/opt/AetherFlow.bak.$$"', setup)
        self.assertLess(
            setup.index("Bootstrap archive SHA-256 verification failed"),
            setup.index('bootstrap_backup="/opt/AetherFlow.bak.$$"'),
        )
        self.assertLess(
            setup.index("_verify_bootstrap_sigstore_attestation"),
            setup.index('bootstrap_backup="/opt/AetherFlow.bak.$$"'),
        )

    @unittest.skipUnless(os.name == "posix", "Bash bootstrap behavior requires POSIX shell")
    def test_bootstrap_standalone_checkout_enforces_sigstore_attestation_and_sha256_pin(self):
        import hashlib
        import io
        import shutil
        import tarfile

        setup_src = (ROOT / "setup/AetherFlow-Setup").read_text(encoding="utf-8")
        resolved_tmp = str(Path(tempfile.gettempdir()).resolve())
        with tempfile.TemporaryDirectory(prefix="af-bs-test-", dir=resolved_tmp) as tmp:
            root = Path(tmp)
            standalone_dir = root / "standalone"
            standalone_dir.mkdir()
            standalone_setup = standalone_dir / "AetherFlow-Setup"
            standalone_setup.write_text(setup_src, encoding="utf-8")
            standalone_setup.chmod(0o755)

            # Build a minimal valid bootstrap tarball
            tar_buf = io.BytesIO()
            for name, payload, mode in (
                ("AetherFlow/setup/AetherFlow-Setup", b"#!/bin/bash\nexit 0\n", 0o755),
                ("AetherFlow/setup/modules/00-core.sh", b"#!/bin/bash\n", 0o644),
            ):
                pass
            with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
                d_info = tarfile.TarInfo("AetherFlow")
                d_info.type = tarfile.DIRTYPE
                d_info.mode = 0o755
                tf.addfile(d_info)
                for name, payload, mode in (
                    ("AetherFlow/setup/AetherFlow-Setup", b"#!/bin/bash\necho STAGED_OK\n", 0o755),
                    ("AetherFlow/setup/modules/00-core.sh", b"#!/bin/bash\n", 0o644),
                ):
                    info = tarfile.TarInfo(name)
                    info.size = len(payload)
                    info.mode = mode
                    tf.addfile(info, io.BytesIO(payload))
            tar_bytes = tar_buf.getvalue()
            tar_sha = hashlib.sha256(tar_bytes).hexdigest()

            release_dir = root / "release-assets"
            release_dir.mkdir()
            (release_dir / "aetherflow-bootstrap.tar.gz").write_bytes(tar_bytes)
            (release_dir / "SHA256SUMS").write_text(f"{tar_sha}  aetherflow-bootstrap.tar.gz\n", encoding="utf-8")
            (release_dir / "aetherflow-bootstrap.tar.gz.attestation.jsonl").write_text(
                '{"verificationMaterial":{},"dsseEnvelope":{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"sig":"AA=="}]}}\n',
                encoding="utf-8",
            )

            opt_target = root / "opt" / "AetherFlow"
            opt_target.mkdir(parents=True)
            sentinel = opt_target / "SENTINEL"
            sentinel.write_text("PRESERVED", encoding="utf-8")

            tool_bin = root / "tools"
            tool_bin.mkdir()
            for tool in ("awk", "bash", "cat", "chmod", "cp", "dirname", "env", "find", "head", "mkdir", "mktemp", "mv", "openssl", "python3", "rm", "sed", "sha256sum", "tar", "tr"):
                src = shutil.which(tool)
                if src:
                    (tool_bin / tool).symlink_to(src)
            (tool_bin / "apt-get").write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            (tool_bin / "apt-get").chmod(0o755)
            (tool_bin / "curl").write_text(
                "#!/usr/bin/env python3\n"
                "import os, pathlib, shutil, sys\n"
                "args = sys.argv[1:]\n"
                "out = pathlib.Path(args[args.index('-o') + 1] if '-o' in args else args[args.index('--output') + 1])\n"
                "url = args[-1]\n"
                "rdir = pathlib.Path(os.environ['TEST_RELEASE_DIR'])\n"
                "if url.endswith('/releases/latest') or '/releases?' in url:\n"
                "    import json\n"
                "    assets = [\n"
                "        {'name': 'aetherflow-bootstrap.tar.gz', 'browser_download_url': 'https://github.com/McEveritts/AetherFlow/releases/download/v4.0.0/aetherflow-bootstrap.tar.gz'},\n"
                "        {'name': 'SHA256SUMS', 'browser_download_url': 'https://github.com/McEveritts/AetherFlow/releases/download/v4.0.0/SHA256SUMS'},\n"
                "    ]\n"
                "    if os.environ.get('TEST_INCLUDE_ATTEST_ASSET') == '1':\n"
                "        assets.append({'name': 'aetherflow-bootstrap.tar.gz.attestation.jsonl', 'browser_download_url': 'https://github.com/McEveritts/AetherFlow/releases/download/v4.0.0/aetherflow-bootstrap.tar.gz.attestation.jsonl'})\n"
                "    rel = {'tag_name': 'v4.0.0', 'draft': False, 'prerelease': False, 'assets': assets}\n"
                "    out.write_text(json.dumps(rel if url.endswith('/latest') else [rel]))\n"
                "    sys.exit(0)\n"
                "name = url.rsplit('/', 1)[-1]\n"
                "cand = rdir / name\n"
                "if not cand.is_file():\n"
                "    sys.exit(22)\n"
                "shutil.copyfile(cand, out)\n",
                encoding="utf-8",
            )
            (tool_bin / "curl").chmod(0o755)

            os_rel = root / "os-release"
            os_rel.write_text('ID=ubuntu\nVERSION_ID="22.04"\n', encoding="utf-8")

            base_env = {
                "PATH": str(tool_bin),
                "TEST_RELEASE_DIR": str(release_dir),
                "AETHERFLOW_BOOTSTRAP_TMPDIR": str(root / "tmp"),
                "AETHERFLOW_BOOTSTRAP_INSTALL_ROOT": str(opt_target),
                "AETHERFLOW_BOOTSTRAP_NO_EXEC": "1",
                "AETHERFLOW_BOOTSTRAP_URL": "https://github.com/McEveritts/AetherFlow/releases/download/v4.0.0/aetherflow-bootstrap.tar.gz",
            }
            (root / "tmp").mkdir()

            bootstrap_prefix = setup_src.split('if [[ ! -d "${SCRIPT_DIR}/modules" ]]; then', 1)[0]

            def run_bootstrap(extra_args=(), extra_env=None):
                env = {**base_env, **(extra_env or {})}
                probe_script = (
                    bootstrap_prefix
                    + f'\nexport PATH="{tool_bin}:${{PATH}}"\n'
                    + "\nbootstrap_check_supported_os() { return 0; }\n"
                    + "_bootstrap_standalone_checkout\n"
                )
                probe_file = root / "probe_bootstrap.sh"
                probe_file.write_text(probe_script, encoding="utf-8")
                return subprocess.run(
                    ["bash", str(probe_file), *extra_args],
                    env=env,
                    capture_output=True,
                    text=True,
                )

            # 0. Verify embedded self-contained Python Sigstore verifier passes on real captured GitHub Actions bundle (including JSONL format)
            real_fixture = ROOT / "tests" / "fixtures" / "sigstore_bundle_nightly_109_1.json"
            real_digest = "018a270e2833886b1c59e2f831912c794e2ed66dacf6c2249ab1390fc2d44b26"
            py_verifier = setup_src.split("<<'PYEOF'\n", 2)[1].split("\nPYEOF\n", 1)[0]
            jsonl_bundle = root / "real.attestation.jsonl"
            jsonl_bundle.write_text(real_fixture.read_text(encoding="utf-8").strip() + "\n", encoding="utf-8")
            real_res = subprocess.run(
                [
                    "python3",
                    "-",
                    str(jsonl_bundle),
                    "McEveritts/AetherFlow",
                    real_digest,
                    "aetherflow-linux-amd64.tar.gz",
                    "v4.0.0-nightly.109.1",
                    "nightly",
                ],
                input=py_verifier,
                capture_output=True,
                text=True,
            )
            self.assertEqual(real_res.returncode, 0, real_res.stderr)

            # Subject name mismatch (e.g. replaying linux tarball bundle as bootstrap tarball) must fail closed
            mismatch_res = subprocess.run(
                [
                    "python3",
                    "-",
                    str(jsonl_bundle),
                    "McEveritts/AetherFlow",
                    real_digest,
                    "aetherflow-bootstrap.tar.gz",
                    "v4.0.0-nightly.109.1",
                    "nightly",
                ],
                input=py_verifier,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(mismatch_res.returncode, 0)

            # 1. Missing attestation bundle fails closed BEFORE extraction & preserves opt_target
            (release_dir / "aetherflow-bootstrap.tar.gz.attestation.jsonl").unlink()
            res_missing = run_bootstrap()
            self.assertNotEqual(res_missing.returncode, 0)
            self.assertIn("Sigstore attestation", res_missing.stderr)
            self.assertEqual(sentinel.read_text(), "PRESERVED")

            # 2. Invalid/forged attestation bundle fails closed via self-contained Python verifier (no gh in PATH)
            (release_dir / "aetherflow-bootstrap.tar.gz.attestation.jsonl").write_text(
                '{"verificationMaterial":{},"dsseEnvelope":{"payloadType":"application/vnd.in-toto+json","payload":"e30=","signatures":[{"sig":"AA=="}]}}\n',
                encoding="utf-8",
            )
            res_bad_sigstore = run_bootstrap()
            self.assertNotEqual(res_bad_sigstore.returncode, 0)
            self.assertIn("Sigstore attestation verification failed", res_bad_sigstore.stderr)
            self.assertEqual(sentinel.read_text(), "PRESERVED")

            # 3. With gh installed, gh attestation verify args are enforced and valid verification stages tree
            gh_log = root / "gh_args.json"
            (tool_bin / "gh").write_text(
                "#!/usr/bin/env python3\n"
                "import json, os, pathlib, sys\n"
                "if sys.argv[1:4] == ['attestation', 'verify', '--help']:\n"
                "    sys.exit(0)\n"
                "pathlib.Path(os.environ['TEST_GH_LOG']).write_text(json.dumps(sys.argv[1:]))\n"
                "sys.exit(int(os.environ.get('TEST_GH_RC', '0')))\n",
                encoding="utf-8",
            )
            (tool_bin / "gh").chmod(0o755)

            res_gh_fail = run_bootstrap(extra_env={"TEST_GH_LOG": str(gh_log), "TEST_GH_RC": "1"})
            self.assertNotEqual(res_gh_fail.returncode, 0)
            self.assertEqual(sentinel.read_text(), "PRESERVED")

            res_gh_ok = run_bootstrap(extra_env={"TEST_GH_LOG": str(gh_log), "TEST_GH_RC": "0"})
            self.assertEqual(res_gh_ok.returncode, 0, res_gh_ok.stderr)
            gh_args = json.loads(gh_log.read_text())
            self.assertIn("--repo", gh_args)
            self.assertEqual(gh_args[gh_args.index("--repo") + 1], "McEveritts/AetherFlow")
            self.assertIn("--source-ref", gh_args)
            self.assertEqual(gh_args[gh_args.index("--source-ref") + 1], "refs/tags/v4.0.0")
            self.assertTrue((opt_target / "setup/modules/00-core.sh").is_file())
            self.assertFalse(sentinel.exists())

            # 4. Explicit --sha256 offline pin bypasses attestation download and succeeds when digest matches, fails on mismatch
            (tool_bin / "gh").unlink()
            res_pin_bad = run_bootstrap(extra_args=("--sha256", "0" * 64))
            self.assertNotEqual(res_pin_bad.returncode, 0)
            self.assertIn("SHA-256 verification failed", res_pin_bad.stderr)

            opt_target.joinpath("SENTINEL2").write_text("OLD", encoding="utf-8")
            (release_dir / "aetherflow-bootstrap.tar.gz.attestation.jsonl").unlink()
            res_pin_ok = run_bootstrap(extra_args=("--sha256", tar_sha))
            self.assertEqual(res_pin_ok.returncode, 0, res_pin_ok.stderr)
            self.assertFalse(opt_target.joinpath("SENTINEL2").exists())
            self.assertTrue((opt_target / "setup/AetherFlow-Setup").is_file())

    def test_embedded_e2e_runner_defaults_no_runner_and_fails_closed_without_isolation_controls(self):
        import shutil
        import stat
        import subprocess
        import tempfile

        runner_path = ROOT / "scripts/run_embedded_e2e.sh"
        runner = runner_path.read_text(encoding="utf-8")
        self.assertIn("set -euo pipefail", runner)
        self.assertIn('START_RUNNER="${START_RUNNER:-0}"', runner)
        self.assertIn("verify_binary_isolation_support", runner)
        self.assertIn("AETHERFLOW_DISABLE_BACKGROUND_WORKERS", runner)
        self.assertIn("AETHERFLOW_ENV_FILE", runner)
        self.assertIn("BIND_ADDR", runner)
        self.assertIn("Preserving E2E work directory and logs at", runner)
        self.assertNotIn("printf '%s\\n' \"${bin_strings}\" | grep", runner)

        bash_bin = shutil.which("bash")
        if os.name != "posix" or not bash_bin:
            self.skipTest("requires native Linux shell execution")
        if bash_bin:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_dir = Path(tmp)
                padding = (b"AETHERFLOW_LARGE_BINARY_PADDING_LINE_0123456789ABCDEF\n" * 40000)  # >2 MiB

                # 1. >2 MiB ELF binary with all required markers at the start (triggers SIGPIPE if piped into grep -q)
                valid_large_bin = tmp_dir / "valid-large-api"
                valid_large_bin.write_bytes(
                    b"\x7fELF\n"
                    b"AETHERFLOW_DISABLE_BACKGROUND_WORKERS\n"
                    b"AETHERFLOW_ENV_FILE\n"
                    b"AETHERFLOW_SKIP_ENV_FILES\n"
                    b"BIND_ADDR\n"
                    + padding
                )
                valid_large_bin.chmod(valid_large_bin.stat().st_mode | stat.S_IEXEC)

                res_ok = subprocess.run(
                    [bash_bin, str(runner_path), "--binary", str(valid_large_bin), "--verify-binary-only"],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(
                    res_ok.returncode,
                    0,
                    f"Expected >2MB binary with isolation markers to pass without SIGPIPE (exit 141), got rc={res_ok.returncode}: {res_ok.stderr}",
                )

                # 2. >2 MiB ELF binary missing BIND_ADDR must still fail closed (non-zero)
                missing_bind_bin = tmp_dir / "missing-bind-api"
                missing_bind_bin.write_bytes(
                    b"\x7fELF\n"
                    b"AETHERFLOW_DISABLE_BACKGROUND_WORKERS\n"
                    b"AETHERFLOW_ENV_FILE\n"
                    + padding
                )
                missing_bind_bin.chmod(missing_bind_bin.stat().st_mode | stat.S_IEXEC)

                res_missing = subprocess.run(
                    [bash_bin, str(runner_path), "--binary", str(missing_bind_bin), "--verify-binary-only"],
                    capture_output=True,
                    text=True,
                )
                self.assertNotEqual(res_missing.returncode, 0)
                self.assertIn("BIND_ADDR", res_missing.stderr)


if __name__ == "__main__":
    unittest.main()
