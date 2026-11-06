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
WORKSPACE_CLIPPY = "cargo clippy --workspace --all-targets --locked"
STRICT_CORE_CLIPPY = "cargo clippy --no-deps -p af-models -p af-host -p af-release -p af-cli --all-targets --locked -- -D warnings"


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

    @unittest.skipUnless(os.name == "posix", "Bash retry behavior requires the remote Linux test environment")
    def test_boot_readiness_retry_survives_strict_shell_and_stays_bounded(self):
        source = (ROOT / "setup/modules/05-finalize.sh").read_text(encoding="utf-8")
        loop = "local _api_try=0" + source.split("local _api_try=0", 1)[1].split("python3 -c", 1)[0]
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

    def test_embedded_harness_owns_process_groups_and_rejects_occupied_listeners(self):
        harness = (ROOT / "scripts/run_embedded_e2e.sh").read_text(encoding="utf-8")
        self.assertIn('exec setsid "${EXEC_PREFIX[@]}" "${BINARY_PATH}"', harness)
        self.assertIn('kill -TERM -- "-${API_PID}"', harness)
        self.assertIn('kill -TERM -- "-${RUNNER_PID}"', harness)
        self.assertIn("Refusing to reuse occupied E2E listener", harness)
        self.assertLess(harness.index("probe.bind((host, port))"), harness.index('API_PID=$!'))

    def test_release_workflow_enforces_ubuntu_2204_and_security_gate_dag_before_publish(self):
        release_yml = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
        jobs = parse_workflow_jobs(release_yml)

        self.assertIn("security-gate", jobs)
        self.assertIn("release-build", jobs)

        sec_job = jobs["security-gate"]
        build_job = jobs["release-build"]

        # 1. Both security-gate and release-build must run on ubuntu-22.04 (GLIBC 2.35 baseline), never ubuntu-latest
        self.assertIn("runs-on: ubuntu-22.04", sec_job)
        self.assertIn("runs-on: ubuntu-22.04", build_job)
        self.assertNotIn("runs-on: ubuntu-latest", release_yml)

        # 2. release-build must depend on security-gate in the workflow DAG
        self.assertRegex(build_job, r"needs:\s*\[?\s*security-gate\s*\]?")

        # 3. security-gate must run gitleaks, cargo-deny, cargo-audit, clippy, and locked workspace tests
        self.assertIn("gitleaks dir . --verbose --redact", sec_job)
        self.assertIn("cargo deny --locked check advisories bans sources", sec_job)
        self.assertIn("cargo audit --file Cargo.lock", sec_job)
        self.assertIn(WORKSPACE_CLIPPY, sec_job)
        self.assertIn(STRICT_CORE_CLIPPY, sec_job)
        self.assertIn("cargo test --workspace --locked", sec_job)

        # 4. Inside release-build, locked clippy, locked tests, and locked build of both binaries must precede Publish
        clippy_idx = build_job.index(WORKSPACE_CLIPPY)
        strict_clippy_idx = build_job.index(STRICT_CORE_CLIPPY)
        test_idx = build_job.index("cargo test --workspace --locked")
        build_idx = build_job.index("cargo build --release --locked --bin aetherflow-api --bin af")
        attest_idx = build_job.index("actions/attest-build-provenance@v2")
        publish_idx = build_job.index("- name: Publish to GitHub Releases")

        self.assertLess(clippy_idx, test_idx)
        self.assertLess(strict_clippy_idx, test_idx)
        self.assertLess(test_idx, build_idx)
        self.assertLess(build_idx, attest_idx)
        self.assertLess(attest_idx, publish_idx)

        self.assertIn('node-version: "24.22.2"', build_job)
        self.assertIn('cp target/release/af "${STAGE_DIR}/af"', build_job)
        self.assertIn('cp target/release/af "${STAGE_DIR}/bin/af"', build_job)
        self.assertIn("release-dist/SHA256SUMS", build_job)

    def test_ci_workflow_runs_locked_rust_build_and_embedded_e2e_and_smoke_gate(self):
        ci_yml = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        jobs = parse_workflow_jobs(ci_yml)
        self.assertIn("release-lifecycle-smoke", jobs)
        self.assertIn("backend-rs", jobs)
        self.assertIn("embedded-e2e", jobs)

        self.assertIn("runs-on: ubuntu-22.04", jobs["backend-rs"])
        self.assertIn("runs-on: ubuntu-22.04", jobs["embedded-e2e"])
        self.assertIn("needs: backend-rs", jobs["embedded-e2e"])
        self.assertIn('node-version: "24.22.2"', ci_yml)
        self.assertIn("bash scripts/smoke_v4_release_lifecycle.sh", jobs["release-lifecycle-smoke"])
        self.assertIn("cargo test --workspace --locked", jobs["backend-rs"])
        self.assertIn("cargo build --release --locked --bin aetherflow-api --bin af", jobs["backend-rs"])
        self.assertIn("bash scripts/run_embedded_e2e.sh", jobs["embedded-e2e"])

    def test_security_workflow_covers_nightly_and_retires_experimental(self):
        sec_yml = (ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
        self.assertNotIn("- experimental", sec_yml)
        self.assertIn("- nightly", sec_yml)
        self.assertIn("rust-security:", sec_yml)
        self.assertIn("cargo deny --locked check advisories bans sources", sec_yml)
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
        self.assertEqual(len(local_dependencies), 9)
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
        self.assertIn('${target_dir}/bin/${CLI_BINARY_NAME}', gold)

        self.assertIn("Refusing unlocked source build.", modern)
        self.assertIn("Refusing unlocked source build.", rm)

    def test_canonical_root_config_exists_and_matches_legacy_go_config_without_drift(self):
        for filename in ("packages.json", "package_automation.json"):
            canonical_path = ROOT / "config" / filename
            legacy_path = ROOT / "backend" / "config" / filename
            self.assertTrue(canonical_path.is_file(), f"Missing canonical {canonical_path}")
            self.assertTrue(legacy_path.is_file(), f"Missing compatibility {legacy_path}")
            canonical_bytes = canonical_path.read_bytes()
            legacy_bytes = legacy_path.read_bytes()
            self.assertEqual(
                canonical_bytes,
                legacy_bytes,
                f"Drift detected between {canonical_path} and {legacy_path}",
            )

        pkgs = json.loads((ROOT / "config/packages.json").read_text(encoding="utf-8"))
        auto = json.loads((ROOT / "config/package_automation.json").read_text(encoding="utf-8"))
        pkg_ids = {p.get("id") or p.get("name") for p in pkgs}
        auto_ids = set(auto["packages"].keys()) if isinstance(auto, dict) and "packages" in auto else set(auto.keys())

    def test_openapi_embed_uses_neutral_asset_with_legacy_byte_parity(self):
        canonical = ROOT / "config/openapi-v1.yaml"
        legacy = ROOT / "backend/api/spec/openapi-v1.yaml"
        self.assertTrue(canonical.is_file())
        self.assertEqual(canonical.read_bytes(), legacy.read_bytes())
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
        self.assertIn("ephemeral process secret", checklist)
        self.assertIn("Hex strings and arbitrary passphrases are not supported", checklist)
        self.assertIn("Missing-secret handling is not uniformly fail-closed", checklist)

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
        core = (ROOT / "setup/modules/00-core.sh").read_text(encoding="utf-8")

        self.assertIn("--from-source", setup)
        self.assertIn("--channel", setup)
        self.assertIn("af_detect_default_channel", setup)
        self.assertIn("_pull_prebuilt_v4_release", modern)
        self.assertIn("_af_is_v4_release_tag", modern)
        self.assertIn("Refusing pre-v4 release tag", modern)
        self.assertIn("Refusing implicit source-build or legacy v3 downgrade", modern)
        self.assertIn('AF_NODE_VERSION="${AF_NODE_VERSION:-24.22.2}"', core)
        self.assertIn("_af_verify_sha256", core)

    def test_systemd_templates_and_packaged_units_share_data_root_without_db_override(self):
        tpl_api = (ROOT / "setup/templates/sysd/aetherflow-api.template").read_text(encoding="utf-8")
        tpl_runner = (ROOT / "setup/templates/sysd/aetherflow-runner.template").read_text(encoding="utf-8")
        pkg_api = (ROOT / "deploy/systemd/aetherflow-api.service").read_text(encoding="utf-8")
        pkg_runner = (ROOT / "deploy/systemd/aetherflow-runner.service").read_text(encoding="utf-8")

        self.assertIn("ExecStart=/opt/AetherFlow/current/aetherflow-api", tpl_api)
        self.assertIn("ExecStart=/opt/AetherFlow/current/aetherflow-api", pkg_api)
        for unit in (tpl_api, tpl_runner, pkg_api, pkg_runner):
            self.assertIn("Environment=DATA_DIR=/var/lib/aetherflow", unit)
            self.assertNotRegex(unit, r"(?m)^Environment=(?:AF_DB_PATH|DB_PATH|AETHERFLOW_DB_PATH)=")
        self.assertIn("ExecStart=/opt/AetherFlow/current/aetherflow-api runner", tpl_runner)
        self.assertIn("ExecStart=/opt/AetherFlow/current/aetherflow-api runner", pkg_runner)

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
