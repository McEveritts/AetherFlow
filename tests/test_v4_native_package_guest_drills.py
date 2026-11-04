from __future__ import annotations

import ast
from pathlib import Path
import sqlite3
import sys
import tempfile
import tokenize
from typing import List, Set
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from v4_native_package_guest_drills import (
    ALLOWED_THREADFIN_AMD64_DIGESTS,
    MANDATORY_NATIVE_PACKAGE_PHASES,
    NATIVE_PACKAGE_HARNESS_SCHEMA_VERSION,
    SUPPORTED_NATIVE_PACKAGES,
    THREADFIN_PINNED_AMD64_COMPAT_SHA256,
    THREADFIN_PINNED_VERSION,
    AssertionRecord,
    DrillPhaseResult,
    GuestSafetyError,
    PackageUdsStreamRecord,
    build_arg_parser,
    create_labeled_quassel_sqlite_fixture,
    create_labeled_threadfin_config_fixture,
    evaluate_native_package_suite_status,
    evaluate_package_stream_exchange,
    inspect_elf_binary_metadata,
    main,
    parse_lock_file_kv,
    parse_package_stream_output,
    validate_binary_not_in_live_host_tree,
    validate_isolated_work_root,
    verify_guest_execution_guardrails,
)


def make_passing_native_phase(phase_id: str) -> DrillPhaseResult:
    return DrillPhaseResult(
        phase_id=phase_id,
        status="passed",
        real_execution=True,
        started_at="2026-11-03T07:00:00Z",
        completed_at="2026-11-03T07:00:05Z",
        duration_ms=5000.0,
        assertions=[
            AssertionRecord(
                name=f"{phase_id}_assertion",
                passed=True,
                expected="ok",
                actual="ok",
            )
        ],
    )


def make_stream_record(
    *,
    http_status: int = 200,
    engine_header: str = "declarative_rust",
    raw_response: str = "[PROGRESS:5] Starting\n[PROGRESS:50] Working\n[PROGRESS:100] Complete\n",
    socket_error: str | None = None,
) -> PackageUdsStreamRecord:
    progress_events, runner_exit_error = parse_package_stream_output(raw_response)
    return PackageUdsStreamRecord(
        socket_path="/var/tmp/aetherflow-v4-guest-drills-native/run/runner.sock",
        method="POST",
        path="/v1/package",
        request_body={
            "action": "install",
            "package_id": "fail2ban",
            "script_name": "installpackage-fail2ban",
            "app_port": 0,
        },
        http_status=http_status,
        headers={"X-AetherFlow-Package-Engine": engine_header} if engine_header else {},
        engine_header=engine_header or None,
        raw_response=raw_response,
        progress_events=progress_events,
        runner_exit_error=runner_exit_error,
        socket_error=socket_error,
        duration_ms=12.5,
    )


class TestNativePackageGuardrails(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.base_dir = Path(self.temp_dir.name)
        self.marker_file = self.base_dir / "aetherflow-disposable-guest"
        self.marker_file.write_text("disposable-debian-13-vm\n", encoding="utf-8")
        self.api_bin = self.base_dir / "aetherflow-api"
        self.af_bin = self.base_dir / "af"
        self.api_bin.write_bytes(b"\x7fELF-api-binary")
        self.af_bin.write_bytes(b"\x7fELF-af-binary")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_guardrail_rejects_missing_confirmation_or_env(self) -> None:
        with self.assertRaisesRegex(GuestSafetyError, "--confirm-disposable-guest"):
            verify_guest_execution_guardrails(
                confirm_disposable_guest=False,
                work_root="/var/tmp/aetherflow-v4-guest-drills-native-run",
                api_bin="/var/tmp/stage/aetherflow-api",
                af_bin="/var/tmp/stage/af",
                guest_marker_file="/run/aetherflow-disposable-guest",
                marker_content="AETHERFLOW_DISPOSABLE_GUEST_V4",
                environ={"AETHERFLOW_DISPOSABLE_GUEST": "1"},
                platform_name="linux",
                euid=0,
                virt_Identifiers=["kvm"],
            )

        with self.assertRaisesRegex(GuestSafetyError, "AETHERFLOW_DISPOSABLE_GUEST"):
            verify_guest_execution_guardrails(
                confirm_disposable_guest=True,
                work_root="/var/tmp/aetherflow-v4-guest-drills-native-run",
                api_bin="/var/tmp/stage/aetherflow-api",
                af_bin="/var/tmp/stage/af",
                guest_marker_file="/run/aetherflow-disposable-guest",
                marker_content="AETHERFLOW_DISPOSABLE_GUEST_V4",
                environ={},
                platform_name="linux",
                euid=0,
                virt_Identifiers=["kvm"],
            )

    def test_guardrail_rejects_live_host_paths_and_bare_metal(self) -> None:
        with self.assertRaisesRegex(GuestSafetyError, "/opt/AetherFlow"):
            validate_binary_not_in_live_host_tree(
                "/opt/AetherFlow/dashboard/aetherflow-api",
                "aetherflow-api",
            )

        with self.assertRaisesRegex(GuestSafetyError, "must reside under"):
            validate_isolated_work_root("/var/tmp/other-root")

        with self.assertRaisesRegex(GuestSafetyError, "virtualization"):
            verify_guest_execution_guardrails(
                confirm_disposable_guest=True,
                work_root="/var/tmp/aetherflow-v4-guest-drills-native-run",
                api_bin="/var/tmp/stage/aetherflow-api",
                af_bin="/var/tmp/stage/af",
                guest_marker_file="/run/aetherflow-disposable-guest",
                marker_content="AETHERFLOW_DISPOSABLE_GUEST_V4",
                environ={"AETHERFLOW_DISPOSABLE_GUEST": "1"},
                platform_name="linux",
                euid=0,
                virt_Identifiers=[],
            )

    def test_cli_main_returns_exit_2_when_guardrail_blocks(self) -> None:
        report_out = self.base_dir / "blocked.json"
        exit_code = main(
            [
                "--work-root",
                "/var/tmp/aetherflow-v4-guest-drills-native-run",
                "--api-bin",
                str(self.api_bin),
                "--af-bin",
                str(self.af_bin),
                "--json-out",
                str(report_out),
            ]
        )
        self.assertEqual(exit_code, 2)
        self.assertTrue(report_out.is_file())
        content = report_out.read_text(encoding="utf-8")
        self.assertIn("blocked_by_guest_safety_guardrail", content)
        self.assertIn(NATIVE_PACKAGE_HARNESS_SCHEMA_VERSION, content)


class TestStreamAndArtifactEvaluators(unittest.TestCase):
    def test_parse_and_evaluate_valid_declarative_rust_stream(self) -> None:
        record = make_stream_record(
            raw_response=(
                "[PROGRESS:5] Starting declarative install for Fail2ban (fail2ban)\n"
                "[PROGRESS:40] Installing fail2ban and python3-systemd backend...\n"
                "[PROGRESS:85] Starting and enabling fail2ban.service...\n"
                "[PROGRESS:100] Fail2ban installed successfully.\n"
            )
        )
        passed, detail = evaluate_package_stream_exchange(record)
        self.assertTrue(passed, detail)
        self.assertEqual(len(record.progress_events), 4)
        self.assertIsNone(record.runner_exit_error)

    def test_evaluate_stream_rejects_legacy_bash_or_non_monotonic_or_incomplete(self) -> None:
        wrong_engine = make_stream_record(engine_header="legacy_bash_fallback")
        passed_eng, detail_eng = evaluate_package_stream_exchange(wrong_engine)
        self.assertFalse(passed_eng)
        self.assertIn("declarative_rust", detail_eng)

        non_monotonic = make_stream_record(
            raw_response="[PROGRESS:5] Start\n[PROGRESS:60] Step\n[PROGRESS:40] Backwards\n[PROGRESS:100] Done\n"
        )
        passed_mono, detail_mono = evaluate_package_stream_exchange(non_monotonic)
        self.assertFalse(passed_mono)
        self.assertIn("monotonic", detail_mono)

        incomplete = make_stream_record(
            raw_response="[PROGRESS:5] Start\n[PROGRESS:85] Almost\n"
        )
        passed_inc, detail_inc = evaluate_package_stream_exchange(incomplete)
        self.assertFalse(passed_inc)
        self.assertIn("100", detail_inc)

    def test_evaluate_stream_handles_runner_exit_error_fail_closed(self) -> None:
        failed_stream = make_stream_record(
            raw_response=(
                "[PROGRESS:5] Starting declarative install for Threadfin (threadfin)\n"
                "[PROGRESS:98] Rolling back partial install state\n"
                "__RUNNER_EXIT_ERROR__:artifact verification failed: SHA-256 mismatch\n"
            )
        )
        passed_when_expecting_success, unused_detail = evaluate_package_stream_exchange(
            failed_stream,
            expect_success=True,
        )
        self.assertFalse(passed_when_expecting_success)
        self.assertIn("SHA-256 mismatch", unused_detail)

        passed_expected_err, detail_err = evaluate_package_stream_exchange(
            failed_stream,
            expect_success=False,
            expected_error_substring="SHA-256 mismatch",
        )
        self.assertTrue(passed_expected_err, detail_err)

    def test_inspect_elf_binary_metadata_and_lock_file_parser(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            base_path = Path(tmp_dir)
            elf_amd64 = base_path / "threadfin_amd64"
            header_bytes = bytearray(64)
            header_bytes[0:4] = b"\x7fELF"
            header_bytes[5] = 1
            header_bytes[18:20] = (62).to_bytes(2, byteorder="little")
            elf_amd64.write_bytes(bytes(header_bytes))

            meta_amd64 = inspect_elf_binary_metadata(elf_amd64)
            self.assertTrue(meta_amd64["exists"])
            self.assertTrue(meta_amd64["is_elf"])
            self.assertEqual(meta_amd64["e_machine"], 62)
            self.assertEqual(meta_amd64["arch"], "amd64")

            elf_arm64 = base_path / "threadfin_arm64"
            header_arm = bytearray(64)
            header_arm[0:4] = b"\x7fELF"
            header_arm[5] = 1
            header_arm[18:20] = (183).to_bytes(2, byteorder="little")
            elf_arm64.write_bytes(bytes(header_arm))
            meta_arm64 = inspect_elf_binary_metadata(elf_arm64)
            self.assertEqual(meta_arm64["arch"], "arm64")

            lock_file = base_path / ".quassel.lock"
            lock_file.write_text(
                "package=quassel\nversion=0.14.0\nengine=declarative_rust\n",
                encoding="utf-8",
            )
            parsed_lock = parse_lock_file_kv(lock_file)
            self.assertEqual(parsed_lock["package"], "quassel")
            self.assertEqual(parsed_lock["version"], "0.14.0")
            self.assertEqual(parsed_lock["engine"], "declarative_rust")

    def test_labeled_fixtures_are_explicitly_marked_test_provisioning_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            base_path = Path(tmp_dir)
            sqlite_path = base_path / "quassel-storage.sqlite"
            q_info = create_labeled_quassel_sqlite_fixture(sqlite_path, "nonexistent_test_user")
            self.assertEqual(q_info["classification"], "test_provisioning_fixture_only")
            conn = sqlite3.connect(str(sqlite_path))
            try:
                row = conn.execute(
                    "SELECT classification FROM af_test_provisioning_sentinel WHERE sentinel_id = 'quassel_storage_preservation_v4';"
                ).fetchone()
            finally:
                conn.close()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], "test_provisioning_fixture_only")

            conf_path = base_path / "conf/settings.json"
            t_info = create_labeled_threadfin_config_fixture(conf_path, "nonexistent_test_user")
            self.assertEqual(t_info["classification"], "test_provisioning_fixture_only")
            self.assertIn("test_provisioning_fixture_only", conf_path.read_text(encoding="utf-8"))


class TestFailClosedNativeSuiteEvaluation(unittest.TestCase):
    def test_all_mandatory_phases_passing_evaluates_to_passed(self) -> None:
        phases = [
            make_passing_native_phase(phase_id)
            for phase_id in MANDATORY_NATIVE_PACKAGE_PHASES
        ]
        result = evaluate_native_package_suite_status(phases)
        self.assertTrue(result["overall_passed"])
        self.assertEqual(result["overall_status"], "passed")
        self.assertEqual(result["required_phase_count"], 5)
        self.assertEqual(len(result["passed_phases"]), 5)

    def test_missing_or_failed_or_unexecuted_phase_fails_closed(self) -> None:
        empty_res = evaluate_native_package_suite_status([])
        self.assertFalse(empty_res["overall_passed"])
        self.assertEqual(empty_res["overall_status"], "failed")
        self.assertEqual(len(empty_res["missing_phases"]), 5)

        partial_phases = [
            make_passing_native_phase(phase_id)
            for phase_id in MANDATORY_NATIVE_PACKAGE_PHASES[:-1]
        ]
        partial_res = evaluate_native_package_suite_status(partial_phases)
        self.assertFalse(partial_res["overall_passed"])
        self.assertEqual(
            partial_res["missing_phases"],
            [MANDATORY_NATIVE_PACKAGE_PHASES[-1]],
        )

        unexecuted = [
            make_passing_native_phase(phase_id)
            for phase_id in MANDATORY_NATIVE_PACKAGE_PHASES
        ]
        unexecuted[2].real_execution = False
        unexec_res = evaluate_native_package_suite_status(unexecuted)
        self.assertFalse(unexec_res["overall_passed"])
        self.assertIn(
            f"{MANDATORY_NATIVE_PACKAGE_PHASES[2]} (real_execution=False)",
            unexec_res["failed_phases"],
        )

        failed_assertion_phases = [
            make_passing_native_phase(phase_id)
            for phase_id in MANDATORY_NATIVE_PACKAGE_PHASES
        ]
        failed_assertion_phases[1].assertions[0].passed = False
        failed_res = evaluate_native_package_suite_status(failed_assertion_phases)
        self.assertFalse(failed_res["overall_passed"])
        self.assertIn(MANDATORY_NATIVE_PACKAGE_PHASES[1], failed_res["failed_phases"])


class TestCodeHygieneConstraints(unittest.TestCase):
    def test_owned_python_files_have_no_inline_comments_or_single_letter_variables(self) -> None:
        owned_files = [
            REPO_ROOT / "scripts" / "v4_native_package_guest_drills.py",
            REPO_ROOT / "tests" / "test_v4_native_package_guest_drills.py",
        ]
        for file_path in owned_files:
            with file_path.open("rb") as token_handle:
                comment_tokens = [
                    tok
                    for tok in tokenize.tokenize(token_handle.readline)
                    if tok.type == tokenize.COMMENT
                ]
            self.assertEqual(
                len(comment_tokens),
                0,
                f"Found inline comments in {file_path}: {comment_tokens}",
            )

            source_text = file_path.read_text(encoding="utf-8")
            tree = ast.parse(source_text, filename=str(file_path))
            single_letter_names: Set[str] = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Name) and len(node.id) == 1:
                    single_letter_names.add(f"Name:{node.id}@L{node.lineno}")
                elif isinstance(node, ast.arg) and len(node.arg) == 1:
                    single_letter_names.add(f"arg:{node.arg}@L{node.lineno}")
                elif isinstance(node, ast.ExceptHandler) and node.name and len(node.name) == 1:
                    single_letter_names.add(f"except:{node.name}@L{node.lineno}")
                elif isinstance(node, ast.alias) and node.asname and len(node.asname) == 1:
                    single_letter_names.add(f"alias:{node.asname}")
            self.assertEqual(
                len(single_letter_names),
                0,
                f"Found single-letter variable names in {file_path}: {sorted(single_letter_names)}",
            )

    def test_constants_and_parser_defaults(self) -> None:
        self.assertEqual(SUPPORTED_NATIVE_PACKAGES, ("fail2ban", "quassel", "threadfin"))
        self.assertEqual(THREADFIN_PINNED_VERSION, "1.2.37")
        self.assertIn(THREADFIN_PINNED_AMD64_COMPAT_SHA256, ALLOWED_THREADFIN_AMD64_DIGESTS)
        parser = build_arg_parser()
        parsed = parser.parse_args(["--api-bin", "/tmp/api", "--af-bin", "/tmp/af"])
        self.assertFalse(parsed.confirm_disposable_guest)
        self.assertTrue(parsed.work_root.startswith("/var/tmp/aetherflow-v4-guest-drills"))


if __name__ == "__main__":
    unittest.main()
