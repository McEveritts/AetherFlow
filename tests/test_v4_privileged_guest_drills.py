#!/usr/bin/env python3
"""Unit tests for `scripts/v4_privileged_guest_drills.py` validation and evaluation helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import v4_privileged_guest_drills as drills  # noqa: E402


class TestGuestExecutionGuardrails(unittest.TestCase):
    def test_valid_disposable_qemu_guest_passes(self) -> None:
        info = drills.verify_guest_execution_guardrails(
            confirm_disposable_guest=True,
            work_root="/var/tmp/aetherflow-v4-guest-drills-unit",
            api_bin="/var/tmp/stage/aetherflow-api",
            af_bin="/var/tmp/stage/af",
            guest_marker_file="/run/aetherflow-disposable-guest",
            platform_name="linux",
            euid=0,
            environ={"AETHERFLOW_DISPOSABLE_GUEST": "1"},
            marker_content="AETHERFLOW_DISPOSABLE_GUEST_V4\n",
            virt_Identifiers=["kvm", "QEMU Standard PC (i440FX + PIIX, 1996)"],
        )
        self.assertEqual(info["platform"], "linux")
        self.assertEqual(info["euid"], 0)
        self.assertEqual(info["work_root"], "/var/tmp/aetherflow-v4-guest-drills-unit")

    def test_rejects_non_linux_or_non_root_or_missing_confirmation(self) -> None:
        with self.assertRaisesRegex(drills.GuestSafetyError, "require Linux guest OS"):
            drills.verify_guest_execution_guardrails(
                confirm_disposable_guest=True,
                work_root="/var/tmp/aetherflow-v4-guest-drills-unit",
                api_bin="/var/tmp/stage/aetherflow-api",
                af_bin="/var/tmp/stage/af",
                platform_name="win32",
                euid=0,
                environ={"AETHERFLOW_DISPOSABLE_GUEST": "1"},
                marker_content="AETHERFLOW_DISPOSABLE_GUEST_V4",
                virt_Identifiers=["kvm"],
            )

        with self.assertRaisesRegex(drills.GuestSafetyError, "must run as root"):
            drills.verify_guest_execution_guardrails(
                confirm_disposable_guest=True,
                work_root="/var/tmp/aetherflow-v4-guest-drills-unit",
                api_bin="/var/tmp/stage/aetherflow-api",
                af_bin="/var/tmp/stage/af",
                platform_name="linux",
                euid=1000,
                environ={"AETHERFLOW_DISPOSABLE_GUEST": "1"},
                marker_content="AETHERFLOW_DISPOSABLE_GUEST_V4",
                virt_Identifiers=["kvm"],
            )

        with self.assertRaisesRegex(drills.GuestSafetyError, "missing required --confirm-disposable-guest"):
            drills.verify_guest_execution_guardrails(
                confirm_disposable_guest=False,
                work_root="/var/tmp/aetherflow-v4-guest-drills-unit",
                api_bin="/var/tmp/stage/aetherflow-api",
                af_bin="/var/tmp/stage/af",
                platform_name="linux",
                euid=0,
                environ={"AETHERFLOW_DISPOSABLE_GUEST": "1"},
                marker_content="AETHERFLOW_DISPOSABLE_GUEST_V4",
                virt_Identifiers=["kvm"],
            )

    def test_rejects_missing_env_or_marker_or_bare_metal_virt(self) -> None:
        with self.assertRaisesRegex(drills.GuestSafetyError, "AETHERFLOW_DISPOSABLE_GUEST"):
            drills.verify_guest_execution_guardrails(
                confirm_disposable_guest=True,
                work_root="/var/tmp/aetherflow-v4-guest-drills-unit",
                api_bin="/var/tmp/stage/aetherflow-api",
                af_bin="/var/tmp/stage/af",
                platform_name="linux",
                euid=0,
                environ={},
                marker_content="AETHERFLOW_DISPOSABLE_GUEST_V4",
                virt_Identifiers=["kvm"],
            )

        with self.assertRaisesRegex(drills.GuestSafetyError, "missing token"):
            drills.verify_guest_execution_guardrails(
                confirm_disposable_guest=True,
                work_root="/var/tmp/aetherflow-v4-guest-drills-unit",
                api_bin="/var/tmp/stage/aetherflow-api",
                af_bin="/var/tmp/stage/af",
                platform_name="linux",
                euid=0,
                environ={"AETHERFLOW_DISPOSABLE_GUEST": "1"},
                marker_content="WRONG_TOKEN",
                virt_Identifiers=["kvm"],
            )

        with self.assertRaisesRegex(drills.GuestSafetyError, "did not match disposable QEMU/KVM"):
            drills.verify_guest_execution_guardrails(
                confirm_disposable_guest=True,
                work_root="/var/tmp/aetherflow-v4-guest-drills-unit",
                api_bin="/var/tmp/stage/aetherflow-api",
                af_bin="/var/tmp/stage/af",
                platform_name="linux",
                euid=0,
                environ={"AETHERFLOW_DISPOSABLE_GUEST": "1"},
                marker_content="AETHERFLOW_DISPOSABLE_GUEST_V4",
                virt_Identifiers=["none", "Hetzner Bare Metal Server"],
            )

    def test_rejects_unsafe_work_roots_and_live_opt_aetherflow_binaries(self) -> None:
        for bad_root in (
            "",
            "relative/path",
            "/tmp/aetherflow-drills",
            "/opt/AetherFlow",
            "/opt/AetherFlow/drills",
            "/var/lib/aetherflow/backups",
            "/var/tmp/aetherflow-v4-guest-drills/../escape",
        ):
            with self.subTest(bad_root=bad_root):
                with self.assertRaises(drills.GuestSafetyError):
                    drills.validate_isolated_work_root(bad_root)

        for bad_bin in (
            "/opt/AetherFlow/bin/aetherflow-api",
            "/opt/aetherflow/af",
            "relative/af",
            "/var/tmp/../opt/AetherFlow/af",
        ):
            with self.subTest(bad_bin=bad_bin):
                with self.assertRaises(drills.GuestSafetyError):
                    drills.validate_binary_not_in_live_host_tree(bad_bin, "binary")


class TestSentinelAndEnvelopeValidators(unittest.TestCase):
    def test_sentinel_snapshot_and_drift_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            sentinel = Path(tmp) / "root_sentinel.conf"
            sentinel.write_text("KEEP_SENTINEL=1\n", encoding="utf-8")
            snap1 = drills.snapshot_sentinel(sentinel)
            snap2 = drills.snapshot_sentinel(sentinel)
            ok, drifts = drills.verify_sentinel_unchanged(snap1, snap2)
            self.assertTrue(ok)
            self.assertEqual(drifts, [])

            sentinel.write_text("MUTATED_SENTINEL=2\n", encoding="utf-8")
            snap_mutated = drills.snapshot_sentinel(sentinel)
            ok_mut, drifts_mut = drills.verify_sentinel_unchanged(snap1, snap_mutated)
            self.assertFalse(ok_mut)
            self.assertTrue(any("sha256 drift" in d for d in drifts_mut))

            sentinel.unlink()
            snap_deleted = drills.snapshot_sentinel(sentinel)
            ok_del, drifts_del = drills.verify_sentinel_unchanged(snap1, snap_deleted)
            self.assertFalse(ok_del)
            self.assertTrue(any("deleted or missing" in d for d in drifts_del))

    def test_evaluate_cli_envelope(self) -> None:
        ok_json = json.dumps(
            {
                "domain": "backup",
                "action": "list",
                "status": "ok",
                "exit_code": 0,
                "data": {"backups": []},
            }
        )
        ok, payload, detail = drills.evaluate_cli_envelope(ok_json, expected_status="ok")
        self.assertTrue(ok, detail)
        self.assertIsNotNone(payload)

        err_json = json.dumps(
            {
                "domain": "backup",
                "action": "restore",
                "status": "error",
                "exit_code": 6,
                "error_kind": "unsupported_operation",
                "message": "confirmation required",
            }
        )
        ok_err, _, detail_err = drills.evaluate_cli_envelope(
            err_json,
            expected_status="error",
            expected_error_code="unsupported_operation",
        )
        self.assertTrue(ok_err, detail_err)

        wrong_code, _, _ = drills.evaluate_cli_envelope(
            err_json,
            expected_status="error",
            expected_error_code="privilege_required",
        )
        self.assertFalse(wrong_code)

    def test_evaluate_runner_backup_exchange(self) -> None:
        inner = {
            "action": "create_sqlite",
            "filename": "aetherflow_20261103T060001Z.sqlite",
            "verified": True,
            "size_bytes": 12288,
            "details": {"schema_version": 1},
        }
        outer = json.dumps({"success": True, "output": json.dumps(inner), "error": None})
        ok, runner_env, backup_payload, detail = drills.evaluate_runner_backup_exchange(
            200,
            outer,
            expect_http_status=200,
            expect_runner_success=True,
            expected_action="create_sqlite",
        )
        self.assertTrue(ok, detail)
        self.assertIsNotNone(runner_env)
        self.assertEqual(
            backup_payload["filename"],
            "aetherflow_20261103T060001Z.sqlite",
        )
        self.assertNotIn("success", backup_payload)
        missing_action = json.dumps({"success": True, "output": json.dumps({"verified": True})})
        self.assertFalse(drills.evaluate_runner_backup_exchange(200, missing_action)[0])
        non_boolean_success = json.dumps({"success": "true", "output": json.dumps(inner)})
        self.assertFalse(drills.evaluate_runner_backup_exchange(200, non_boolean_success)[0])

        forbidden_outer = json.dumps(
            {
                "success": False,
                "output": "",
                "error": "untrusted backup_dir override '/etc' rejected: runner enforces server-owned backup root",
            }
        )
        ok_rej, _, _, detail_rej = drills.evaluate_runner_backup_exchange(
            403,
            forbidden_outer,
            expect_http_status=403,
            expect_runner_success=False,
            expected_error_substring="untrusted backup_dir override",
        )
        self.assertTrue(ok_rej, detail_rej)

    def test_cli_errors_are_recorded_from_stderr(self) -> None:
        payload = {
            "status": "error",
            "domain": "backup",
            "action": "restore",
            "exit_code": 6,
            "error_kind": "unsupported_operation",
            "message": "confirmation required",
        }
        script = f"import sys; print({json.dumps(payload)!r}, file=sys.stderr); sys.exit(6)"
        with tempfile.TemporaryDirectory() as directory:
            result = drills.run_recorded_command(
                [sys.executable, "-c", script], cwd=Path(directory)
            )
        self.assertEqual(result.exit_code, 6)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.parsed_json, payload)
        self.assertTrue(drills.evaluate_cli_envelope(
            result.stderr, expected_status="error", expected_error_code="unsupported_operation"
        )[0])

    def test_cli_error_contract_rejects_missing_exit_code_and_wrong_error_kind(self) -> None:
        legacy_shape = {
            "status": "error",
            "errors": [{"code": "unsupported_operation"}],
        }
        self.assertFalse(drills.evaluate_cli_envelope(
            json.dumps(legacy_shape), expected_status="error", expected_error_code="unsupported_operation"
        )[0])
        wrong_exit_code = {"status": "error", "exit_code": 0, "error_kind": "unsupported_operation"}
        self.assertFalse(drills.evaluate_cli_envelope(
            json.dumps(wrong_exit_code), expected_status="error", expected_error_code="unsupported_operation"
        )[0])


class TestFailClosedSuiteEvaluation(unittest.TestCase):
    def _make_phase(
        self,
        phase_id: str,
        *,
        status: str = "passed",
        real_execution: bool = True,
        assertion_passed: bool = True,
    ) -> drills.DrillPhaseResult:
        return drills.DrillPhaseResult(
            phase_id=phase_id,
            status=status,
            real_execution=real_execution,
            started_at="2026-11-03T06:00:00Z",
            completed_at="2026-11-03T06:00:01Z",
            duration_ms=10.0,
            assertions=[
                drills.AssertionRecord(
                    name=f"{phase_id}_check",
                    passed=assertion_passed,
                    expected=True,
                    actual=assertion_passed,
                )
            ],
        )

    def test_empty_or_missing_phases_fail_closed(self) -> None:
        empty_eval = drills.evaluate_drill_suite_status([])
        self.assertFalse(empty_eval["overall_passed"])
        self.assertEqual(empty_eval["overall_status"], "failed")
        self.assertEqual(
            empty_eval["missing_phases"],
            list(drills.MANDATORY_DRILL_PHASES),
        )

    def test_pending_contract_or_unexecuted_phase_fails_closed(self) -> None:
        phases = [self._make_phase(pid) for pid in drills.MANDATORY_DRILL_PHASES[:-1]]
        phases.append(
            self._make_phase(
                drills.MANDATORY_DRILL_PHASES[-1],
                status="pending_contract",
                real_execution=True,
                assertion_passed=True,
            )
        )
        res = drills.evaluate_drill_suite_status(phases)
        self.assertFalse(res["overall_passed"])
        self.assertEqual(res["overall_status"], "failed_pending_contract")
        self.assertEqual(
            res["pending_contract_phases"],
            [drills.MANDATORY_DRILL_PHASES[-1]],
        )

        phases[-1] = self._make_phase(
            drills.MANDATORY_DRILL_PHASES[-1],
            status="passed",
            real_execution=False,
            assertion_passed=True,
        )
        res_mock = drills.evaluate_drill_suite_status(phases)
        self.assertFalse(res_mock["overall_passed"])
        self.assertEqual(res_mock["overall_status"], "failed")

    def test_all_mandatory_phases_real_and_passing_succeeds(self) -> None:
        phases = [self._make_phase(pid) for pid in drills.MANDATORY_DRILL_PHASES]
        res = drills.evaluate_drill_suite_status(phases)
        self.assertTrue(res["overall_passed"])
        self.assertEqual(res["overall_status"], "passed")
        self.assertEqual(res["passed_phases"], list(drills.MANDATORY_DRILL_PHASES))


if __name__ == "__main__":
    unittest.main()
