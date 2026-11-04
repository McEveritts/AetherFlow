#!/usr/bin/env python3
"""Unit tests for `scripts/v4_lifecycle_guest_drills.py` validation, evaluation, and cleanup helpers."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys
import tempfile
from typing import List, Sequence
import unittest
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "scripts"
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import v4_lifecycle_guest_drills as lifecycle  # noqa: E402


class TestLifecycleGuestGuardrails(unittest.TestCase):
    def test_valid_disposable_qemu_guest_passes(self) -> None:
        info = lifecycle.verify_guest_execution_guardrails(
            confirm_disposable_guest=True,
            work_root="/var/tmp/aetherflow-v4-guest-drills-lifecycle",
            api_bin="/var/tmp/stage/aetherflow-api",
            af_bin="/var/tmp/stage/af",
            guest_marker_file="/run/aetherflow-disposable-guest",
            platform_name="linux",
            euid=0,
            environ={"AETHERFLOW_DISPOSABLE_GUEST": "1"},
            marker_content="AETHERFLOW_DISPOSABLE_GUEST_V4\n",
            virt_Identifiers=["kvm", "QEMU Standard PC (Q35 + ICH9, 2009)"],
        )
        self.assertEqual(info["platform"], "linux")
        self.assertEqual(info["euid"], 0)
        self.assertEqual(info["work_root"], "/var/tmp/aetherflow-v4-guest-drills-lifecycle")

    def test_rejects_windows_or_bare_metal_or_live_host_paths(self) -> None:
        with self.assertRaisesRegex(lifecycle.GuestSafetyError, "require Linux guest OS"):
            lifecycle.verify_guest_execution_guardrails(
                confirm_disposable_guest=True,
                work_root="/var/tmp/aetherflow-v4-guest-drills-lifecycle",
                api_bin="/var/tmp/stage/aetherflow-api",
                af_bin="/var/tmp/stage/af",
                platform_name="win32",
                euid=0,
                environ={"AETHERFLOW_DISPOSABLE_GUEST": "1"},
                marker_content="AETHERFLOW_DISPOSABLE_GUEST_V4",
                virt_Identifiers=["kvm"],
            )

        with self.assertRaisesRegex(lifecycle.GuestSafetyError, "did not match disposable QEMU/KVM"):
            lifecycle.verify_guest_execution_guardrails(
                confirm_disposable_guest=True,
                work_root="/var/tmp/aetherflow-v4-guest-drills-lifecycle",
                api_bin="/var/tmp/stage/aetherflow-api",
                af_bin="/var/tmp/stage/af",
                platform_name="linux",
                euid=0,
                environ={"AETHERFLOW_DISPOSABLE_GUEST": "1"},
                marker_content="AETHERFLOW_DISPOSABLE_GUEST_V4",
                virt_Identifiers=["none", "Hetzner Dedicated Server"],
            )

        with self.assertRaisesRegex(lifecycle.GuestSafetyError, "forbidden live host path"):
            lifecycle.validate_binary_not_in_live_host_tree(
                "/opt/AetherFlow/current/bin/aetherflow-api", "aetherflow-api"
            )

    def test_validate_guest_isolated_path_enforces_work_root_containment(self) -> None:
        work_root = "/var/tmp/aetherflow-v4-guest-drills-lifecycle"
        valid = lifecycle.validate_guest_isolated_path(
            f"{work_root}/lifecycle_iso/releases",
            "releases_dir",
            work_root,
        )
        self.assertEqual(valid, f"{work_root}/lifecycle_iso/releases")

        for forbidden_candidate in (
            "/opt/AetherFlow/releases",
            "/var/lib/aetherflow",
            "/var/tmp/other-dir",
            f"{work_root}/../escape",
            "relative/path",
        ):
            with self.subTest(candidate=forbidden_candidate):
                with self.assertRaises(lifecycle.GuestSafetyError):
                    lifecycle.validate_guest_isolated_path(
                        forbidden_candidate, "candidate", work_root
                    )


class TestLifecycleSystemdOptIn(unittest.TestCase):
    def test_valid_marker_is_read_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker_path = Path(directory) / "guest-marker"
            marker_bytes = b"AETHERFLOW_DISPOSABLE_GUEST_V4\n"
            marker_path.write_bytes(marker_bytes)
            owner_uid = marker_path.stat().st_uid
            report = lifecycle.verify_lifecycle_systemd_marker(marker_path, trusted_uid=owner_uid)
            self.assertEqual(report, {"path": str(marker_path), "uid": owner_uid})
            self.assertEqual(marker_path.read_bytes(), marker_bytes)

    def test_missing_directory_and_invalid_marker_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker_path = Path(directory) / "guest-marker"
            for candidate in (marker_path, Path(directory)):
                with self.subTest(candidate=candidate):
                    with self.assertRaises(lifecycle.GuestSafetyError):
                        lifecycle.verify_lifecycle_systemd_marker(candidate)
            marker_path.write_text("untrusted-marker", encoding="utf-8")
            with self.assertRaisesRegex(lifecycle.GuestSafetyError, "invalid disposable-guest token"):
                lifecycle.verify_lifecycle_systemd_marker(
                    marker_path, trusted_uid=marker_path.stat().st_uid
                )

    def test_marker_owner_must_match_trusted_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker_path = Path(directory) / "guest-marker"
            marker_path.write_text("AETHERFLOW_DISPOSABLE_GUEST_V4\n", encoding="utf-8")
            with self.assertRaisesRegex(lifecycle.GuestSafetyError, "must be owned by UID"):
                lifecycle.verify_lifecycle_systemd_marker(
                    marker_path, trusted_uid=marker_path.stat().st_uid + 1
                )

    def test_missing_systemd_marker_prevents_work_root_mutation(self) -> None:
        with mock.patch.object(lifecycle, "verify_guest_execution_guardrails", return_value={}), \
             mock.patch.object(
                 lifecycle, "verify_lifecycle_systemd_marker",
                 side_effect=lifecycle.GuestSafetyError("missing systemd marker"),
             ), \
             mock.patch.object(lifecycle.shutil, "rmtree") as remove_tree:
            with self.assertRaisesRegex(lifecycle.GuestSafetyError, "missing systemd marker"):
                lifecycle.execute_lifecycle_guest_drill_suite(
                    confirm_disposable_guest=True,
                    work_root="/var/tmp/aetherflow-v4-guest-drills-lifecycle",
                    api_bin="/var/tmp/stage/aetherflow-api",
                    af_bin="/var/tmp/stage/af",
                )
            remove_tree.assert_not_called()

    def test_marker_replacement_after_metadata_check_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker_path = Path(directory) / "guest-marker"
            marker_path.write_text("AETHERFLOW_DISPOSABLE_GUEST_V4\n", encoding="utf-8")
            owner_uid = marker_path.stat().st_uid
            original_open = os.open

            def replace_marker_before_open(path: Path, flags: int) -> int:
                marker_path.rename(marker_path.with_suffix(".previous"))
                marker_path.write_text("AETHERFLOW_DISPOSABLE_GUEST_V4\n", encoding="utf-8")
                return original_open(path, flags)

            with mock.patch.object(lifecycle.os, "open", side_effect=replace_marker_before_open):
                with self.assertRaisesRegex(lifecycle.GuestSafetyError, "changed during verification"):
                    lifecycle.verify_lifecycle_systemd_marker(marker_path, trusted_uid=owner_uid)

    def test_guest_runner_explicitly_opts_into_isolated_lifecycle(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            work_root = Path(directory)
            with mock.patch.object(lifecycle, "validate_guest_isolated_path"), \
                 mock.patch.object(lifecycle.os, "symlink"):
                fixture = lifecycle.seed_isolated_lifecycle_fixture(
                    work_root / "lifecycle_iso",
                    api_bin=work_root / "aetherflow-api",
                    af_bin=work_root / "af",
                    work_root=work_root,
                )
            self.assertIn(
                "Environment=AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE=1\n",
                fixture["runner_unit_content"],
            )
            self.assertIn(
                f"Environment=AETHERFLOW_RELEASE_ROOT={fixture['iso_root']}\n",
                fixture["runner_unit_content"],
            )
            self.assertIn(
                f"Environment=AETHERFLOW_RUNNER_SOCK={fixture['runner_sock']}\n",
                fixture["runner_unit_content"],
            )
            self.assertNotIn("Environment=AETHERFLOW_RUNNER_SOCKET=", fixture["runner_unit_content"])
            self.assertIn(
                'SQLITE_DB="aetherflow.sqlite"\n',
                fixture["release_conf_path"].read_text(encoding="utf-8"),
            )
            for release in (fixture["good_release"], fixture["bad_release"]):
                snapshot_dir = release / "data-snapshot"
                manifest_lines = (snapshot_dir / "MANIFEST.sha256").read_text(encoding="utf-8").splitlines()
                self.assertEqual(len(manifest_lines), 2)
                for manifest_line in manifest_lines:
                    digest, filename = manifest_line.split()
                    self.assertIn(filename, ("aetherflow.sqlite.bak", ".env.bak"))
                    self.assertEqual(digest, lifecycle.compute_file_sha256(snapshot_dir / filename))


class TestLifecycleFixtureCredentials(unittest.TestCase):
    def test_each_fixture_generates_a_fresh_secret(self) -> None:
        entropy_values = (bytes(range(32)), bytes(range(32, 64)))
        with tempfile.TemporaryDirectory() as directory:
            work_root = Path(directory)
            secrets = []
            with mock.patch.object(lifecycle, "validate_guest_isolated_path"), \
                 mock.patch.object(lifecycle.os, "symlink"), \
                 mock.patch.object(lifecycle.os, "urandom", side_effect=entropy_values) as entropy:
                for index, expected_entropy in enumerate(entropy_values):
                    fixture = lifecycle.seed_isolated_lifecycle_fixture(
                        work_root / f"lifecycle_iso_{index}",
                        api_bin=work_root / "aetherflow-api",
                        af_bin=work_root / "af",
                        work_root=work_root,
                    )
                    environment = dict(
                        line.split("=", 1)
                        for line in fixture["env_file"].read_text(encoding="utf-8").splitlines()
                    )
                    self.assertEqual(environment["JWT_SECRET"], expected_entropy.hex())
                    secrets.append(environment["JWT_SECRET"])
                self.assertEqual(entropy.call_args_list, [mock.call(32), mock.call(32)])
            self.assertNotEqual(secrets[0], secrets[1])


class TestLifecycleRunnerTransport(unittest.TestCase):
    def test_readiness_uses_versioned_runner_health_route(self) -> None:
        socket_path = Path("isolated") / "runner.sock"
        health_response = mock.Mock(http_status=200, runner_response={"success": True})
        with mock.patch.object(Path, "exists", return_value=True), \
             mock.patch.object(lifecycle, "perform_uds_http_request", return_value=health_response) as request:
            response = lifecycle.wait_for_runner_uds_ready(socket_path, timeout_sec=0.1)
        self.assertIs(response, health_response)
        request.assert_called_once_with(str(socket_path), "GET", "/v1/health", timeout=2.0)

    def test_status_request_normalizes_socket_path_without_changing_job_identity(self) -> None:
        socket_path = Path("isolated") / "runner.sock"
        job_unit = "aetherflow-self-update-rollback-stable-12345678.service"
        with mock.patch.object(lifecycle, "perform_uds_http_request") as request:
            response = lifecycle.query_self_update_status(socket_path, job_unit)
        self.assertIs(response, request.return_value)
        request.assert_called_once_with(
            str(socket_path), "POST", "/v1/self-update/status",
            body={"job_unit": job_unit}, timeout=15.0,
        )


class TestLifecycleReportSerialization(unittest.TestCase):
    def test_nested_paths_serialize_without_coercing_status_types(self) -> None:
        payload = {
            "artifacts": [{"path": Path("fixture") / "receipt.json"}],
            "completed": False,
            "success": False,
            "exit_code": None,
        }
        rendered = json.dumps(payload, default=lifecycle.serialize_report_value)
        parsed = json.loads(rendered)
        self.assertEqual(parsed["artifacts"][0]["path"], str(Path("fixture") / "receipt.json"))
        self.assertIs(parsed["completed"], False)
        self.assertIs(parsed["success"], False)
        self.assertIsNone(parsed["exit_code"])

    def test_unsupported_values_fail_closed_instead_of_becoming_strings(self) -> None:
        with self.assertRaisesRegex(TypeError, "unsupported lifecycle report value: bytes"):
            json.dumps({"unexpected": b"not-valid-evidence"}, default=lifecycle.serialize_report_value)

    def test_cli_writes_failed_report_with_nested_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "report.json"
            report = {
                "evaluation": {"overall_passed": False},
                "phases": [{"status": "failed", "actual": Path("fixture") / "failed.log"}],
            }
            with mock.patch.object(lifecycle, "execute_lifecycle_guest_drill_suite", return_value=report), \
                 mock.patch("sys.stdout", new=io.StringIO()):
                exit_code = lifecycle.main([
                    "--api-bin", "/var/tmp/stage/aetherflow-api",
                    "--af-bin", "/var/tmp/stage/af",
                    "--json-out", str(output_path),
                ])
            self.assertEqual(exit_code, 1)
            parsed = json.loads(output_path.read_text(encoding="utf-8"))
            self.assertFalse(parsed["evaluation"]["overall_passed"])
            self.assertEqual(parsed["phases"][0]["actual"], str(Path("fixture") / "failed.log"))


class TestSelfUpdateTerminalStatusEvaluation(unittest.TestCase):
    def test_terminal_success_and_failure_receipts(self) -> None:
        job_unit = "aetherflow-self-update-rollback-stable-12345678.service"
        for expected_success in (True, False):
            payload = {
                "job_unit": job_unit,
                "status": "succeeded" if expected_success else "failed",
                "completed": True,
                "success": expected_success,
                "exit_code": 0 if expected_success else 1,
                "error": "" if expected_success else "remote artifact fetch failed",
            }
            raw_body = json.dumps({"success": True, "output": json.dumps(payload), "error": ""})
            passed, parsed, detail = lifecycle.evaluate_self_update_terminal_status_exchange(
                200, raw_body, expected_job_unit=job_unit, expected_success=expected_success
            )
            self.assertTrue(passed, detail)
            self.assertEqual(parsed, payload)

    def test_initiation_incomplete_and_mismatched_receipts_fail_closed(self) -> None:
        job_unit = "aetherflow-self-update-rollback-stable-12345678.service"
        valid_payload = {
            "job_unit": job_unit,
            "status": "succeeded",
            "completed": True,
            "success": True,
            "exit_code": 0,
            "error": "",
        }
        for overrides in (
            {"status": "initiated", "completed": False},
            {"completed": 1},
            {"success": False},
            {"job_unit": "aetherflow-self-update-rollback-stable-deadbeef.service"},
            {"exit_code": False},
            {"exit_code": "0"},
        ):
            payload = {**valid_payload, **overrides}
            passed, _, _ = lifecycle.evaluate_self_update_terminal_status_exchange(
                200,
                json.dumps({"success": True, "output": json.dumps(payload)}),
                expected_job_unit=job_unit,
                expected_success=True,
            )
            self.assertFalse(passed, payload)

    def test_missing_or_malformed_status_is_not_completion(self) -> None:
        job_unit = "aetherflow-self-update-deploy-stable-12345678.service"
        for status_code, raw_body in (
            (404, '{}'),
            (200, 'not json'),
            (200, '[]'),
            (200, '{"success":false,"error":"missing job"}'),
            (200, '{"success":true,"output":"not json"}'),
        ):
            passed, _, _ = lifecycle.evaluate_self_update_terminal_status_exchange(
                status_code, raw_body, expected_job_unit=job_unit, expected_success=False
            )
            self.assertFalse(passed)


class TestSelfUpdateInitiationEvaluation(unittest.TestCase):
    def test_valid_transient_unit_initiation_response_passes(self) -> None:
        inner = {
            "status": "initiated",
            "completed": False,
            "engine": "native_rust_release",
            "command": "rollback",
            "channel": "stable",
            "job_unit": "aetherflow-self-update-rollback-stable-9f8e7d6c.service",
        }
        outer = json.dumps({"success": True, "output": json.dumps(inner), "error": ""})
        ok, runner_env, payload, detail = lifecycle.evaluate_self_update_initiation_exchange(
            200,
            outer,
            expect_http_status=200,
            expect_runner_success=True,
            expected_command="rollback",
            expected_channel="stable",
            expected_engine="native_rust_release",
        )
        self.assertTrue(ok, detail)
        self.assertIsNotNone(runner_env)
        self.assertIsNotNone(payload)
        self.assertEqual(
            payload["job_unit"],
            "aetherflow-self-update-rollback-stable-9f8e7d6c.service",
        )
        self.assertIs(payload["completed"], False)

    def test_rejects_synchronous_completed_true_or_missing_job_unit_or_wrong_engine(self) -> None:
        # Regression check: old synchronous in-cgroup runner returned `completed: True` without `job_unit`
        sync_inner = {
            "status": "initiated",
            "completed": True,
            "engine": "native_rust_release",
            "command": "rollback",
            "channel": "stable",
            "job_unit": "aetherflow-self-update-rollback-stable-12345678.service",
        }
        sync_outer = json.dumps({"success": True, "output": json.dumps(sync_inner), "error": ""})
        ok_sync, _, _, detail_sync = lifecycle.evaluate_self_update_initiation_exchange(
            200, sync_outer
        )
        self.assertFalse(ok_sync)
        self.assertIn("completed=False", detail_sync)

        # Invalid job_unit format
        bad_unit_inner = dict(sync_inner, completed=False, job_unit="aetherflow-runner.service")
        bad_unit_outer = json.dumps(
            {"success": True, "output": json.dumps(bad_unit_inner), "error": ""}
        )
        ok_unit, _, _, detail_unit = lifecycle.evaluate_self_update_initiation_exchange(
            200, bad_unit_outer
        )
        self.assertFalse(ok_unit)
        self.assertIn("job_unit", detail_unit)

        # Legacy bash engine when native_rust_release is required
        bash_inner = dict(
            sync_inner,
            completed=False,
            engine="legacy_bash_fallback",
        )
        bash_outer = json.dumps({"success": True, "output": json.dumps(bash_inner), "error": ""})
        ok_bash, _, _, detail_bash = lifecycle.evaluate_self_update_initiation_exchange(
            200, bash_outer
        )
        self.assertFalse(ok_bash)
        self.assertIn("native_rust_release", detail_bash)

    def test_validates_self_update_error_responses(self) -> None:
        err_outer = json.dumps(
            {
                "success": False,
                "output": "",
                "error": "invalid self-update command: exec_arbitrary",
            }
        )
        ok_err, _, payload_err, detail_err = lifecycle.evaluate_self_update_initiation_exchange(
            400,
            err_outer,
            expect_http_status=400,
            expect_runner_success=False,
            expected_error_substring="invalid self-update command",
        )
        self.assertTrue(ok_err, detail_err)
        self.assertIsNone(payload_err)


class TestCgroupIsolationAndRunnerRestartSurvival(unittest.TestCase):
    def test_valid_external_cgroup_and_updater_survival_passes(self) -> None:
        boundary = lifecycle.InterruptionBoundaryRecord(
            job_unit="aetherflow-self-update-rollback-stable-a1b2c3d4.service",
            runner_unit="aetherflow-runner.service",
            runner_pid_before_restart=1410,
            runner_cgroup_before_restart="/system.slice/aetherflow-runner.service",
            runner_invocation_before_restart="inv-111",
            updater_pid_during_flight=1522,
            updater_cgroup_during_flight="/system.slice/aetherflow-self-update-rollback-stable-a1b2c3d4.service",
            updater_active_state_before_restart="active",
            restart_command_exit_code=0,
            restart_duration_ms=84.5,
            runner_pid_after_restart=1605,
            runner_cgroup_after_restart="/system.slice/aetherflow-runner.service",
            runner_invocation_after_restart="inv-222",
            updater_pid_after_runner_restart=1522,
            updater_cgroup_after_runner_restart="/system.slice/aetherflow-self-update-rollback-stable-a1b2c3d4.service",
            updater_active_state_after_runner_restart="active",
            updater_survived_runner_restart=True,
        )
        ok, failures = lifecycle.evaluate_cgroup_isolation_and_survival(boundary)
        self.assertTrue(ok, f"Unexpected failures: {failures}")
        self.assertEqual(failures, [])

    def test_detects_shared_cgroup_or_killed_updater_or_unrotated_runner_pid(self) -> None:
        # Case 1: Updater is inside aetherflow-runner.service cgroup
        in_runner_cgroup = lifecycle.InterruptionBoundaryRecord(
            job_unit="aetherflow-self-update-rollback-stable-a1b2c3d4.service",
            runner_unit="aetherflow-runner.service",
            runner_pid_before_restart=1410,
            runner_cgroup_before_restart="/system.slice/aetherflow-runner.service",
            runner_invocation_before_restart="inv-111",
            updater_pid_during_flight=1522,
            updater_cgroup_during_flight="/system.slice/aetherflow-runner.service",
            updater_active_state_before_restart="active",
            restart_command_exit_code=0,
            restart_duration_ms=50.0,
            runner_pid_after_restart=1605,
            runner_cgroup_after_restart="/system.slice/aetherflow-runner.service",
            runner_invocation_after_restart="inv-222",
            updater_pid_after_runner_restart=1522,
            updater_cgroup_after_runner_restart="/system.slice/aetherflow-runner.service",
            updater_active_state_after_runner_restart="active",
            updater_survived_runner_restart=True,
        )
        ok_cg, failures_cg = lifecycle.evaluate_cgroup_isolation_and_survival(in_runner_cgroup)
        self.assertFalse(ok_cg)
        self.assertTrue(any("collided with runner cgroup" in f for f in failures_cg))

        # Case 2: Updater was killed when runner restarted (PID -> 0) and runner PID didn't rotate
        killed_updater = lifecycle.InterruptionBoundaryRecord(
            job_unit="aetherflow-self-update-rollback-stable-a1b2c3d4.service",
            runner_unit="aetherflow-runner.service",
            runner_pid_before_restart=1410,
            runner_cgroup_before_restart="/system.slice/aetherflow-runner.service",
            runner_invocation_before_restart="inv-111",
            updater_pid_during_flight=1522,
            updater_cgroup_during_flight="/system.slice/aetherflow-self-update-rollback-stable-a1b2c3d4.service",
            updater_active_state_before_restart="active",
            restart_command_exit_code=0,
            restart_duration_ms=50.0,
            runner_pid_after_restart=1410,
            runner_cgroup_after_restart="/system.slice/aetherflow-runner.service",
            runner_invocation_after_restart="inv-111",
            updater_pid_after_runner_restart=0,
            updater_cgroup_after_runner_restart="",
            updater_active_state_after_runner_restart="failed",
            updater_survived_runner_restart=False,
        )
        ok_killed, failures_killed = lifecycle.evaluate_cgroup_isolation_and_survival(
            killed_updater
        )
        self.assertFalse(ok_killed)
        self.assertTrue(any("did not rotate" in f for f in failures_killed))
        self.assertTrue(any("did not survive" in f for f in failures_killed))


class TestSelfStopQuiescenceRejection(unittest.TestCase):
    def test_valid_self_stop_rejection_preserves_controller_pid(self) -> None:
        raw_err = json.dumps(
            {
                "success": False,
                "output": "",
                "error": 'invalid backup configuration: quiesce_services must not include the active control worker unit "aetherflow-runner.service" inside its own cgroup',
            }
        )
        ok, failures = lifecycle.evaluate_self_stop_rejection_exchange(
            http_status=400,
            raw_body=raw_err,
            runner_pid_before=2100,
            runner_pid_after=2100,
            runner_active_after="active",
        )
        self.assertTrue(ok, f"Unexpected failures: {failures}")
        self.assertEqual(failures, [])

    def test_detects_if_controller_was_killed_or_returned_200(self) -> None:
        raw_err = json.dumps(
            {
                "success": False,
                "output": "",
                "error": 'invalid backup configuration: quiesce_services must not include the active control worker unit "aetherflow-runner.service"',
            }
        )
        # Controller PID changed (meaning it was restarted/stopped)
        ok_pid, failures_pid = lifecycle.evaluate_self_stop_rejection_exchange(
            http_status=400,
            raw_body=raw_err,
            runner_pid_before=2100,
            runner_pid_after=2250,
            runner_active_after="active",
        )
        self.assertFalse(ok_pid)
        self.assertTrue(any("MainPID changed" in f for f in failures_pid))

        # Controller became inactive
        ok_inact, failures_inact = lifecycle.evaluate_self_stop_rejection_exchange(
            http_status=400,
            raw_body=raw_err,
            runner_pid_before=2100,
            runner_pid_after=2100,
            runner_active_after="inactive",
        )
        self.assertFalse(ok_inact)
        self.assertTrue(any("ActiveState" in f for f in failures_inact))


class TestRollbackOutcomeEvaluation(unittest.TestCase):
    def test_rollback_outcome_evaluation_and_corruption_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            good_rel = root / "releases/1700000001_good"
            bad_rel = root / "releases/1700000002_bad"
            good_rel.mkdir(parents=True)
            bad_rel.mkdir(parents=True)
            (good_rel / ".version").write_text("v4.0.0-good-rollback-target\n", encoding="utf-8")
            (bad_rel / ".version").write_text("v4.0.0-bad-candidate\n", encoding="utf-8")

            data_dir = root / "var/lib/aetherflow"
            data_dir.mkdir(parents=True)
            db_path = data_dir / "aetherflow.sqlite"
            expected_rows = [
                (1, "golden_pre_update_state_v4"),
                (2, "preserved_across_transient_rollback"),
            ]
            conn = sqlite3.connect(str(db_path))
            try:
                conn.execute(
                    "CREATE TABLE lifecycle_release_marker (id INTEGER PRIMARY KEY, marker TEXT NOT NULL);"
                )
                conn.executemany(
                    "INSERT INTO lifecycle_release_marker (id, marker) VALUES (?, ?);",
                    expected_rows,
                )
                conn.commit()
            finally:
                conn.close()
            os.chmod(db_path, 0o600)

            # Create quarantined `.corrupted.*` file as `restore_state_if_corrupted` does
            quarantined_file = data_dir / "aetherflow.sqlite.corrupted.1700000099.abcd1234"
            quarantined_file.write_bytes(b"CORRUPTED_BYTES")

            rec_state = root / "releases/.recovery_state.json"
            rec_state.write_text(
                json.dumps(
                    {
                        "previous_release": str(good_rel),
                        "candidate_release": str(bad_rel),
                        "phase": "complete",
                        "timestamp": 1700000100,
                    }
                ),
                encoding="utf-8",
            )

            deploy_log = root / "var/log/aetherflow-deploy.log"
            deploy_log.parent.mkdir(parents=True)
            deploy_log.write_text(
                '{"level":"WARN","message":"=== STAGE 4: ROLLBACK INITIATED ==="}\n'
                '{"level":"INFO","message":"Database RESTORED to /var/tmp/.../aetherflow.sqlite"}\n'
                '{"level":"INFO","message":"=== ROLLBACK COMPLETE: Reverted to 1700000001_good ==="}\n',
                encoding="utf-8",
            )

            unit_snap = lifecycle.UnitRuntimeSnapshot(
                unit_name="aetherflow-self-update-rollback-stable-11223344.service",
                load_state="not-found",
                active_state="inactive",
                sub_state="dead",
                main_pid=0,
                exec_main_pid=1999,
                exec_main_status=0,
                result="success",
                control_group="",
                invocation_id="inv-rollback",
                fragment_path="",
                proc_cgroup="",
            )

            # Verify failure when stale -wal sidecar is still present or recovery phase != complete
            Path(f"{db_path}-wal").write_bytes(b"STALE_WAL")
            rec_state.write_text(json.dumps({"phase": "switching"}), encoding="utf-8")
            ok_fail, summary_fail, failures = lifecycle.evaluate_rollback_outcome(
                current_link=good_rel,
                expected_previous_release_dir=good_rel,
                expected_version_string="v4.0.0-good-rollback-target",
                live_db_path=db_path,
                expected_marker_rows=expected_rows,
                recovery_state_file=rec_state,
                deploy_log_file=deploy_log,
                job_unit_snapshot=unit_snap,
                runner_active_after="active",
                api_active_after="active",
            )
            self.assertFalse(ok_fail)
            self.assertTrue(any("stale SQLite sidecars" in f for f in failures))
            self.assertTrue(any("phase='complete'" in f for f in failures))
            self.assertEqual(summary_fail["live_db_integrity_check"], "ok")
            self.assertEqual(summary_fail["live_db_marker_rows"], expected_rows)
            self.assertEqual(
                summary_fail["quarantined_corrupted_db_files"],
                ["aetherflow.sqlite.corrupted.1700000099.abcd1234"],
            )


class TestRejectedSnapshotEvaluation(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.sentinels = []
        for suffix in ("", "-wal", "-shm"):
            sentinel = self.root / f"aetherflow.sqlite{suffix}"
            sentinel.write_bytes(f"corrupt fixture {suffix}".encode("utf-8"))
            self.sentinels.append(lifecycle.snapshot_sentinel(sentinel))
        self.state = self.root / ".recovery_state.json"
        self.state.write_text(json.dumps({
            "phase": "failed", "last_error": "database recovery failed: digest mismatch",
        }), encoding="utf-8")
        self.api = self.unit_snapshot(lifecycle.DISPOSABLE_API_UNIT_NAME)
        self.runner = self.unit_snapshot(lifecycle.DISPOSABLE_RUNNER_UNIT_NAME)

    def unit_snapshot(self, unit_name: str) -> lifecycle.UnitRuntimeSnapshot:
        return lifecycle.UnitRuntimeSnapshot(
            unit_name=unit_name, load_state="loaded", active_state="inactive",
            sub_state="dead", main_pid=0, exec_main_pid=0, exec_main_status=0,
            result="success", control_group="", invocation_id="fixture",
            fragment_path="fixture", proc_cgroup="",
        )

    def evaluate(self):
        return lifecycle.evaluate_rejected_snapshot_outcome(
            before_sentinels=self.sentinels, recovery_state_file=self.state,
            api_snapshot=self.api, runner_snapshot=self.runner,
        )

    def test_failed_state_unchanged_bytes_and_stopped_writers_pass(self) -> None:
        passed, summary, failures = self.evaluate()
        self.assertTrue(passed, failures)
        self.assertEqual(summary["recovery_state"]["phase"], "failed")

    def test_each_database_or_sidecar_mutation_is_rejected(self) -> None:
        for sentinel in self.sentinels:
            with self.subTest(path=sentinel.path):
                sentinel_path = Path(sentinel.path)
                original = sentinel_path.read_bytes()
                sentinel_path.write_bytes(b"unexpected restored bytes")
                passed, _, failures = self.evaluate()
                self.assertFalse(passed)
                self.assertTrue(any("sha256 drift" in failure for failure in failures))
                sentinel_path.write_bytes(original)

    def test_completed_state_or_readmitted_writer_is_rejected(self) -> None:
        self.state.write_text(json.dumps({"phase": "complete"}), encoding="utf-8")
        passed, _, failures = self.evaluate()
        self.assertFalse(passed)
        self.assertIn("rollback recovery state is not failed", failures)
        self.state.write_text(json.dumps({
            "phase": "failed", "last_error": "database recovery failed",
        }), encoding="utf-8")
        for service in (self.api, self.runner):
            with self.subTest(service=service.unit_name):
                service.active_state = "active"
                service.main_pid = 1234
                passed, _, failures = self.evaluate()
                self.assertFalse(passed)
                self.assertTrue(any(service.unit_name in failure for failure in failures))
                service.active_state = "inactive"
                service.main_pid = 0

    def test_missing_or_duplicate_sentinels_fail_closed(self) -> None:
        self.sentinels = self.sentinels[:2]
        self.assertFalse(self.evaluate()[0])
        self.sentinels.append(self.sentinels[0])
        self.assertFalse(self.evaluate()[0])


class TestSuiteEvaluationAndCleanup(unittest.TestCase):
    def test_fail_closed_suite_evaluation_rejects_missing_or_unexecuted_phases(self) -> None:
        # Empty phase list must fail closed
        empty_eval = lifecycle.evaluate_lifecycle_drill_suite_status([])
        self.assertFalse(empty_eval["overall_passed"])
        self.assertEqual(empty_eval["overall_status"], "failed")
        self.assertEqual(
            len(empty_eval["missing_phases"]),
            len(lifecycle.MANDATORY_LIFECYCLE_PHASES),
        )

        # All mandatory phases present, real_execution=True, non-empty passing assertions -> pass
        passing_phases = [
            lifecycle.DrillPhaseResult(
                phase_id=pid,
                status="passed",
                real_execution=True,
                started_at="2026-11-03T08:00:00Z",
                completed_at="2026-11-03T08:00:01Z",
                duration_ms=100.0,
                assertions=[
                    lifecycle.AssertionRecord(
                        name=f"{pid}_assertion",
                        passed=True,
                        expected=True,
                        actual=True,
                    )
                ],
            )
            for pid in lifecycle.MANDATORY_LIFECYCLE_PHASES
        ]
        ok_eval = lifecycle.evaluate_lifecycle_drill_suite_status(passing_phases)
        self.assertTrue(ok_eval["overall_passed"])
        self.assertEqual(ok_eval["overall_status"], "passed")

        # Mark one phase with real_execution=False -> must fail closed
        passing_phases[3].real_execution = False
        bad_eval = lifecycle.evaluate_lifecycle_drill_suite_status(passing_phases)
        self.assertFalse(bad_eval["overall_passed"])
        self.assertEqual(bad_eval["overall_status"], "failed")

    def test_cleanup_owned_guest_units_and_processes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_runner_unit = tmp_path / "aetherflow-runner.service"
            fake_api_unit = tmp_path / "aetherflow-api.service"
            fake_runner_unit.write_text("[Unit]\nDescription=Disposable\n", encoding="utf-8")
            fake_api_unit.write_text("[Unit]\nDescription=Disposable\n", encoding="utf-8")

            recorded_cmds: List[List[str]] = []

            def _fake_runner(argv: Sequence[str]) -> None:
                recorded_cmds.append([str(a) for a in argv])

            summary = lifecycle.cleanup_owned_guest_units_and_processes(
                owned_transient_units=[
                    "aetherflow-self-update-rollback-stable-deadbeef.service"
                ],
                installed_unit_files=[fake_runner_unit, fake_api_unit],
                owned_helper_pids=[],
                cwd=tmp_path,
                runner_Fn=_fake_runner,
            )

            self.assertEqual(
                summary["stopped_transient_units"],
                ["aetherflow-self-update-rollback-stable-deadbeef.service"],
            )
            self.assertEqual(len(summary["removed_unit_files"]), 2)
            self.assertFalse(fake_runner_unit.exists())
            self.assertFalse(fake_api_unit.exists())
            self.assertIn(["systemctl", "daemon-reload"], recorded_cmds)

    def test_parse_systemctl_show_output(self) -> None:
        raw = (
            "Id=aetherflow-runner.service\n"
            "LoadState=loaded\n"
            "ActiveState=active\n"
            "SubState=running\n"
            "MainPID=4242\n"
            "ExecMainPID=4242\n"
            "ExecMainStatus=0\n"
            "Result=success\n"
            "ControlGroup=/system.slice/aetherflow-runner.service\n"
            "InvocationID=99887766554433221100aabbccddeeff\n"
        )
        props = lifecycle.parse_systemctl_show_output(raw)
        self.assertEqual(props["Id"], "aetherflow-runner.service")
        self.assertEqual(props["MainPID"], "4242")
        self.assertEqual(props["ControlGroup"], "/system.slice/aetherflow-runner.service")


if __name__ == "__main__":
    unittest.main()
