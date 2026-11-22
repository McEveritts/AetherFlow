"""Pure evaluators and cleanup helpers for AetherFlow v4 lifecycle guest drills."""

from __future__ import annotations

from dataclasses import asdict
import json
import os
from pathlib import Path
import re
import signal
import sqlite3
import stat
import subprocess
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from lib.vm_guest_common import (
    CommandRecord,
    InterruptionBoundaryRecord,
    SentinelSnapshot,
    UnitRuntimeSnapshot,
    compute_file_sha256,
    evaluate_runner_backup_exchange,
    inspect_systemd_unit,
    snapshot_sentinel,
    verify_sentinel_unchanged,
)

TRANSIENT_SELF_UPDATE_UNIT_RE = re.compile(
    r"^aetherflow-self-update-(deploy|rollback)-(stable|nightly)-[0-9a-f]{8}\.service$"
)

DISPOSABLE_RUNNER_UNIT_NAME = "aetherflow-runner.service"
DISPOSABLE_API_UNIT_NAME = "aetherflow-api.service"
SYSTEMD_ETC_UNIT_DIR = "/etc/systemd/system"
SYSTEMD_LIFECYCLE_GUEST_MARKER = "/etc/aetherflow-disposable-guest"



def evaluate_self_update_initiation_exchange(
    http_status: Optional[int],
    raw_body: str,
    *,
    expect_http_status: int = 200,
    expect_runner_success: bool = True,
    expected_command: Optional[str] = "rollback",
    expected_channel: Optional[str] = "stable",
    expected_engine: Optional[str] = "native_rust_release",
    expected_error_substring: Optional[str] = None,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Dict[str, Any]], str]:
    """Validate `/v1/self-update` HTTP + `RunnerResponse` + inner transient-unit initiation JSON.

    Contract (`backend-rs/crates/af-runner/src/lib.rs:321-385`):
      - Outer `RunnerResponse`: `{"success": true, "output": "<json_string>", "error": ""}`
      - Inner JSON (`RunnerResponse.output`):
        `{"status": "initiated", "completed": false, "engine": "native_rust_release",
          "command": "<deploy|rollback>", "channel": "<stable|nightly>",
          "job_unit": "aetherflow-self-update-<command>-<channel>-<8hex>.service"}`
    """
    if http_status != expect_http_status:
        return (
            False,
            None,
            None,
            f"expected HTTP {expect_http_status}, got {http_status} (body={raw_body[:240]!r})",
        )

    try:
        runner_env = json.loads(raw_body)
    except json.JSONDecodeError as exc:
        return False, None, None, f"runner response is not valid JSON: {exc}"

    if not isinstance(runner_env, dict):
        return False, None, None, "runner response JSON root must be an object"

    actual_success = runner_env.get("success")
    if not isinstance(actual_success, bool):
        return False, runner_env, None, "RunnerResponse.success must be a boolean"
    if actual_success != expect_runner_success:
        return (
            False,
            runner_env,
            None,
            f"expected RunnerResponse.success={expect_runner_success}, got {actual_success} (error={runner_env.get('error')!r})",
        )

    if expected_error_substring is not None:
        err_text = str(runner_env.get("error") or "")
        if expected_error_substring.lower() not in err_text.lower():
            return (
                False,
                runner_env,
                None,
                f"expected error containing {expected_error_substring!r}, got {err_text!r}",
            )

    if not expect_runner_success:
        return True, runner_env, None, "runner self-update error response matched"

    output_str = runner_env.get("output")
    if not isinstance(output_str, str) or not output_str.strip():
        return False, runner_env, None, "RunnerResponse.output must be a non-empty JSON string"

    try:
        payload = json.loads(output_str)
    except json.JSONDecodeError as exc:
        return False, runner_env, None, f"RunnerResponse.output is not valid JSON: {exc}"

    if not isinstance(payload, dict):
        return False, runner_env, None, "RunnerResponse.output JSON root must be an object"

    if payload.get("status") != "initiated":
        return (
            False,
            runner_env,
            payload,
            f"expected self-update payload status='initiated', got {payload.get('status')!r}",
        )

    if payload.get("completed") is not False:
        return (
            False,
            runner_env,
            payload,
            f"expected self-update payload completed=False (asynchronous transient unit), got {payload.get('completed')!r}",
        )

    if expected_engine is not None and payload.get("engine") != expected_engine:
        return (
            False,
            runner_env,
            payload,
            f"expected engine={expected_engine!r}, got {payload.get('engine')!r}",
        )

    if expected_command is not None and payload.get("command") != expected_command:
        return (
            False,
            runner_env,
            payload,
            f"expected command={expected_command!r}, got {payload.get('command')!r}",
        )

    if expected_channel is not None and payload.get("channel") != expected_channel:
        return (
            False,
            runner_env,
            payload,
            f"expected channel={expected_channel!r}, got {payload.get('channel')!r}",
        )

    job_unit = payload.get("job_unit")
    if not isinstance(job_unit, str) or not TRANSIENT_SELF_UPDATE_UNIT_RE.match(job_unit):
        return (
            False,
            runner_env,
            payload,
            f"expected job_unit matching {TRANSIENT_SELF_UPDATE_UNIT_RE.pattern!r}, got {job_unit!r}",
        )

    if expected_command is not None and expected_channel is not None:
        expected_prefix = f"aetherflow-self-update-{expected_command}-{expected_channel}-"
        if not job_unit.startswith(expected_prefix):
            return (
                False,
                runner_env,
                payload,
                f"expected job_unit starting with {expected_prefix!r}, got {job_unit!r}",
            )

    return True, runner_env, payload, "self-update transient-unit initiation matched"


def evaluate_self_update_terminal_status_exchange(
    http_status: Optional[int],
    raw_body: str,
    *,
    expected_job_unit: str,
    expected_success: bool,
) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """Require a durable terminal receipt, not a transient initiation acknowledgment."""
    if http_status != 200:
        return False, None, f"expected HTTP 200, got {http_status}"
    if not TRANSIENT_SELF_UPDATE_UNIT_RE.fullmatch(expected_job_unit):
        return False, None, "invalid expected job unit"
    try:
        envelope = json.loads(raw_body)
        if not isinstance(envelope, dict) or envelope.get("success") is not True:
            return False, None, "expected a successful RunnerResponse envelope"
        output = envelope.get("output")
        if not isinstance(output, str):
            return False, None, "RunnerResponse.output must be a JSON string"
        payload = json.loads(output)
    except (TypeError, ValueError) as error:
        return False, None, f"invalid status JSON: {error}"
    if not isinstance(payload, dict):
        return False, None, "status payload must be an object"
    expected_status = "succeeded" if expected_success else "failed"
    expected_fields = {
        "job_unit": expected_job_unit,
        "status": expected_status,
        "completed": True,
        "success": expected_success,
    }
    for field_name, expected_value in expected_fields.items():
        actual_value = payload.get(field_name)
        if type(actual_value) is not type(expected_value) or actual_value != expected_value:
            return False, payload, f"unexpected {field_name}: {actual_value!r}"
    if "exit_code" not in payload:
        return False, payload, "terminal receipt must include exit_code"
    exit_code = payload.get("exit_code")
    error_text = payload.get("error")
    if expected_success:
        if type(exit_code) is not int or exit_code != 0 or error_text != "":
            return False, payload, "successful receipt must have exit_code=0 and no error"
    elif (
        (exit_code is not None and (type(exit_code) is not int or exit_code == 0))
        or not isinstance(error_text, str)
        or not error_text.strip()
    ):
        return False, payload, "failed receipt must provide a diagnostic and no zero exit code"
    return True, payload, "durable terminal receipt matched"


def evaluate_cgroup_isolation_and_survival(
    boundary: InterruptionBoundaryRecord,
) -> Tuple[bool, List[str]]:
    """Verify that the transient self-update unit ran in an external cgroup and survived restarting `aetherflow-runner.service`."""
    failures: List[str] = []

    if not TRANSIENT_SELF_UPDATE_UNIT_RE.match(boundary.job_unit):
        failures.append(f"invalid transient job_unit name: {boundary.job_unit!r}")

    if boundary.runner_pid_before_restart <= 0:
        failures.append(
            f"runner MainPID before restart must be > 0, got {boundary.runner_pid_before_restart}"
        )

    if boundary.updater_pid_during_flight <= 0:
        failures.append(
            f"updater PID during flight must be > 0, got {boundary.updater_pid_during_flight}"
        )

    if boundary.updater_pid_during_flight == boundary.runner_pid_before_restart:
        failures.append(
            f"updater PID ({boundary.updater_pid_during_flight}) must be distinct from runner MainPID ({boundary.runner_pid_before_restart})"
        )

    runner_cg = (boundary.runner_cgroup_before_restart or "").strip()
    updater_cg = (boundary.updater_cgroup_during_flight or "").strip()
    if not runner_cg:
        failures.append("runner cgroup before restart was empty")
    if not updater_cg:
        failures.append("updater cgroup during flight was empty")

    if runner_cg and updater_cg:
        if runner_cg == updater_cg:
            failures.append(
                f"updater cgroup ({updater_cg!r}) collided with runner cgroup ({runner_cg!r})"
            )
        if DISPOSABLE_RUNNER_UNIT_NAME in updater_cg:
            failures.append(
                f"updater cgroup ({updater_cg!r}) is nested inside {DISPOSABLE_RUNNER_UNIT_NAME}"
            )
        if boundary.job_unit not in updater_cg:
            failures.append(
                f"updater cgroup ({updater_cg!r}) does not reference transient unit {boundary.job_unit!r}"
            )

    if boundary.restart_command_exit_code != 0:
        failures.append(
            f"deliberate systemctl restart {boundary.runner_unit} failed with exit code {boundary.restart_command_exit_code}"
        )

    if boundary.runner_pid_after_restart <= 0:
        failures.append(
            f"runner MainPID after restart must be > 0, got {boundary.runner_pid_after_restart}"
        )

    if boundary.runner_pid_after_restart == boundary.runner_pid_before_restart:
        failures.append(
            f"runner MainPID did not rotate across deliberate service restart (remained {boundary.runner_pid_after_restart})"
        )

    if boundary.updater_pid_after_runner_restart <= 0:
        failures.append(
            "updater process did not survive deliberate runner restart (PID after restart <= 0)"
        )
    elif boundary.updater_pid_after_runner_restart != boundary.updater_pid_during_flight:
        failures.append(
            f"updater PID changed across runner restart ({boundary.updater_pid_during_flight} -> {boundary.updater_pid_after_runner_restart})"
        )

    if not boundary.updater_survived_runner_restart:
        failures.append("updater_survived_runner_restart was False")

    return len(failures) == 0, failures


def evaluate_self_stop_rejection_exchange(
    *,
    http_status: Optional[int],
    raw_body: str,
    runner_pid_before: int,
    runner_pid_after: int,
    runner_active_after: str,
    expected_error_substring: str = "quiesce_services must not include the active control worker unit",
) -> Tuple[bool, List[str]]:
    """Verify `/v1/backup` `restore_execute` rejects self-stopping `aetherflow-runner.service` without killing the controller."""
    failures: List[str] = []

    ok_ex, _, _, detail = evaluate_runner_backup_exchange(
        http_status,
        raw_body,
        expect_http_status=400,
        expect_runner_success=False,
        expected_error_substring=expected_error_substring,
    )
    if not ok_ex:
        failures.append(f"restore_execute self-stop rejection exchange failed: {detail}")

    if runner_pid_before <= 0:
        failures.append(f"runner_pid_before must be > 0, got {runner_pid_before}")
    if runner_pid_after <= 0:
        failures.append(f"runner_pid_after must be > 0, got {runner_pid_after}")
    if runner_pid_before > 0 and runner_pid_after != runner_pid_before:
        failures.append(
            f"controller MainPID changed during self-stop rejection check ({runner_pid_before} -> {runner_pid_after})"
        )
    if (runner_active_after or "").strip() != "active":
        failures.append(
            f"controller ActiveState after self-stop rejection must be 'active', got {runner_active_after!r}"
        )

    return len(failures) == 0, failures


def evaluate_rollback_outcome(
    *,
    current_link: Path,
    expected_previous_release_dir: Path,
    expected_version_string: str,
    live_db_path: Path,
    expected_marker_rows: Sequence[Tuple[int, str]],
    recovery_state_file: Path,
    deploy_log_file: Path,
    job_unit_snapshot: UnitRuntimeSnapshot,
    runner_active_after: str,
    api_active_after: str,
) -> Tuple[bool, Dict[str, Any], List[str]]:
    """Evaluate the filesystem, SQLite DB recovery, recovery state, and systemd outcomes of a native `af-release` rollback."""
    failures: List[str] = []
    summary: Dict[str, Any] = {}

    if not current_link.is_symlink():
        failures.append(f"CURRENT_LINK {str(current_link)!r} is not a symlink")
        resolved_current = ""
    else:
        resolved_current = str(current_link.resolve())
    expected_resolved = str(expected_previous_release_dir.resolve())
    summary["current_link_resolved"] = resolved_current
    summary["expected_release_dir"] = expected_resolved
    if resolved_current != expected_resolved:
        failures.append(
            f"CURRENT_LINK points to {resolved_current!r}; expected {expected_resolved!r}"
        )

    version_file = current_link / ".version"
    actual_version = (
        version_file.read_text(encoding="utf-8", errors="replace").strip()
        if version_file.is_file()
        else ""
    )
    summary["active_release_version"] = actual_version
    if actual_version != expected_version_string:
        failures.append(
            f"active release .version is {actual_version!r}; expected {expected_version_string!r}"
        )

    # Check SQLite database restoration from verified data-snapshot/aetherflow.sqlite.bak
    if not live_db_path.is_file():
        failures.append(f"live SQLite DB missing at {str(live_db_path)!r}")
    else:
        st = os.stat(live_db_path)
        db_mode = f"{stat.S_IMODE(st.st_mode):04o}"
        summary["live_db_mode"] = db_mode
        summary["live_db_sha256"] = compute_file_sha256(live_db_path)
        if db_mode != "0600":
            failures.append(
                f"restored live SQLite DB mode is {db_mode!r}; expected '0600' per restore_state_if_corrupted"
            )
        try:
            conn = sqlite3.connect(f"file:{live_db_path}?mode=ro", uri=True)
            try:
                integrity = str(conn.execute("PRAGMA integrity_check;").fetchone()[0])
                rows = [
                    (int(r[0]), str(r[1]))
                    for r in conn.execute(
                        "SELECT id, marker FROM lifecycle_release_marker ORDER BY id;"
                    ).fetchall()
                ]
            finally:
                conn.close()
            summary["live_db_integrity_check"] = integrity
            summary["live_db_marker_rows"] = rows
            if integrity != "ok":
                failures.append(f"live SQLite DB PRAGMA integrity_check={integrity!r} (expected 'ok')")
            if rows != list(expected_marker_rows):
                failures.append(
                    f"live SQLite DB marker rows={rows!r}; expected {list(expected_marker_rows)!r}"
                )
        except Exception as exc:  # noqa: BLE001
            failures.append(f"failed to query restored SQLite DB: {type(exc).__name__}: {exc}")

    # Verify corrupted DB was quarantined to `aetherflow.sqlite.corrupted.<epoch>.<uuid>` and stale -wal/-shm were unlinked
    db_parent = live_db_path.parent
    quarantined = sorted(
        str(p.name)
        for p in db_parent.glob(f"{live_db_path.name}.corrupted.*")
        if p.is_file()
    )
    summary["quarantined_corrupted_db_files"] = quarantined
    if not quarantined:
        failures.append(
            f"expected quarantined corrupted DB file matching '{live_db_path.name}.corrupted.*' in {str(db_parent)!r}"
        )

    wal_exists = Path(f"{live_db_path}-wal").exists()
    shm_exists = Path(f"{live_db_path}-shm").exists()
    summary["stale_wal_exists"] = wal_exists
    summary["stale_shm_exists"] = shm_exists
    if wal_exists or shm_exists:
        failures.append(
            f"stale SQLite sidecars were not unlinked during rollback DB recovery (wal={wal_exists}, shm={shm_exists})"
        )

    # Verify `.recovery_state.json`
    if not recovery_state_file.is_file():
        failures.append(f"recovery state file missing at {str(recovery_state_file)!r}")
    else:
        try:
            rec_state = json.loads(recovery_state_file.read_text(encoding="utf-8"))
            summary["recovery_state"] = rec_state
            if rec_state.get("phase") != "complete":
                failures.append(
                    f"expected .recovery_state.json phase='complete', got {rec_state.get('phase')!r}"
                )
        except Exception as exc:  # noqa: BLE001
            failures.append(f"failed to parse .recovery_state.json: {exc}")

    # Verify structured JSONL deploy.log entries
    if not deploy_log_file.is_file():
        failures.append(f"deploy log file missing at {str(deploy_log_file)!r}")
    else:
        log_text = deploy_log_file.read_text(encoding="utf-8", errors="replace")
        summary["deploy_log_excerpt"] = log_text[-2000:]
        for required_marker in (
            "STAGE 4: ROLLBACK INITIATED",
            "Database RESTORED",
            "ROLLBACK COMPLETE",
        ):
            if required_marker not in log_text:
                failures.append(f"deploy.log missing required marker {required_marker!r}")

    # Verify transient unit exit status and service states
    summary["job_unit_exec_main_status"] = job_unit_snapshot.exec_main_status
    summary["job_unit_result"] = job_unit_snapshot.result
    if job_unit_snapshot.exec_main_status != 0:
        failures.append(
            f"transient unit {job_unit_snapshot.unit_name} exited with ExecMainStatus={job_unit_snapshot.exec_main_status} (Result={job_unit_snapshot.result!r})"
        )
    if job_unit_snapshot.result not in ("success", ""):
        failures.append(
            f"transient unit {job_unit_snapshot.unit_name} Result={job_unit_snapshot.result!r} (expected 'success')"
        )

    if (runner_active_after or "").strip() != "active":
        failures.append(
            f"{DISPOSABLE_RUNNER_UNIT_NAME} ActiveState after rollback is {runner_active_after!r} (expected 'active')"
        )
    if (api_active_after or "").strip() != "active":
        failures.append(
            f"{DISPOSABLE_API_UNIT_NAME} ActiveState after rollback is {api_active_after!r} (expected 'active')"
        )

    return len(failures) == 0, summary, failures


def evaluate_rejected_snapshot_outcome(
    *,
    before_sentinels: Sequence[SentinelSnapshot],
    recovery_state_file: Path,
    api_snapshot: UnitRuntimeSnapshot,
    runner_snapshot: UnitRuntimeSnapshot,
) -> Tuple[bool, Dict[str, Any], List[str]]:
    failures: List[str] = []
    summary: Dict[str, Any] = {
        "api": asdict(api_snapshot),
        "runner": asdict(runner_snapshot),
        "sentinels": [],
    }
    if len(before_sentinels) != 3 or len({entry.path for entry in before_sentinels}) != 3:
        failures.append("expected three distinct database/WAL/SHM sentinels")
    for before in before_sentinels:
        after = snapshot_sentinel(Path(before.path))
        unchanged, drifts = verify_sentinel_unchanged(before, after)
        summary["sentinels"].append({"after": asdict(after), "drifts": drifts})
        if not unchanged:
            failures.extend(drifts)
    try:
        recovery_state = json.loads(recovery_state_file.read_text(encoding="utf-8"))
        summary["recovery_state"] = recovery_state
        if not isinstance(recovery_state, dict) or recovery_state.get("phase") != "failed":
            failures.append("rollback recovery state is not failed")
        elif "database recovery failed" not in str(recovery_state.get("last_error", "")).lower():
            failures.append("failed recovery state lacks the database recovery diagnostic")
    except (OSError, ValueError) as error:
        failures.append(f"cannot inspect failed recovery state: {error}")
    for snapshot in (api_snapshot, runner_snapshot):
        if snapshot.active_state not in ("inactive", "failed") or snapshot.main_pid != 0:
            failures.append(f"database service was not stopped: {snapshot.unit_name}")
    return not failures, summary, failures



def wait_for_transient_unit_completion(
    unit_name: str,
    *,
    cwd: Path,
    timeout_sec: float = 45.0,
) -> Tuple[UnitRuntimeSnapshot, List[CommandRecord]]:
    """Wait for a transient systemd unit (`--collect`) to finish execution, capturing its final state."""
    deadline = time.monotonic() + timeout_sec
    records: List[CommandRecord] = []
    last_observed_active: Optional[UnitRuntimeSnapshot] = None

    while time.monotonic() < deadline:
        snap, cmd = inspect_systemd_unit(unit_name, cwd=cwd)
        records.append(cmd)
        if snap.active_state in ("activating", "active", "reloading"):
            last_observed_active = snap
            time.sleep(0.2)
            continue
        if snap.active_state in ("inactive", "failed", "deactivating"):
            # Because `systemd-run --collect` unloads the transient unit when it exits cleanly
            # (`LoadState=not-found`, `ActiveState=inactive`), if `LoadState=not-found` and
            # `ExecMainStatus=0`, normalize `result="success"` when systemd already collected it.
            if snap.load_state == "not-found" and snap.active_state == "inactive":
                snap.result = snap.result or "success"
                if snap.exec_main_status < 0:
                    snap.exec_main_status = 0
            return snap, records
        time.sleep(0.2)

    final_snap, final_cmd = inspect_systemd_unit(unit_name, cwd=cwd)
    records.append(final_cmd)
    if last_observed_active is not None and final_snap.control_group == "":
        final_snap.control_group = last_observed_active.control_group
    return final_snap, records


def cleanup_owned_guest_units_and_processes(
    *,
    owned_transient_units: Sequence[str],
    installed_unit_files: Sequence[Path],
    owned_helper_pids: Sequence[int],
    cwd: Path,
    runner_Fn: Optional[Callable[[Sequence[str]], Any]] = None,
) -> Dict[str, Any]:
    """Fail-safe cleanup of all transient self-update units, disposable runner/api service files,
    and helper process groups owned by this guest drill run.
    """
    exec_cmd = runner_Fn or (
        lambda argv: subprocess.run(
            list(argv),
            cwd=str(cwd) if cwd.exists() else "/tmp",
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    )

    stopped_transient: List[str] = []
    for unit in owned_transient_units:
        if not unit:
            continue
        exec_cmd(["systemctl", "stop", unit])
        exec_cmd(["systemctl", "reset-failed", unit])
        stopped_transient.append(unit)

    removed_unit_files: List[str] = []
    for unit_path in installed_unit_files:
        unit_name = unit_path.name
        exec_cmd(["systemctl", "stop", unit_name])
        exec_cmd(["systemctl", "disable", unit_name])
        exec_cmd(["systemctl", "reset-failed", unit_name])
        if unit_path.exists() or unit_path.is_symlink():
            try:
                unit_path.unlink()
                removed_unit_files.append(str(unit_path))
            except OSError:
                pass

    exec_cmd(["systemctl", "daemon-reload"])

    terminated_pids: List[int] = []
    for pid in owned_helper_pids:
        if pid <= 0:
            continue
        try:
            os.killpg(os.getpgid(pid), signal.SIGTERM)
            terminated_pids.append(pid)
        except OSError:
            try:
                os.kill(pid, signal.SIGTERM)
                terminated_pids.append(pid)
            except OSError:
                pass

    return {
        "stopped_transient_units": stopped_transient,
        "removed_unit_files": removed_unit_files,
        "terminated_helper_pids": terminated_pids,
    }


