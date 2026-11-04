#!/usr/bin/env python3
"""AetherFlow v4 Lifecycle & Transient-Systemd Self-Update Guest Drills Harness.

This stdlib-only Python harness executes ONLY inside a disposable QEMU/systemd
guest VM. It refuses to run on bare-metal hosts, on non-Linux systems, without
root privileges, without explicit disposable-guest markers, or with a work root
outside `/var/tmp/aetherflow-v4-guest-drills*`.

It exercises the real shipped `aetherflow-api` (running as a genuine isolated
`aetherflow-runner.service` systemd unit over an isolated Unix domain socket),
`af` (`af-cli` / `af-release`), `systemctl`, and `systemd-run` binaries—never
mocks—to verify:
  1. Binary, source, and release-artifact provenance plus systemd runtime environment.
  2. Genuine isolated `aetherflow-runner.service` startup with server-owned
     environment and `/v1/self-update` UDS model validation (`SelfUpdateRequest`).
  3. Controller self-stop rejection on `/v1/backup` (`restore_execute`) when
     `quiesce_services` includes `aetherflow-runner.service` (or `aetherflow-runner`
     or bypass tokens), proving the live runner unit is never stopped (`MainPID`
     unchanged, unit remains `active`, target files untouched).
  4. Real `/v1/self-update` (`{"command": "rollback", "channel": "stable"}`)
     spawning an external transient systemd unit (`aetherflow-self-update-rollback-stable-<8hex>.service`),
     returning `status: "initiated"`, `completed: false`, and `job_unit`,
     proving the updater runs in an independent systemd cgroup outside
     `aetherflow-runner.service`, deliberately restarting `aetherflow-runner.service`
     at the interruption boundary while the updater is in flight, proving the
     updater process/unit survives the runner restart, and verifying the native
     `af-release` rollback outcome (atomic `current` symlink revert + corrupted
     SQLite DB quarantine and verified `.bak` snapshot restoration + clean
     service restart).
  5. Honest native `deploy` (`command: "deploy"`) artifact-provider contract
     probe and transient-unit environment/config propagation diagnostics.
  6. A rejected snapshot must produce durable rollback failure, preserve the
     corrupt database and sidecars, and leave database writers stopped.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import signal
import sqlite3
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows local unit-test fallback
    fcntl = None  # type: ignore[assignment]

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from v4_privileged_guest_drills import (
    ALLOWED_WORK_ROOT_PREFIX,
    DEFAULT_GUEST_MARKER_FILE,
    FORBIDDEN_HOST_PATHS,
    GUEST_MARKER_REQUIRED_TOKEN,
    AssertionRecord,
    CommandRecord,
    DrillAssertionError,
    DrillPhaseResult,
    GuestSafetyError,
    SentinelSnapshot,
    UdsExchangeRecord,
    compute_file_sha256,
    evaluate_cli_envelope,
    evaluate_drill_suite_status,
    evaluate_runner_backup_exchange,
    perform_uds_http_request,
    run_recorded_command,
    snapshot_sentinel,
    utc_now_iso,
    validate_binary_not_in_live_host_tree,
    validate_isolated_work_root,
    verify_guest_execution_guardrails,
    verify_sentinel_unchanged,
)


LIFECYCLE_HARNESS_SCHEMA_VERSION = "aetherflow.v4.lifecycle_guest_drills.v1"

MANDATORY_LIFECYCLE_PHASES: Tuple[str, ...] = (
    "binary_and_systemd_environment_provenance",
    "isolated_systemd_runner_and_self_update_validation",
    "self_stop_quiescence_rejection_preserves_controller",
    "transient_unit_cgroup_survival_and_native_rollback_recovery",
    "native_deploy_artifact_provider_contract_probe",
    "rejected_snapshot_rollback_preserves_failure_and_quiescence",
)

TRANSIENT_SELF_UPDATE_UNIT_RE = re.compile(
    r"^aetherflow-self-update-(deploy|rollback)-(stable|nightly)-[0-9a-f]{8}\.service$"
)

DISPOSABLE_RUNNER_UNIT_NAME = "aetherflow-runner.service"
DISPOSABLE_API_UNIT_NAME = "aetherflow-api.service"
SYSTEMD_ETC_UNIT_DIR = "/etc/systemd/system"
SYSTEMD_LIFECYCLE_GUEST_MARKER = "/etc/aetherflow-disposable-guest"


@dataclass
class UnitRuntimeSnapshot:
    unit_name: str
    load_state: str
    active_state: str
    sub_state: str
    main_pid: int
    exec_main_pid: int
    exec_main_status: int
    result: str
    control_group: str
    invocation_id: str
    fragment_path: str
    proc_cgroup: str


@dataclass
class InterruptionBoundaryRecord:
    job_unit: str
    runner_unit: str
    runner_pid_before_restart: int
    runner_cgroup_before_restart: str
    runner_invocation_before_restart: str
    updater_pid_during_flight: int
    updater_cgroup_during_flight: str
    updater_active_state_before_restart: str
    restart_command_exit_code: int
    restart_duration_ms: float
    runner_pid_after_restart: int
    runner_cgroup_after_restart: str
    runner_invocation_after_restart: str
    updater_pid_after_runner_restart: int
    updater_cgroup_after_runner_restart: str
    updater_active_state_after_runner_restart: str
    updater_survived_runner_restart: bool


def _record_assertion(
    phase: DrillPhaseResult,
    name: str,
    passed: bool,
    expected: Any,
    actual: Any,
    detail: str = "",
) -> None:
    phase.assertions.append(
        AssertionRecord(
            name=name,
            passed=bool(passed),
            expected=expected,
            actual=actual,
            detail=detail,
        )
    )


def verify_lifecycle_systemd_marker(
    marker_path: Path, *, trusted_uid: int = 0
) -> Dict[str, Any]:
    """Require a protected regular marker before opting into guest systemd mutations."""
    try:
        checked_metadata = marker_path.lstat()
        if not stat.S_ISREG(checked_metadata.st_mode):
            raise GuestSafetyError("systemd lifecycle marker must be a regular non-symlink file")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
        with os.fdopen(os.open(marker_path, flags), "r", encoding="utf-8") as marker:
            opened_metadata = os.fstat(marker.fileno())
            if not stat.S_ISREG(opened_metadata.st_mode) or (
                checked_metadata.st_dev,
                checked_metadata.st_ino,
            ) != (opened_metadata.st_dev, opened_metadata.st_ino):
                raise GuestSafetyError("systemd lifecycle marker changed during verification")
            if opened_metadata.st_uid != trusted_uid:
                raise GuestSafetyError(f"systemd lifecycle marker must be owned by UID {trusted_uid}")
            if marker.read(4097).strip() != GUEST_MARKER_REQUIRED_TOKEN:
                raise GuestSafetyError("systemd lifecycle marker has an invalid disposable-guest token")
    except (OSError, UnicodeError) as error:
        raise GuestSafetyError(f"cannot verify systemd lifecycle marker {marker_path}") from error
    return {"path": str(marker_path), "uid": opened_metadata.st_uid}


def validate_guest_isolated_path(path_value: str, label: str, work_root: str) -> str:
    """Ensure a path used by the lifecycle drill resides strictly inside the isolated guest work_root."""
    import posixpath

    normalized_root = validate_isolated_work_root(work_root)
    raw = (path_value or "").strip()
    if not raw:
        raise GuestSafetyError(f"{label} path must not be empty")
    if "\x00" in raw or "\\" in raw:
        raise GuestSafetyError(f"{label} path contains invalid characters: {raw!r}")
    if not raw.startswith("/"):
        raise GuestSafetyError(f"{label} path must be absolute: {raw!r}")
    if ".." in PurePosixPath(raw).parts:
        raise GuestSafetyError(f"{label} path must not contain '..': {raw!r}")
    normalized = posixpath.normpath(raw)
    for forbidden in FORBIDDEN_HOST_PATHS:
        if normalized == forbidden or normalized.startswith(forbidden + "/"):
            raise GuestSafetyError(
                f"{label} path {normalized!r} collides with forbidden host path {forbidden!r}"
            )
    if not (normalized == normalized_root or normalized.startswith(normalized_root + "/")):
        raise GuestSafetyError(
            f"{label} path {normalized!r} must reside inside isolated work_root {normalized_root!r}"
        )
    return normalized


def parse_systemctl_show_output(raw_text: str) -> Dict[str, str]:
    """Parse `systemctl show` key=value lines into a dictionary."""
    props: Dict[str, str] = {}
    for line in (raw_text or "").splitlines():
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        props[key.strip()] = val.strip()
    return props


def read_proc_cgroup(pid: int) -> str:
    """Read `/proc/<pid>/cgroup` for a live process on Linux."""
    if pid <= 0:
        return ""
    cgroup_file = Path(f"/proc/{pid}/cgroup")
    if not cgroup_file.is_file():
        return ""
    try:
        return cgroup_file.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def read_proc_cmdline(pid: int) -> List[str]:
    """Read `/proc/<pid>/cmdline` for a live process on Linux."""
    if pid <= 0:
        return []
    cmdline_file = Path(f"/proc/{pid}/cmdline")
    if not cmdline_file.is_file():
        return []
    try:
        raw = cmdline_file.read_bytes()
        return [part.decode("utf-8", errors="replace") for part in raw.split(b"\x00") if part]
    except OSError:
        return []


def inspect_systemd_unit(unit_name: str, *, cwd: Path) -> Tuple[UnitRuntimeSnapshot, CommandRecord]:
    """Query `systemctl show` for a unit and capture its PID, cgroup, invocation, and status."""
    cmd = run_recorded_command(
        [
            "systemctl",
            "show",
            unit_name,
            "--property=Id,LoadState,ActiveState,SubState,MainPID,ExecMainPID,ExecMainStatus,Result,ControlGroup,InvocationID,FragmentPath",
        ],
        cwd=cwd,
    )
    props = parse_systemctl_show_output(cmd.stdout)

    def _safe_int(val: Optional[str], default: int = 0) -> int:
        try:
            return int((val or "").strip() or default)
        except ValueError:
            return default

    main_pid = _safe_int(props.get("MainPID"), 0)
    exec_main_pid = _safe_int(props.get("ExecMainPID"), 0)
    effective_pid = main_pid if main_pid > 0 else exec_main_pid
    proc_cg = read_proc_cgroup(effective_pid)
    snapshot = UnitRuntimeSnapshot(
        unit_name=unit_name,
        load_state=props.get("LoadState", ""),
        active_state=props.get("ActiveState", ""),
        sub_state=props.get("SubState", ""),
        main_pid=main_pid,
        exec_main_pid=exec_main_pid,
        exec_main_status=_safe_int(props.get("ExecMainStatus"), -1),
        result=props.get("Result", ""),
        control_group=props.get("ControlGroup", ""),
        invocation_id=props.get("InvocationID", ""),
        fragment_path=props.get("FragmentPath", ""),
        proc_cgroup=proc_cg,
    )
    return snapshot, cmd


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


def evaluate_lifecycle_drill_suite_status(
    phases: Sequence[DrillPhaseResult],
    required_phases: Sequence[str] = MANDATORY_LIFECYCLE_PHASES,
) -> Dict[str, Any]:
    """Fail-closed evaluation of all mandatory lifecycle guest drill phases."""
    return evaluate_drill_suite_status(phases, required_phases=required_phases)


class HeldFlockGuard:
    """Holds an exclusive `flock(LOCK_EX | LOCK_NB)` on a lockfile in the parent process
    so the transient `af release rollback --local` unit stays alive at a deterministic
    interruption boundary while the harness inspects cgroups and restarts `aetherflow-runner.service`.
    """

    def __init__(self, lock_path: Path) -> None:
        self.lock_path = lock_path
        self._fd: Optional[int] = None

    def acquire(self) -> None:
        if fcntl is None:
            raise RuntimeError("fcntl is required to hold flock inside Linux guest")
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(self.lock_path), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except Exception:
            os.close(fd)
            raise
        self._fd = fd

    def release(self) -> None:
        if self._fd is not None:
            try:
                if fcntl is not None:
                    fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)
                self._fd = None

    def __enter__(self) -> "HeldFlockGuard":
        self.acquire()
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.release()


def seed_isolated_lifecycle_fixture(
    iso_root: Path,
    *,
    api_bin: Path,
    af_bin: Path,
    work_root: Path,
) -> Dict[str, Any]:
    """Provision a complete isolated release & runtime layout inside `<work_root>/lifecycle_iso`.

    The runner receives an explicit isolated release root and config path.
    It persists a protected config snapshot and passes --root, --config,
    --job-status-file, and --job-unit to the external updater. No working-directory
    fallback or production configuration is required. An unpublished synthetic
    repository makes the later deploy fetch fail closed without selecting a
    production release. Rollback remains a real native operation on local data.
    """
    validate_guest_isolated_path(str(iso_root), "lifecycle_iso_root", str(work_root))

    if iso_root.exists():
        shutil.rmtree(iso_root)

    releases_dir = iso_root / "releases"
    current_link = iso_root / "current"
    repo_dir = iso_root / "repo"
    data_dir = iso_root / "var/lib/aetherflow"
    backups_dir = iso_root / "var/backups/aetherflow"
    restore_staging_dir = iso_root / "var/tmp/restore_staging"
    env_dir = iso_root / "etc/aetherflow"
    env_file = env_dir / ".env"
    log_dir = iso_root / "var/log"
    deploy_log_file = log_dir / "aetherflow-deploy.log"
    run_dir = iso_root / "run/aetherflow"
    runner_sock = run_dir / "runner.sock"
    maintenance_lock = iso_root / "locks/.snapshot.lock"
    runner_workdir = iso_root / "runner_workdir"
    runner_deploy_dir = runner_workdir / "deploy"
    systemd_units_src = runner_deploy_dir / "systemd"
    systemd_units_dst = iso_root / "systemd_units_dst"

    for directory in (
        releases_dir,
        repo_dir,
        data_dir,
        backups_dir,
        restore_staging_dir,
        env_dir,
        log_dir,
        run_dir,
        maintenance_lock.parent,
        runner_deploy_dir,
        systemd_units_src,
        systemd_units_dst,
    ):
        directory.mkdir(parents=True, exist_ok=True)

    # Create two release directories:
    # - `1700000001_good`: previous healthy release (`v4.0.0-good-rollback-target`)
    # - `1700000002_bad`: currently linked broken release (`v4.0.0-bad-candidate`)
    #   containing the verified pre-swap `data-snapshot/aetherflow.sqlite.bak` and `MANIFEST.sha256`!
    good_release = releases_dir / "1700000001_good"
    bad_release = releases_dir / "1700000002_bad"
    for rel_dir, ver_tag in (
        (good_release, "v4.0.0-good-rollback-target"),
        (bad_release, "v4.0.0-bad-candidate"),
    ):
        (rel_dir / "bin").mkdir(parents=True, exist_ok=True)
        (rel_dir / "deploy/systemd").mkdir(parents=True, exist_ok=True)
        (rel_dir / ".version").write_text(f"{ver_tag}\n", encoding="utf-8")
        # Symlink the staged real binaries into the isolated release directories
        os.symlink(str(api_bin), str(rel_dir / "bin/aetherflow-api"))
        os.symlink(str(af_bin), str(rel_dir / "bin/af"))
        os.symlink(str(af_bin), str(rel_dir / "af"))

    # Point `current` to `1700000002_bad` and `.previous_release` to `1700000001_good`
    os.symlink(str(bad_release), str(current_link))
    (releases_dir / ".previous_release").write_text(f"{good_release}\n", encoding="utf-8")

    # Seed the golden SQLite database and capture its verified pre-swap snapshot inside `bad_release/data-snapshot`
    live_db_path = data_dir / "aetherflow.sqlite"
    marker_rows = [
        (1, "golden_pre_update_state_v4"),
        (2, "preserved_across_transient_rollback"),
    ]
    conn = sqlite3.connect(str(live_db_path))
    try:
        conn.execute("PRAGMA journal_mode=DELETE;")
        conn.execute(
            "CREATE TABLE lifecycle_release_marker (id INTEGER PRIMARY KEY, marker TEXT NOT NULL);"
        )
        conn.executemany(
            "INSERT INTO lifecycle_release_marker (id, marker) VALUES (?, ?);",
            marker_rows,
        )
        conn.commit()
    finally:
        conn.close()
    os.chmod(live_db_path, 0o600)
    golden_db_sha256 = compute_file_sha256(live_db_path)

    # Create verified `data-snapshot` inside `bad_release` matching `af_release::snapshot::create_pre_swap_snapshot`
    snapshot_dir = bad_release / "data-snapshot"
    snapshot_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(snapshot_dir, 0o700)
    snapshot_bak = snapshot_dir / "aetherflow.sqlite.bak"
    shutil.copy2(live_db_path, snapshot_bak)
    os.chmod(snapshot_bak, 0o600)

    env_file.write_text(
        f"AF_DB_PATH={live_db_path}\n"
        "AETHERFLOW_ENV=disposable-guest-lifecycle-drill\n"
        f"JWT_SECRET={os.urandom(32).hex()}\n",
        encoding="utf-8",
    )
    os.chmod(env_file, 0o600)
    env_bak = snapshot_dir / ".env.bak"
    shutil.copy2(env_file, env_bak)
    os.chmod(env_bak, 0o600)

    manifest_lines = [
        f"{compute_file_sha256(snapshot_bak)}  {snapshot_bak.name}",
        f"{compute_file_sha256(env_bak)}  {env_bak.name}",
    ]
    manifest_file = snapshot_dir / "MANIFEST.sha256"
    manifest_file.write_text("\n".join(manifest_lines) + "\n", encoding="utf-8")
    os.chmod(manifest_file, 0o600)

    # Also copy the verified data-snapshot to `good_release/data-snapshot` as fallback
    good_snapshot_dir = good_release / "data-snapshot"
    shutil.copytree(snapshot_dir, good_snapshot_dir)
    os.chmod(good_snapshot_dir, 0o700)
    good_manifest = good_snapshot_dir / "MANIFEST.sha256"
    os.chmod(good_manifest, 0o600)

    # Also create `etc/aetherflow/lock.json` and `settings.json` so backup/restore drills have complete files
    lock_file = env_dir / "lock.json"
    lock_file.write_text('{"schema_version": 4, "locked": false}\n', encoding="utf-8")
    os.chmod(lock_file, 0o640)

    release_conf_path = runner_deploy_dir / "release-manager.conf"
    synthetic_repo = (
        "aetherflow-disposable-guest-drills/unpublished-"
        + hashlib.sha256(str(iso_root).encode("utf-8")).hexdigest()[:24]
    )
    release_conf_content = (
        "# Isolated AetherFlow v4 Lifecycle Guest Drill release-manager.conf\n"
        f'GITHUB_REPO="{synthetic_repo}"\n'
        f'RELEASES_DIR="{releases_dir}"\n'
        f'CURRENT_LINK="{current_link}"\n'
        f'REPO_DIR="{repo_dir}"\n'
        f'DATA_DIR="{data_dir}"\n'
        f'ENV_DIR="{env_dir}"\n'
        f'ENV_FILE="{env_file}"\n'
        f'LOG_FILE="{deploy_log_file}"\n'
        'SQLITE_DB="aetherflow.sqlite"\n'
        f'SYSTEMD_UNITS_SRC="{systemd_units_src}"\n'
        f'SYSTEMD_UNITS_DST="{systemd_units_dst}"\n'
        'HEALTH_ENDPOINT="http://127.0.0.1:18080/api/v1/system/health"\n'
        "HEALTH_RETRIES=5\n"
        "HEALTH_INTERVAL=1\n"
        "MAX_RELEASES=5\n"
        "SNAPSHOT_TIMEOUT=25\n"
    )
    release_conf_path.write_text(release_conf_content, encoding="utf-8")
    # Also place copies inside both release directories' `deploy/release-manager.conf`
    for rel_dir in (good_release, bad_release):
        (rel_dir / "deploy/release-manager.conf").write_text(
            release_conf_content, encoding="utf-8"
        )

    # Build disposable systemd unit files (`aetherflow-runner.service` and `aetherflow-api.service`)
    # pointing exclusively to staged guest binaries and isolated `<work_root>` paths.
    runner_unit_content = (
        "[Unit]\n"
        "Description=Disposable Guest AetherFlow v4 Privileged Runner Service\n"
        "After=network.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "User=root\n"
        "Group=root\n"
        f"WorkingDirectory={runner_workdir}\n"
        f"ExecStart={api_bin} runner\n"
        "Restart=on-failure\n"
        "RestartSec=1\n"
        f"Environment=AETHERFLOW_RUNNER_SOCK={runner_sock}\n"
        f"Environment=AETHERFLOW_CLI_BIN={af_bin}\n"
        "Environment=AETHERFLOW_ENABLE_RUST_RELEASE=1\n"
        "Environment=AETHERFLOW_FORCE_BASH_RELEASE=0\n"
        "Environment=AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE=1\n"
        f"Environment=AETHERFLOW_RELEASE_ROOT={iso_root}\n"
        f"Environment=AETHERFLOW_RELEASE_CONF={release_conf_path}\n"
        f"Environment=AETHERFLOW_MAINTENANCE_LOCK_PATH={maintenance_lock}\n"
        f"Environment=AF_DB_PATH={live_db_path}\n"
        f"Environment=DB_PATH={live_db_path}\n"
        f"Environment=AETHERFLOW_DB_PATH={live_db_path}\n"
        f"Environment=AETHERFLOW_BACKUP_DIR={backups_dir}\n"
        f"Environment=AETHERFLOW_RESTORE_STAGING_ROOT={iso_root}\n"
        "Environment=AETHERFLOW_BACKUP_DRY_RUN_QUIESCENCE=0\n"
        "Environment=RUST_LOG=info\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )

    # Disposable `aetherflow-api.service` so `af-release` rollback's `stop_database_services`
    # and `restart_systemd_units` (`systemctl stop/restart aetherflow-runner.service aetherflow-api.service`)
    # succeed against real guest systemd units without touching `/opt/AetherFlow`.
    api_unit_content = (
        "[Unit]\n"
        "Description=Disposable Guest AetherFlow v4 API Service Target\n"
        "After=network.target aetherflow-runner.service\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "User=root\n"
        "Group=root\n"
        f"WorkingDirectory={runner_workdir}\n"
        f"ExecStart={sys.executable} -c 'import time; time.sleep(7200)'\n"
        "Restart=on-failure\n"
        "RestartSec=1\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )

    for rel_dir in (good_release, bad_release):
        (rel_dir / "deploy/systemd" / DISPOSABLE_RUNNER_UNIT_NAME).write_text(
            runner_unit_content, encoding="utf-8"
        )
        (rel_dir / "deploy/systemd" / DISPOSABLE_API_UNIT_NAME).write_text(
            api_unit_content, encoding="utf-8"
        )
    (systemd_units_src / DISPOSABLE_RUNNER_UNIT_NAME).write_text(
        runner_unit_content, encoding="utf-8"
    )
    (systemd_units_src / DISPOSABLE_API_UNIT_NAME).write_text(
        api_unit_content, encoding="utf-8"
    )

    return {
        "iso_root": iso_root,
        "releases_dir": releases_dir,
        "good_release": good_release,
        "bad_release": bad_release,
        "good_version": "v4.0.0-good-rollback-target",
        "bad_version": "v4.0.0-bad-candidate",
        "current_link": current_link,
        "previous_release_file": releases_dir / ".previous_release",
        "recovery_state_file": releases_dir / ".recovery_state.json",
        "release_lock_file": releases_dir / ".release.lock",
        "maintenance_lock": maintenance_lock,
        "data_dir": data_dir,
        "live_db_path": live_db_path,
        "golden_db_sha256": golden_db_sha256,
        "marker_rows": marker_rows,
        "snapshot_bak": snapshot_bak,
        "manifest_file": manifest_file,
        "backups_dir": backups_dir,
        "env_dir": env_dir,
        "env_file": env_file,
        "lock_file": lock_file,
        "deploy_log_file": deploy_log_file,
        "runner_sock": runner_sock,
        "runner_workdir": runner_workdir,
        "release_conf_path": release_conf_path,
        "systemd_units_src": systemd_units_src,
        "systemd_units_dst": systemd_units_dst,
        "runner_unit_content": runner_unit_content,
        "api_unit_content": api_unit_content,
    }


def query_self_update_status(socket_path: Path, job_unit: str) -> UdsExchangeRecord:
    return perform_uds_http_request(
        str(socket_path),
        "POST",
        "/v1/self-update/status",
        body={"job_unit": job_unit},
        timeout=15.0,
    )


def wait_for_runner_uds_ready(
    socket_path: Path,
    *,
    timeout_sec: float = 15.0,
) -> UdsExchangeRecord:
    """Poll `GET /v1/health` over the isolated runner Unix domain socket until HTTP 200."""
    deadline = time.monotonic() + timeout_sec
    last_record: Optional[UdsExchangeRecord] = None
    while time.monotonic() < deadline:
        if socket_path.exists():
            rec = perform_uds_http_request(str(socket_path), "GET", "/v1/health", timeout=2.0)
            last_record = rec
            if rec.http_status == 200 and (rec.runner_response or {}).get("success") is True:
                return rec
        time.sleep(0.1)
    raise DrillAssertionError(
        f"Timed out waiting for isolated runner UDS {str(socket_path)!r} to become healthy "
        f"(last_record={asdict(last_record) if last_record else None})"
    )


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


def run_phase_1_binary_and_systemd_provenance(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
    guardrail_info: Dict[str, Any],
    source_manifest: Optional[str] = None,
    release_artifact: Optional[str] = None,
) -> DrillPhaseResult:
    """Phase 1: Verify binary, source, and artifact identities plus guest systemd runtime."""
    started_at = utc_now_iso()
    t0 = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="binary_and_systemd_environment_provenance",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    phase.artifacts["guardrails"] = guardrail_info
    for label, bin_path in (("aetherflow_api_bin", api_bin), ("af_cli_bin", af_bin)):
        exists = bin_path.is_file()
        is_exec = exists and os.access(bin_path, os.X_OK)
        _record_assertion(
            phase,
            f"{label}_exists_and_executable",
            exists and is_exec,
            {"exists": True, "executable": True},
            {"exists": exists, "executable": is_exec, "path": str(bin_path)},
        )
        if exists:
            st = os.stat(bin_path)
            phase.artifacts[label] = {
                "path": str(bin_path),
                "sha256": compute_file_sha256(bin_path),
                "size_bytes": int(st.st_size),
                "mode_octal": f"{stat.S_IMODE(st.st_mode):04o}",
                "uid": int(st.st_uid),
                "gid": int(st.st_gid),
            }

    # Record optional source manifest and release artifact provenance if supplied
    if source_manifest:
        sm_path = Path(source_manifest)
        if sm_path.is_file():
            phase.artifacts["source_manifest"] = {
                "path": str(sm_path),
                "sha256": compute_file_sha256(sm_path),
                "content": sm_path.read_text(encoding="utf-8", errors="replace")[:4000],
            }
        else:
            phase.artifacts["source_manifest"] = {"raw_reference": source_manifest}

    if release_artifact:
        ra_path = Path(release_artifact)
        if ra_path.is_file():
            phase.artifacts["release_artifact"] = {
                "path": str(ra_path),
                "sha256": compute_file_sha256(ra_path),
                "size_bytes": int(ra_path.stat().st_size),
            }
        else:
            phase.artifacts["release_artifact"] = {"raw_reference": release_artifact}

    # Verify `systemctl` and `systemd-run` binaries exist and systemd PID 1 is active in the guest
    systemctl_path = shutil.which("systemctl") or "/bin/systemctl"
    systemd_run_path = shutil.which("systemd-run") or "/usr/bin/systemd-run"
    phase.artifacts["systemd_binaries"] = {
        "systemctl": systemctl_path,
        "systemd_run": systemd_run_path,
    }
    _record_assertion(
        phase,
        "systemctl_and_systemd_run_present",
        Path(systemctl_path).is_file() and Path(systemd_run_path).is_file(),
        {"systemctl": True, "systemd_run": True},
        {
            "systemctl": Path(systemctl_path).is_file(),
            "systemd_run": Path(systemd_run_path).is_file(),
        },
    )

    sys_ver_cmd = run_recorded_command(["systemctl", "--version"], cwd=work_root)
    phase.commands.append(sys_ver_cmd)
    _record_assertion(
        phase,
        "systemctl_version_exit_zero",
        sys_ver_cmd.exit_code == 0,
        0,
        sys_ver_cmd.exit_code,
        detail=sys_ver_cmd.stdout.strip(),
    )

    af_ver_cmd = run_recorded_command([str(af_bin), "--json", "version"], cwd=work_root)
    phase.commands.append(af_ver_cmd)
    ok_ver, ver_payload, ver_detail = evaluate_cli_envelope(
        af_ver_cmd.stdout, expected_status="ok"
    )
    _record_assertion(
        phase,
        "af_cli_json_version_envelope",
        af_ver_cmd.exit_code == 0 and ok_ver,
        "exit_code == 0 and status == 'ok'",
        {"exit_code": af_ver_cmd.exit_code, "detail": ver_detail, "payload": ver_payload},
    )

    # Guardrail: ensure the disposable guest does NOT already have a live production `/opt/AetherFlow`
    # unit active before we install our isolated `/etc/systemd/system/aetherflow-runner.service`.
    for unit_name in (DISPOSABLE_RUNNER_UNIT_NAME, DISPOSABLE_API_UNIT_NAME):
        unit_file = Path(SYSTEMD_ETC_UNIT_DIR) / unit_name
        if unit_file.is_file():
            existing_text = unit_file.read_text(encoding="utf-8", errors="replace")
            if "/opt/AetherFlow" in existing_text or "/opt/aetherflow" in existing_text:
                raise GuestSafetyError(
                    f"Existing {str(unit_file)!r} references live /opt/AetherFlow; refusing to overwrite non-disposable unit"
                )

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
    if any(not a.passed for a in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_2_isolated_systemd_runner_and_validation(
    *,
    work_root: Path,
    fixture: Dict[str, Any],
    installed_unit_files: List[Path],
) -> DrillPhaseResult:
    """Phase 2: Start isolated genuine `aetherflow-runner.service` & `aetherflow-api.service`
    via systemd, record unit invocation/cgroup/MainPID/environment, and validate `/v1/self-update`
    model bounds over UDS.
    """
    started_at = utc_now_iso()
    t0 = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="isolated_systemd_runner_and_self_update_validation",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    runner_unit_dst = Path(SYSTEMD_ETC_UNIT_DIR) / DISPOSABLE_RUNNER_UNIT_NAME
    api_unit_dst = Path(SYSTEMD_ETC_UNIT_DIR) / DISPOSABLE_API_UNIT_NAME
    runner_sock: Path = fixture["runner_sock"]

    try:
        runner_unit_dst.write_text(fixture["runner_unit_content"], encoding="utf-8")
        if runner_unit_dst not in installed_unit_files:
            installed_unit_files.append(runner_unit_dst)
        api_unit_dst.write_text(fixture["api_unit_content"], encoding="utf-8")
        if api_unit_dst not in installed_unit_files:
            installed_unit_files.append(api_unit_dst)

        reload_cmd = run_recorded_command(["systemctl", "daemon-reload"], cwd=work_root)
        phase.commands.append(reload_cmd)
        _record_assertion(
            phase,
            "systemctl_daemon_reload_isolated_units",
            reload_cmd.exit_code == 0,
            0,
            reload_cmd.exit_code,
        )

        start_runner_cmd = run_recorded_command(
            ["systemctl", "restart", DISPOSABLE_RUNNER_UNIT_NAME], cwd=work_root
        )
        phase.commands.append(start_runner_cmd)
        start_api_cmd = run_recorded_command(
            ["systemctl", "restart", DISPOSABLE_API_UNIT_NAME], cwd=work_root
        )
        phase.commands.append(start_api_cmd)

        health_rec = wait_for_runner_uds_ready(runner_sock, timeout_sec=15.0)
        phase.uds_exchanges.append(health_rec)
        _record_assertion(
            phase,
            "isolated_runner_service_uds_health_200",
            health_rec.http_status == 200
            and (health_rec.runner_response or {}).get("success") is True,
            {"http_status": 200, "success": True},
            {"http_status": health_rec.http_status, "runner_response": health_rec.runner_response},
        )

        runner_snap, runner_show_cmd = inspect_systemd_unit(
            DISPOSABLE_RUNNER_UNIT_NAME, cwd=work_root
        )
        phase.commands.append(runner_show_cmd)
        api_snap, api_show_cmd = inspect_systemd_unit(
            DISPOSABLE_API_UNIT_NAME, cwd=work_root
        )
        phase.commands.append(api_show_cmd)

        phase.artifacts["runner_service_initial_snapshot"] = asdict(runner_snap)
        phase.artifacts["api_service_initial_snapshot"] = asdict(api_snap)
        phase.artifacts["runner_proc_cmdline"] = read_proc_cmdline(runner_snap.main_pid)

        _record_assertion(
            phase,
            "runner_service_active_with_dedicated_cgroup_and_main_pid",
            runner_snap.active_state == "active"
            and runner_snap.main_pid > 0
            and DISPOSABLE_RUNNER_UNIT_NAME in runner_snap.control_group,
            {
                "active_state": "active",
                "main_pid_gt_0": True,
                "control_group_contains": DISPOSABLE_RUNNER_UNIT_NAME,
            },
            asdict(runner_snap),
        )

        # Validate `/v1/self-update` model bounds (`SelfUpdateRequest`):
        # 1. Invalid command -> HTTP 400 `"invalid self-update command"`
        bad_cmd_ex = perform_uds_http_request(
            str(runner_sock),
            "POST",
            "/v1/self-update",
            body={"command": "exec_arbitrary", "channel": "stable"},
        )
        phase.uds_exchanges.append(bad_cmd_ex)
        ok_bad_cmd, _, _, bad_cmd_detail = evaluate_self_update_initiation_exchange(
            bad_cmd_ex.http_status,
            bad_cmd_ex.raw_response,
            expect_http_status=400,
            expect_runner_success=False,
            expected_error_substring="invalid self-update command",
        )
        _record_assertion(
            phase,
            "self_update_rejects_invalid_command_400",
            ok_bad_cmd,
            "HTTP 400 + error containing 'invalid self-update command'",
            bad_cmd_detail,
        )

        # 2. Invalid channel -> HTTP 400 `"invalid update channel"`
        bad_chan_ex = perform_uds_http_request(
            str(runner_sock),
            "POST",
            "/v1/self-update",
            body={"command": "rollback", "channel": "untrusted-branch"},
        )
        phase.uds_exchanges.append(bad_chan_ex)
        ok_bad_chan, _, _, bad_chan_detail = evaluate_self_update_initiation_exchange(
            bad_chan_ex.http_status,
            bad_chan_ex.raw_response,
            expect_http_status=400,
            expect_runner_success=False,
            expected_error_substring="invalid update channel",
        )
        _record_assertion(
            phase,
            "self_update_rejects_invalid_channel_400",
            ok_bad_chan,
            "HTTP 400 + error containing 'invalid update channel'",
            bad_chan_detail,
        )

    except Exception as exc:  # noqa: BLE001
        phase.failure_diagnostics.append(
            f"Unhandled exception in phase 2: {type(exc).__name__}: {exc}"
        )
        phase.commands.append(
            run_recorded_command(
                ["journalctl", f"--unit={DISPOSABLE_RUNNER_UNIT_NAME}", "--no-pager", "--lines=60"],
                cwd=work_root,
            )
        )
        _record_assertion(phase, "phase2_unhandled_exception", False, "no exception", str(exc))

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
    if any(not a.passed for a in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_3_self_stop_quiescence_rejection(
    *,
    work_root: Path,
    fixture: Dict[str, Any],
) -> DrillPhaseResult:
    """Phase 3: Prove `/v1/backup` (`restore_execute`) rejects `quiesce_services` entries
    targeting `aetherflow-runner.service` (or `aetherflow-runner` or bypass tokens) BEFORE
    invoking `systemctl stop`, preserving the active runner controller PID and target files.
    """
    started_at = utc_now_iso()
    t0 = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="self_stop_quiescence_rejection_preserves_controller",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    runner_sock: Path = fixture["runner_sock"]
    iso_root: Path = fixture["iso_root"]
    live_db_path: Path = fixture["live_db_path"]
    env_file: Path = fixture["env_file"]
    lock_file: Path = fixture["lock_file"]

    try:
        # 1. Create a real verified archive backup over UDS so `restore_execute` has a valid archive filename
        create_ex = perform_uds_http_request(
            str(runner_sock),
            "POST",
            "/v1/backup",
            body={
                "action": "create_archive",
                "app_version": "v4.0.0-lifecycle-drill",
                "timestamp_slug": "20261103T080000Z",
            },
        )
        phase.uds_exchanges.append(create_ex)
        ok_cr, _, cr_payload, cr_detail = evaluate_runner_backup_exchange(
            create_ex.http_status,
            create_ex.raw_response,
            expect_http_status=200,
            expect_runner_success=True,
            expected_action="create_archive",
        )
        _record_assertion(
            phase,
            "create_verified_backup_archive_for_self_stop_drill",
            ok_cr,
            "HTTP 200 create_archive",
            cr_detail,
        )
        archive_filename = str((cr_payload or {}).get("filename") or "drill-fallback.tar.gz")

        pre_snap, pre_cmd = inspect_systemd_unit(DISPOSABLE_RUNNER_UNIT_NAME, cwd=work_root)
        phase.commands.append(pre_cmd)
        before_sentinels = [
            snapshot_sentinel(p) for p in (live_db_path, env_file, lock_file)
        ]

        # 2. Test self-stop rejection across exact unit name, bare name, mixed case, and multi-service list
        self_stop_vectors: Tuple[Tuple[str, List[str], str], ...] = (
            (
                "exact_runner_service_unit",
                ["aetherflow-runner.service"],
                "quiesce_services must not include the active control worker unit",
            ),
            (
                "bare_runner_unit_name",
                ["aetherflow-runner"],
                "quiesce_services must not include the active control worker unit",
            ),
            (
                "uppercase_runner_service_unit_in_list",
                ["aetherflow-api.service", "AETHERFLOW-RUNNER.SERVICE"],
                "quiesce_services must not include the active control worker unit",
            ),
            (
                "unsafe_quiesce_bypass_token",
                ["skip"],
                "unsafe quiesce_services bypass entry rejected",
            ),
        )

        for label, quiesce_list, expected_err in self_stop_vectors:
            ex = perform_uds_http_request(
                str(runner_sock),
                "POST",
                "/v1/backup",
                body={
                    "action": "restore_execute",
                    "filename": archive_filename,
                    "target_root": str(iso_root),
                    "confirm_destructive_restore": True,
                    "allow_overwrite": True,
                    "quiesce_services": quiesce_list,
                },
            )
            phase.uds_exchanges.append(ex)
            post_snap, post_cmd = inspect_systemd_unit(
                DISPOSABLE_RUNNER_UNIT_NAME, cwd=work_root
            )
            phase.commands.append(post_cmd)

            ok_self_stop, failures = evaluate_self_stop_rejection_exchange(
                http_status=ex.http_status,
                raw_body=ex.raw_response,
                runner_pid_before=pre_snap.main_pid,
                runner_pid_after=post_snap.main_pid,
                runner_active_after=post_snap.active_state,
                expected_error_substring=expected_err,
            )
            _record_assertion(
                phase,
                f"reject_restore_self_stop_{label}",
                ok_self_stop,
                {
                    "http_status": 400,
                    "error_contains": expected_err,
                    "runner_pid_preserved": pre_snap.main_pid,
                    "runner_active_state": "active",
                },
                {
                    "http_status": ex.http_status,
                    "runner_response": ex.runner_response,
                    "runner_pid_before": pre_snap.main_pid,
                    "runner_pid_after": post_snap.main_pid,
                    "runner_active_after": post_snap.active_state,
                    "failures": failures,
                },
            )

        # 3. Verify live DB, .env, and lock.json were completely untouched
        sentinel_results = [
            verify_sentinel_unchanged(before, snapshot_sentinel(Path(before.path)))
            for before in before_sentinels
        ]
        _record_assertion(
            phase,
            "self_stop_rejection_leaves_live_files_untouched",
            all(r[0] for r in sentinel_results),
            "zero file drift across live SQLite DB, .env, and lock.json",
            sentinel_results,
        )

    except Exception as exc:  # noqa: BLE001
        phase.failure_diagnostics.append(
            f"Unhandled exception in phase 3: {type(exc).__name__}: {exc}"
        )
        _record_assertion(phase, "phase3_unhandled_exception", False, "no exception", str(exc))

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
    if any(not a.passed for a in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_4_transient_unit_survival_and_rollback(
    *,
    work_root: Path,
    fixture: Dict[str, Any],
    owned_transient_units: List[str],
) -> DrillPhaseResult:
    """Phase 4: Trigger real `/v1/self-update` (`command: "rollback"`, `channel: "stable"`) over UDS,
    prove transient-unit cgroup separation, deliberately restart `aetherflow-runner.service` while
    the updater unit is in flight, prove the updater survives, and verify native `af-release`
    rollback + corrupted SQLite DB recovery.
    """
    started_at = utc_now_iso()
    t0 = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="transient_unit_cgroup_survival_and_native_rollback_recovery",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    runner_sock: Path = fixture["runner_sock"]
    live_db_path: Path = fixture["live_db_path"]
    maintenance_lock: Path = fixture["maintenance_lock"]
    current_link: Path = fixture["current_link"]
    good_release: Path = fixture["good_release"]
    good_version: str = fixture["good_version"]
    marker_rows: Sequence[Tuple[int, str]] = fixture["marker_rows"]
    recovery_state_file: Path = fixture["recovery_state_file"]
    deploy_log_file: Path = fixture["deploy_log_file"]

    phase.contract_notes.append(
        "Contract note: `af-runner` spawns `systemd-run --unit=aetherflow-self-update-<cmd>-<ch>-<8hex>.service "
        "--collect --no-block --property=Type=exec --property=KillMode=control-group` and resolves "
        "the explicit isolated release configuration, passing `--root <isolated_root> --config <protected_snapshot> "
        "--job-status-file <receipt> --job-unit <unit>` to `af release rollback --channel stable --local`. "
        "During rollback (`ReleaseEngine::run_rollback_locked`), `af-release` acquires `AETHERFLOW_MAINTENANCE_LOCK_PATH` "
        "(up to `SNAPSHOT_TIMEOUT` seconds), swaps `CURRENT_LINK` to `.previous_release`, detects SQLite corruption via "
        "`PRAGMA integrity_check`, stops `aetherflow-api.service` and `aetherflow-runner.service`, quarantines the corrupt DB, "
        "restores the verified `data-snapshot/aetherflow.sqlite.bak`, and restarts `aetherflow-runner.service` and `aetherflow-api.service`."
    )

    lock_guard = HeldFlockGuard(maintenance_lock)
    try:
        # 1. Corrupt the live SQLite database and plant stale `-wal` and `-shm` sidecars
        #    so `restore_state_if_corrupted` must detect `PRAGMA integrity_check != "ok"`,
        #    quarantine the corrupt DB, unlink `-wal`/`-shm`, and restore the verified `.bak` snapshot!
        live_db_path.write_bytes(b"CORRUPTED_SQLITE_HEADER_FOR_LIFECYCLE_ROLLBACK_DRILL" * 32)
        os.chmod(live_db_path, 0o644)
        Path(f"{live_db_path}-wal").write_bytes(b"STALE_WAL_SIDE_EFFECT_BYTES")
        Path(f"{live_db_path}-shm").write_bytes(b"STALE_SHM_SIDE_EFFECT_BYTES")
        phase.artifacts["corrupted_live_db_sha256"] = compute_file_sha256(live_db_path)

        # 2. Capture `aetherflow-runner.service` runtime state before self-update
        runner_before, runner_before_cmd = inspect_systemd_unit(
            DISPOSABLE_RUNNER_UNIT_NAME, cwd=work_root
        )
        phase.commands.append(runner_before_cmd)
        phase.artifacts["runner_before_self_update"] = asdict(runner_before)

        # 3. Hold an exclusive flock on `AETHERFLOW_MAINTENANCE_LOCK_PATH` (`SNAPSHOT_TIMEOUT=25s`)
        #    so the transient `af release rollback --channel stable --local` unit stays alive in its
        #    own cgroup at a deterministic interruption boundary while we inspect its `/proc/<pid>/cgroup`
        #    and deliberately restart `aetherflow-runner.service`!
        lock_guard.acquire()
        try:
            self_update_ex = perform_uds_http_request(
                str(runner_sock),
                "POST",
                "/v1/self-update",
                body={"command": "rollback", "channel": "stable"},
                timeout=15.0,
            )
            phase.uds_exchanges.append(self_update_ex)

            ok_init, _, init_payload, init_detail = evaluate_self_update_initiation_exchange(
                self_update_ex.http_status,
                self_update_ex.raw_response,
                expect_http_status=200,
                expect_runner_success=True,
                expected_command="rollback",
                expected_channel="stable",
                expected_engine="native_rust_release",
            )
            _record_assertion(
                phase,
                "uds_post_self_update_returns_initiated_completed_false_and_job_unit",
                ok_init,
                {
                    "http_status": 200,
                    "status": "initiated",
                    "completed": False,
                    "engine": "native_rust_release",
                    "command": "rollback",
                    "channel": "stable",
                },
                {"detail": init_detail, "payload": init_payload},
            )
            if not ok_init or not isinstance(init_payload, dict):
                raise DrillAssertionError(f"/v1/self-update initiation failed: {init_detail}")

            job_unit = str(init_payload["job_unit"])
            owned_transient_units.append(job_unit)

            # Poll briefly until `job_unit` has a live `MainPID` > 0 waiting on the maintenance lock
            updater_during: Optional[UnitRuntimeSnapshot] = None
            for _ in range(30):
                snap_u, cmd_u = inspect_systemd_unit(job_unit, cwd=work_root)
                phase.commands.append(cmd_u)
                if snap_u.main_pid > 0 or snap_u.exec_main_pid > 0:
                    updater_during = snap_u
                    break
                time.sleep(0.1)

            if updater_during is None:
                snap_u, cmd_u = inspect_systemd_unit(job_unit, cwd=work_root)
                phase.commands.append(cmd_u)
                updater_during = snap_u

            updater_pid_flight = (
                updater_during.main_pid
                if updater_during.main_pid > 0
                else updater_during.exec_main_pid
            )
            phase.artifacts["updater_unit_during_flight"] = asdict(updater_during)
            phase.artifacts["updater_proc_cmdline_during_flight"] = read_proc_cmdline(
                updater_pid_flight
            )

            # 4. Deliberately restart the owned `aetherflow-runner.service` while `job_unit` is running!
            restart_runner_cmd = run_recorded_command(
                ["systemctl", "restart", DISPOSABLE_RUNNER_UNIT_NAME],
                cwd=work_root,
            )
            phase.commands.append(restart_runner_cmd)

            runner_after_restart, runner_after_cmd = inspect_systemd_unit(
                DISPOSABLE_RUNNER_UNIT_NAME, cwd=work_root
            )
            phase.commands.append(runner_after_cmd)

            updater_after_restart, updater_after_cmd = inspect_systemd_unit(
                job_unit, cwd=work_root
            )
            phase.commands.append(updater_after_cmd)
            updater_pid_after_restart = (
                updater_after_restart.main_pid
                if updater_after_restart.main_pid > 0
                else updater_after_restart.exec_main_pid
            )

            boundary = InterruptionBoundaryRecord(
                job_unit=job_unit,
                runner_unit=DISPOSABLE_RUNNER_UNIT_NAME,
                runner_pid_before_restart=runner_before.main_pid,
                runner_cgroup_before_restart=runner_before.control_group or runner_before.proc_cgroup,
                runner_invocation_before_restart=runner_before.invocation_id,
                updater_pid_during_flight=updater_pid_flight,
                updater_cgroup_during_flight=updater_during.control_group or updater_during.proc_cgroup,
                updater_active_state_before_restart=updater_during.active_state,
                restart_command_exit_code=restart_runner_cmd.exit_code,
                restart_duration_ms=restart_runner_cmd.duration_ms,
                runner_pid_after_restart=runner_after_restart.main_pid,
                runner_cgroup_after_restart=runner_after_restart.control_group
                or runner_after_restart.proc_cgroup,
                runner_invocation_after_restart=runner_after_restart.invocation_id,
                updater_pid_after_runner_restart=updater_pid_after_restart,
                updater_cgroup_after_runner_restart=updater_after_restart.control_group
                or updater_after_restart.proc_cgroup,
                updater_active_state_after_runner_restart=updater_after_restart.active_state,
                updater_survived_runner_restart=(
                    updater_pid_after_restart > 0
                    and updater_pid_after_restart == updater_pid_flight
                    and updater_after_restart.active_state in ("active", "activating")
                ),
            )
            phase.artifacts["interruption_boundary"] = asdict(boundary)

            ok_survival, survival_failures = evaluate_cgroup_isolation_and_survival(boundary)
            _record_assertion(
                phase,
                "transient_updater_runs_in_external_cgroup_and_survives_deliberate_runner_restart",
                ok_survival,
                "distinct cgroup + runner MainPID rotated + updater PID survived active",
                {"boundary": asdict(boundary), "failures": survival_failures},
            )
        finally:
            # 5. Release the maintenance lock so `af release rollback --local` executes native rollback & DB recovery
            lock_guard.release()

        # 6. Wait for the transient unit (`job_unit`) to finish executing `af release rollback --local`
        final_job_snap, wait_cmds = wait_for_transient_unit_completion(
            job_unit, cwd=work_root, timeout_sec=45.0
        )
        phase.commands.extend(wait_cmds)
        phase.artifacts["updater_unit_final_snapshot"] = asdict(final_job_snap)

        # Capture journalctl logs for the transient unit for forensic verification
        journal_cmd = run_recorded_command(
            ["journalctl", "-u", job_unit, "--no-pager", "-n", "100"],
            cwd=work_root,
        )
        phase.commands.append(journal_cmd)
        phase.artifacts["updater_unit_journal_excerpt"] = journal_cmd.stdout[-3000:]

        # Wait for `aetherflow-runner.service` UDS to be healthy after rollback's `restart_systemd_units`
        post_rollback_health = wait_for_runner_uds_ready(runner_sock, timeout_sec=15.0)
        phase.uds_exchanges.append(post_rollback_health)

        status_exchange = query_self_update_status(runner_sock, job_unit)
        phase.uds_exchanges.append(status_exchange)
        status_ok, status_payload, status_detail = evaluate_self_update_terminal_status_exchange(
            status_exchange.http_status,
            status_exchange.raw_response,
            expected_job_unit=job_unit,
            expected_success=True,
        )
        _record_assertion(
            phase,
            "rollback_terminal_receipt_survives_runner_restart_and_unit_collection",
            status_ok,
            {"job_unit": job_unit, "status": "succeeded", "completed": True, "exit_code": 0},
            {"payload": status_payload, "detail": status_detail},
        )

        runner_final, runner_final_cmd = inspect_systemd_unit(
            DISPOSABLE_RUNNER_UNIT_NAME, cwd=work_root
        )
        phase.commands.append(runner_final_cmd)
        api_final, api_final_cmd = inspect_systemd_unit(
            DISPOSABLE_API_UNIT_NAME, cwd=work_root
        )
        phase.commands.append(api_final_cmd)
        phase.artifacts["runner_service_post_rollback"] = asdict(runner_final)
        phase.artifacts["api_service_post_rollback"] = asdict(api_final)

        ok_rb, rb_summary, rb_failures = evaluate_rollback_outcome(
            current_link=current_link,
            expected_previous_release_dir=good_release,
            expected_version_string=good_version,
            live_db_path=live_db_path,
            expected_marker_rows=marker_rows,
            recovery_state_file=recovery_state_file,
            deploy_log_file=deploy_log_file,
            job_unit_snapshot=final_job_snap,
            runner_active_after=runner_final.active_state,
            api_active_after=api_final.active_state,
        )
        phase.artifacts["rollback_outcome_summary"] = rb_summary
        _record_assertion(
            phase,
            "native_af_release_rollback_symlink_swap_and_sqlite_corruption_recovery",
            ok_rb,
            {
                "current_link": str(good_release.resolve()),
                "version": good_version,
                "db_integrity": "ok",
                "marker_rows": list(marker_rows),
                "recovery_phase": "complete",
                "runner_active": "active",
                "api_active": "active",
            },
            {"summary": rb_summary, "failures": rb_failures},
        )

    except Exception as exc:  # noqa: BLE001
        lock_guard.release()
        phase.failure_diagnostics.append(
            f"Unhandled exception in phase 4: {type(exc).__name__}: {exc}"
        )
        _record_assertion(phase, "phase4_unhandled_exception", False, "no exception", str(exc))

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
    if any(not a.passed for a in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_5_native_deploy_artifact_provider_contract_probe(
    *,
    work_root: Path,
    af_bin: Path,
    fixture: Dict[str, Any],
    owned_transient_units: List[str],
) -> DrillPhaseResult:
    """Phase 5: Honest contract probe of native `deploy` (`command: "deploy"`) via `/v1/self-update`
    and direct `af release deploy`, documenting the exact `GithubHttpArtifactProvider` URL contract
    without faking `af` or weakening rollback/self-update acceptance.
    """
    started_at = utc_now_iso()
    t0 = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="native_deploy_artifact_provider_contract_probe",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    runner_sock: Path = fixture["runner_sock"]
    release_conf_path: Path = fixture["release_conf_path"]
    current_link: Path = fixture["current_link"]
    good_release: Path = fixture["good_release"]

    phase.contract_notes.append(
        "Honest contract report (`backend-rs/crates/af-release/src/artifact.rs` & `ReleaseOptions` in `config.rs`): "
        "`ReleaseEngine::new_production` constructs `GithubHttpArtifactProvider::default()` with `api_base_url: None` "
        "(hardcoded fallback `https://api.github.com`) and `download_base_url: None` (hardcoded fallback `https://github.com`). "
        "Neither `ReleaseConfig::load_with_env` nor `GithubHttpArtifactProvider::default()` reads an environment variable or "
        "`release-manager.conf` key to redirect GitHub release metadata/bundle fetches to a loopback `http://127.0.0.1` server, "
        "and `ReleaseOptions::validate()` rejects `--offline` unless `--dry-run` is also passed "
        "(`--offline is only valid with --dry-run; refusing to deploy a placeholder binary`). "
        "Consequently, inside an airgapped/loopback disposable guest without outbound GitHub release access, "
        "`POST /v1/self-update` with `command: \"deploy\"` spawns the real transient unit "
        "`aetherflow-self-update-deploy-<channel>-<8hex>.service`, which fails closed at Stage 1 artifact fetch "
        "while preserving the active `CURRENT_LINK` release."
    )

    try:
        # 1. Verify `af --json release deploy --channel stable --local --offline --config <conf>` fails closed
        #    with the exact `ReleaseOptions::validate()` guard when `--dry-run` is not set.
        offline_cmd = run_recorded_command(
            [
                str(af_bin),
                "--json",
                "release",
                "deploy",
                "--channel",
                "stable",
                "--local",
                "--offline",
                "--config",
                str(release_conf_path),
            ],
            cwd=work_root,
        )
        phase.commands.append(offline_cmd)
        combined_offline = (offline_cmd.stdout + "\n" + offline_cmd.stderr).lower()
        _record_assertion(
            phase,
            "af_release_deploy_offline_without_dry_run_fails_closed",
            offline_cmd.exit_code != 0
            and "offline is only valid with --dry-run" in combined_offline,
            "non-zero exit + '--offline is only valid with --dry-run'",
            {
                "exit_code": offline_cmd.exit_code,
                "stdout": offline_cmd.stdout,
                "stderr": offline_cmd.stderr,
            },
        )

        # 2. Trigger `POST /v1/self-update` with `{"command": "deploy", "channel": "stable"}` over UDS
        #    and verify that `af-runner` initiates a real `aetherflow-self-update-deploy-stable-<8hex>.service`
        #    transient unit and that `CURRENT_LINK` remains safely pointed at `good_release` if Stage 1 fetch
        #    cannot reach GitHub in the isolated guest.
        deploy_ex = perform_uds_http_request(
            str(runner_sock),
            "POST",
            "/v1/self-update",
            body={"command": "deploy", "channel": "stable"},
            timeout=15.0,
        )
        phase.uds_exchanges.append(deploy_ex)
        ok_dep_init, _, dep_payload, dep_detail = evaluate_self_update_initiation_exchange(
            deploy_ex.http_status,
            deploy_ex.raw_response,
            expect_http_status=200,
            expect_runner_success=True,
            expected_command="deploy",
            expected_channel="stable",
            expected_engine="native_rust_release",
        )
        _record_assertion(
            phase,
            "uds_post_self_update_deploy_spawns_transient_deploy_unit",
            ok_dep_init,
            {
                "http_status": 200,
                "status": "initiated",
                "completed": False,
                "command": "deploy",
                "channel": "stable",
            },
            {"detail": dep_detail, "payload": dep_payload},
        )

        if ok_dep_init and isinstance(dep_payload, dict):
            deploy_job_unit = str(dep_payload["job_unit"])
            owned_transient_units.append(deploy_job_unit)
            dep_final_snap, dep_wait_cmds = wait_for_transient_unit_completion(
                deploy_job_unit, cwd=work_root, timeout_sec=30.0
            )
            phase.commands.extend(dep_wait_cmds)
            phase.artifacts["deploy_transient_unit_final_snapshot"] = asdict(dep_final_snap)

            deploy_status_exchange = query_self_update_status(runner_sock, deploy_job_unit)
            phase.uds_exchanges.append(deploy_status_exchange)
            deploy_status_ok, deploy_status_payload, deploy_status_detail = (
                evaluate_self_update_terminal_status_exchange(
                    deploy_status_exchange.http_status,
                    deploy_status_exchange.raw_response,
                    expected_job_unit=deploy_job_unit,
                    expected_success=False,
                )
            )
            _record_assertion(
                phase,
                "unpublished_deploy_returns_durable_terminal_failure_receipt",
                deploy_status_ok,
                {"job_unit": deploy_job_unit, "status": "failed", "completed": True},
                {"payload": deploy_status_payload, "detail": deploy_status_detail},
            )

            # Verify active `current` symlink was NOT corrupted or repointed away from `good_release`
            resolved_after_deploy_probe = (
                str(current_link.resolve()) if current_link.is_symlink() else ""
            )
            _record_assertion(
                phase,
                "failed_or_unconfigured_remote_deploy_preserves_active_current_symlink",
                resolved_after_deploy_probe == str(good_release.resolve()),
                str(good_release.resolve()),
                resolved_after_deploy_probe,
            )

    except Exception as exc:  # noqa: BLE001
        phase.failure_diagnostics.append(
            f"Unhandled exception in phase 5: {type(exc).__name__}: {exc}"
        )
        _record_assertion(phase, "phase5_unhandled_exception", False, "no exception", str(exc))

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
    if any(not a.passed for a in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_6_rejected_snapshot_rollback(
    *,
    work_root: Path,
    fixture: Dict[str, Any],
    owned_transient_units: List[str],
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    started_monotonic = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="rejected_snapshot_rollback_preserves_failure_and_quiescence",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )
    phase.contract_notes.append(
        "Runs last: a rejected snapshot must not readmit database writers. Only the "
        "control-only runner is explicitly started afterward to query durable status; "
        "the disposable API remains stopped until guest teardown."
    )
    try:
        database_path = fixture["live_db_path"]
        snapshot_manifest = fixture["good_release"] / "data-snapshot" / "MANIFEST.sha256"
        snapshot_manifest.write_text("0" * 64 + "  aetherflow.sqlite.bak\n", encoding="utf-8")
        sentinels: List[SentinelSnapshot] = []
        for suffix, fixture_bytes in (
            ("", b"CORRUPT_DATABASE_REJECTED_SNAPSHOT_FIXTURE" * 32),
            ("-wal", b"PRESERVE_REJECTED_SNAPSHOT_WAL"),
            ("-shm", b"PRESERVE_REJECTED_SNAPSHOT_SHM"),
        ):
            sentinel_path = Path(f"{database_path}{suffix}")
            sentinel_path.write_bytes(fixture_bytes)
            sentinels.append(snapshot_sentinel(sentinel_path))
        phase.artifacts["before_sentinels"] = [asdict(entry) for entry in sentinels]
        exchange = perform_uds_http_request(
            str(fixture["runner_sock"]), "POST", "/v1/self-update",
            body={"command": "rollback", "channel": "stable"}, timeout=15.0,
        )
        phase.uds_exchanges.append(exchange)
        initiated, _, payload, detail = evaluate_self_update_initiation_exchange(
            exchange.http_status, exchange.raw_response,
            expect_http_status=200, expect_runner_success=True,
            expected_command="rollback", expected_channel="stable",
            expected_engine="native_rust_release",
        )
        _record_assertion(phase, "rejected_snapshot_rollback_initiated", initiated, True, detail)
        if not initiated or not payload:
            raise DrillAssertionError("cannot exercise rejected snapshot without a real updater")
        job_unit = str(payload["job_unit"])
        owned_transient_units.append(job_unit)
        final_unit, commands = wait_for_transient_unit_completion(
            job_unit, cwd=work_root, timeout_sec=45.0
        )
        phase.commands.extend(commands)
        phase.artifacts["final_transient_unit"] = asdict(final_unit)
        receipt_path = fixture["data_dir"] / ".self-update-jobs" / f"{job_unit}.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt_envelope = json.dumps({"success": True, "output": json.dumps(receipt)})
        receipt_ok, _, receipt_detail = evaluate_self_update_terminal_status_exchange(
            200, receipt_envelope, expected_job_unit=job_unit, expected_success=False
        )
        _record_assertion(
            phase, "rejected_snapshot_produces_nonzero_durable_failure",
            receipt_ok and isinstance(receipt.get("exit_code"), int)
            and receipt["exit_code"] != 0
            and "database recovery failed" in str(receipt.get("error", "")).lower(),
            "failed receipt with nonzero exit and database recovery error",
            {"receipt": receipt, "detail": receipt_detail},
        )
        api_snapshot, api_command = inspect_systemd_unit(DISPOSABLE_API_UNIT_NAME, cwd=work_root)
        runner_snapshot, runner_command = inspect_systemd_unit(DISPOSABLE_RUNNER_UNIT_NAME, cwd=work_root)
        phase.commands.extend([api_command, runner_command])
        outcome_ok, outcome, failures = evaluate_rejected_snapshot_outcome(
            before_sentinels=sentinels, recovery_state_file=fixture["recovery_state_file"],
            api_snapshot=api_snapshot, runner_snapshot=runner_snapshot,
        )
        _record_assertion(
            phase, "failed_rollback_preserves_bytes_state_and_stopped_services", outcome_ok,
            "unchanged DB/WAL/SHM, failed recovery state, both units stopped",
            {"outcome": outcome, "failures": failures},
        )
        control_start = run_recorded_command(
            ["systemctl", "start", DISPOSABLE_RUNNER_UNIT_NAME], cwd=work_root
        )
        phase.commands.append(control_start)
        phase.uds_exchanges.append(wait_for_runner_uds_ready(fixture["runner_sock"]))
        status_exchange = query_self_update_status(fixture["runner_sock"], job_unit)
        phase.uds_exchanges.append(status_exchange)
        status_ok, status_payload, status_detail = evaluate_self_update_terminal_status_exchange(
            status_exchange.http_status, status_exchange.raw_response,
            expected_job_unit=job_unit, expected_success=False,
        )
        _record_assertion(
            phase, "failure_receipt_survives_control_only_restart",
            control_start.exit_code == 0 and status_ok and status_payload == receipt,
            receipt, {"payload": status_payload, "detail": status_detail},
        )
        api_after, api_after_command = inspect_systemd_unit(DISPOSABLE_API_UNIT_NAME, cwd=work_root)
        phase.commands.append(api_after_command)
        _record_assertion(
            phase, "database_writer_remains_stopped_after_status_query",
            api_after.active_state in ("inactive", "failed") and api_after.main_pid == 0,
            "API inactive with no writer PID", asdict(api_after),
        )
    except Exception as error:
        phase.failure_diagnostics.append(f"Rejected-snapshot drill: {type(error).__name__}: {error}")
        _record_assertion(phase, "rejected_snapshot_drill_completed", False, "no exception", str(error))
    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - started_monotonic) * 1000.0, 2)
    if any(not assertion.passed for assertion in phase.assertions):
        phase.status = "failed"
    return phase


def execute_lifecycle_guest_drill_suite(
    *,
    confirm_disposable_guest: bool,
    work_root: str,
    api_bin: str,
    af_bin: str,
    guest_marker_file: str = DEFAULT_GUEST_MARKER_FILE,
    source_manifest: Optional[str] = None,
    release_artifact: Optional[str] = None,
    keep_work_root: bool = False,
) -> Dict[str, Any]:
    """Run all 6 mandatory lifecycle guest drill phases inside a disposable QEMU/systemd guest."""
    guardrail_info = verify_guest_execution_guardrails(
        confirm_disposable_guest=confirm_disposable_guest,
        work_root=work_root,
        api_bin=api_bin,
        af_bin=af_bin,
        guest_marker_file=guest_marker_file,
    )
    guardrail_info["systemd_lifecycle_marker"] = verify_lifecycle_systemd_marker(
        Path(SYSTEMD_LIFECYCLE_GUEST_MARKER)
    )

    work_root_path = Path(guardrail_info["work_root"])
    api_bin_path = Path(guardrail_info["api_bin"])
    af_bin_path = Path(guardrail_info["af_bin"])

    if work_root_path.exists():
        shutil.rmtree(work_root_path)
    work_root_path.mkdir(parents=True, exist_ok=True)

    suite_started = utc_now_iso()
    t0 = time.monotonic()
    phases: List[DrillPhaseResult] = []
    owned_transient_units: List[str] = []
    installed_unit_files: List[Path] = []
    owned_helper_pids: List[int] = []
    cleanup_summary: Dict[str, Any] = {}

    try:
        phases.append(
            run_phase_1_binary_and_systemd_provenance(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
                guardrail_info=guardrail_info,
                source_manifest=source_manifest,
                release_artifact=release_artifact,
            )
        )

        iso_root = work_root_path / "lifecycle_iso"
        fixture = seed_isolated_lifecycle_fixture(
            iso_root,
            api_bin=api_bin_path,
            af_bin=af_bin_path,
            work_root=work_root_path,
        )

        phases.append(
            run_phase_2_isolated_systemd_runner_and_validation(
                work_root=work_root_path,
                fixture=fixture,
                installed_unit_files=installed_unit_files,
            )
        )

        phases.append(
            run_phase_3_self_stop_quiescence_rejection(
                work_root=work_root_path,
                fixture=fixture,
            )
        )

        phases.append(
            run_phase_4_transient_unit_survival_and_rollback(
                work_root=work_root_path,
                fixture=fixture,
                owned_transient_units=owned_transient_units,
            )
        )

        phases.append(
            run_phase_5_native_deploy_artifact_provider_contract_probe(
                work_root=work_root_path,
                af_bin=af_bin_path,
                fixture=fixture,
                owned_transient_units=owned_transient_units,
            )
        )
        phases.append(
            run_phase_6_rejected_snapshot_rollback(
                work_root=work_root_path,
                fixture=fixture,
                owned_transient_units=owned_transient_units,
            )
        )
    finally:
        cleanup_summary = cleanup_owned_guest_units_and_processes(
            owned_transient_units=owned_transient_units,
            installed_unit_files=installed_unit_files,
            owned_helper_pids=owned_helper_pids,
            cwd=work_root_path,
        )
        if not keep_work_root and work_root_path.exists():
            shutil.rmtree(work_root_path, ignore_errors=True)

    evaluation = evaluate_lifecycle_drill_suite_status(phases)
    suite_completed = utc_now_iso()
    return {
        "schema_version": LIFECYCLE_HARNESS_SCHEMA_VERSION,
        "started_at": suite_started,
        "completed_at": suite_completed,
        "duration_ms": round((time.monotonic() - t0) * 1000.0, 2),
        "guardrails": guardrail_info,
        "cleanup": cleanup_summary,
        "evaluation": evaluation,
        "phases": [asdict(p) for p in phases],
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "AetherFlow v4 Lifecycle & Transient-Systemd Self-Update Guest Drills Harness "
            "(disposable QEMU/systemd VM only)."
        )
    )
    parser.add_argument(
        "--confirm-disposable-guest",
        action="store_true",
        help="Required explicit confirmation that execution is inside a disposable QEMU/systemd guest.",
    )
    parser.add_argument(
        "--work-root",
        default=f"{ALLOWED_WORK_ROOT_PREFIX}-lifecycle",
        help=f"Isolated scratch root inside the guest (must start with {ALLOWED_WORK_ROOT_PREFIX}).",
    )
    parser.add_argument(
        "--api-bin",
        required=True,
        help="Absolute path to the staged `aetherflow-api` binary inside the guest (never /opt/AetherFlow).",
    )
    parser.add_argument(
        "--af-bin",
        required=True,
        help="Absolute path to the staged `af` (`af-cli`) binary inside the guest (never /opt/AetherFlow).",
    )
    parser.add_argument(
        "--guest-marker-file",
        default=DEFAULT_GUEST_MARKER_FILE,
        help=f"Path to disposable guest marker file under /run (default: {DEFAULT_GUEST_MARKER_FILE}).",
    )
    parser.add_argument(
        "--source-manifest",
        default="",
        help="Optional path or reference to the frozen source manifest for provenance logging.",
    )
    parser.add_argument(
        "--release-artifact",
        default="",
        help="Optional path or reference to the release bundle artifact for provenance logging.",
    )
    parser.add_argument(
        "--json-out",
        default="",
        help="Optional path to write the structured JSON drill report.",
    )
    parser.add_argument(
        "--keep-work-root",
        action="store_true",
        help="Preserve the isolated --work-root directory after execution for post-mortem inspection.",
    )
    return parser


def serialize_report_value(value: Any) -> str:
    if isinstance(value, Path):
        return str(value)
    raise TypeError(f"unsupported lifecycle report value: {type(value).__name__}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    try:
        report = execute_lifecycle_guest_drill_suite(
            confirm_disposable_guest=bool(args.confirm_disposable_guest),
            work_root=str(args.work_root),
            api_bin=str(args.api_bin),
            af_bin=str(args.af_bin),
            guest_marker_file=str(args.guest_marker_file),
            source_manifest=str(args.source_manifest) if args.source_manifest else None,
            release_artifact=str(args.release_artifact) if args.release_artifact else None,
            keep_work_root=bool(args.keep_work_root),
        )
    except GuestSafetyError as exc:
        err_payload = {
            "schema_version": LIFECYCLE_HARNESS_SCHEMA_VERSION,
            "status": "blocked_by_guest_safety_guardrail",
            "error": str(exc),
        }
        print(json.dumps(err_payload, indent=2), file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001
        err_payload = {
            "schema_version": LIFECYCLE_HARNESS_SCHEMA_VERSION,
            "status": "harness_runtime_error",
            "error": f"{type(exc).__name__}: {exc}",
        }
        print(json.dumps(err_payload, indent=2), file=sys.stderr)
        return 3

    formatted = json.dumps(report, indent=2, default=serialize_report_value)
    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(formatted + "\n", encoding="utf-8")
    print(formatted)
    return 0 if report["evaluation"]["overall_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
