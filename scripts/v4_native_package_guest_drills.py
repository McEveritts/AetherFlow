from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import sqlite3
import stat
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
import urllib.error
import urllib.request

try:
    import fcntl
    import pwd
except ImportError:
    fcntl = None
    pwd = None

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from v4_privileged_guest_drills import (
    ALLOWED_WORK_ROOT_PREFIX,
    DEFAULT_GUEST_MARKER_FILE,
    AssertionRecord,
    CommandRecord,
    DrillAssertionError,
    DrillPhaseResult,
    GuestSafetyError,
    RunnerDaemonProcess,
    SentinelSnapshot,
    compute_file_sha256,
    evaluate_cli_envelope,
    run_recorded_command,
    snapshot_sentinel,
    utc_now_iso,
    validate_binary_not_in_live_host_tree,
    validate_isolated_work_root,
    verify_guest_execution_guardrails,
    verify_sentinel_unchanged,
)

NATIVE_PACKAGE_HARNESS_SCHEMA_VERSION = "4.0.0-native-package-guest-drills-v1"

SUPPORTED_NATIVE_PACKAGES: Tuple[str, ...] = (
    "fail2ban",
    "quassel",
    "threadfin",
)

MANDATORY_NATIVE_PACKAGE_PHASES: Tuple[str, ...] = (
    "binary_and_environment_provenance",
    "fail2ban_native_lifecycle",
    "quassel_native_lifecycle_and_preservation",
    "threadfin_native_lifecycle_and_artifact_verification",
    "cancellation_serialization_and_rollback_safety",
)

THREADFIN_PINNED_VERSION = "1.2.37"
THREADFIN_PINNED_AMD64_COMPAT_SHA256 = (
    "0b80a1bb5dc270c35288531408657189fd27c2e4346686743ebd36f3b6acbe42"
)
THREADFIN_PINNED_AMD64_PLAIN_SHA256 = (
    "19183058cf28b0080df059113e546a8e8cac16cae210d13be51bda42af94dfc2"
)
ALLOWED_THREADFIN_AMD64_DIGESTS: Tuple[str, ...] = (
    THREADFIN_PINNED_AMD64_COMPAT_SHA256,
    THREADFIN_PINNED_AMD64_PLAIN_SHA256,
)

PROGRESS_LINE_RE = re.compile(r"^\[PROGRESS:(\d{1,3})\]\s+(.+)$")
RUNNER_EXIT_ERROR_PREFIX = "__RUNNER_EXIT_ERROR__:"


@dataclass
class PackageUdsStreamRecord:
    socket_path: str
    method: str
    path: str
    request_body: Optional[Dict[str, Any]]
    http_status: Optional[int]
    headers: Dict[str, str]
    engine_header: Optional[str]
    raw_response: str
    progress_events: List[Dict[str, Any]]
    runner_exit_error: Optional[str]
    socket_error: Optional[str]
    duration_ms: float


class _UnixStreamHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float = 300.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        unix_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        unix_sock.settimeout(self.timeout)
        unix_sock.connect(self.socket_path)
        self.sock = unix_sock


def parse_package_stream_output(raw_text: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    events: List[Dict[str, Any]] = []
    runner_error: Optional[str] = None
    for raw_line in raw_text.splitlines():
        stripped_line = raw_line.strip()
        if not stripped_line:
            continue
        if stripped_line.startswith(RUNNER_EXIT_ERROR_PREFIX):
            runner_error = stripped_line[len(RUNNER_EXIT_ERROR_PREFIX) :].strip()
            continue
        match_obj = PROGRESS_LINE_RE.match(stripped_line)
        if match_obj:
            events.append(
                {
                    "progress_pct": int(match_obj.group(1)),
                    "message": match_obj.group(2).strip(),
                    "raw": stripped_line,
                }
            )
    return events, runner_error


def evaluate_package_stream_exchange(
    exchange: PackageUdsStreamRecord,
    *,
    expect_http_status: int = 200,
    expected_engine: str = "declarative_rust",
    expect_success: bool = True,
    expected_error_substring: Optional[str] = None,
) -> Tuple[bool, str]:
    if exchange.socket_error is not None:
        return False, f"socket error: {exchange.socket_error}"
    if exchange.http_status != expect_http_status:
        return (
            False,
            f"expected HTTP {expect_http_status}, got {exchange.http_status} (raw={exchange.raw_response[:400]!r})",
        )
    if expected_engine and exchange.engine_header != expected_engine:
        return (
            False,
            f"expected X-AetherFlow-Package-Engine={expected_engine!r}, got {exchange.engine_header!r}",
        )
    if expect_success:
        if exchange.runner_exit_error is not None:
            return False, f"unexpected runner exit error: {exchange.runner_exit_error}"
        if not exchange.progress_events:
            return False, "expected non-empty [PROGRESS:<pct>] stream events, got zero"
        percentages = [int(item["progress_pct"]) for item in exchange.progress_events]
        for index_pos in range(1, len(percentages)):
            if percentages[index_pos] < percentages[index_pos - 1]:
                return (
                    False,
                    f"progress percentages were not monotonic: {percentages}",
                )
        if percentages[-1] != 100:
            return (
                False,
                f"expected final progress percentage 100, got {percentages[-1]} (events={percentages})",
            )
        return True, f"verified {len(percentages)} progress events ending at 100%"

    if exchange.runner_exit_error is None:
        return False, f"expected runner exit error, but stream succeeded: {exchange.raw_response[:400]!r}"
    if expected_error_substring and expected_error_substring.lower() not in exchange.runner_exit_error.lower():
        return (
            False,
            f"expected error containing {expected_error_substring!r}, got {exchange.runner_exit_error!r}",
        )
    return True, f"verified expected failure: {exchange.runner_exit_error}"


def perform_package_uds_request(
    socket_path: str,
    method: str,
    path: str,
    body: Optional[Dict[str, Any]] = None,
    timeout: float = 300.0,
) -> PackageUdsStreamRecord:
    started_mono = time.monotonic()
    http_status: Optional[int] = None
    headers_map: Dict[str, str] = {}
    engine_header: Optional[str] = None
    raw_response = ""
    socket_error: Optional[str] = None

    try:
        connection = _UnixStreamHTTPConnection(socket_path, timeout=timeout)
        request_headers: Dict[str, str] = {"Host": "unix"}
        encoded_body: Optional[bytes] = None
        if body is not None:
            encoded_body = json.dumps(body).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
            request_headers["Content-Length"] = str(len(encoded_body))
        connection.request(method, path, body=encoded_body, headers=request_headers)
        response = connection.getresponse()
        http_status = int(response.status)
        for header_key, header_val in response.getheaders():
            headers_map[header_key] = header_val
            if header_key.lower() == "x-aetherflow-package-engine":
                engine_header = header_val.strip()
        raw_response = response.read().decode("utf-8", errors="replace")
        connection.close()
    except Exception as error_exc:
        socket_error = f"{type(error_exc).__name__}: {error_exc}"

    duration_ms = round((time.monotonic() - started_mono) * 1000.0, 2)
    progress_events, runner_exit_error = parse_package_stream_output(raw_response)
    return PackageUdsStreamRecord(
        socket_path=socket_path,
        method=method,
        path=path,
        request_body=body,
        http_status=http_status,
        headers=headers_map,
        engine_header=engine_header,
        raw_response=raw_response,
        progress_events=progress_events,
        runner_exit_error=runner_exit_error,
        socket_error=socket_error,
        duration_ms=duration_ms,
    )


def inspect_elf_binary_metadata(binary_path: Path) -> Dict[str, Any]:
    if not binary_path.is_file():
        return {
            "exists": False,
            "is_elf": False,
            "e_machine": None,
            "arch": None,
            "size_bytes": 0,
            "sha256": None,
            "mode_octal": None,
        }
    stat_info = binary_path.stat()
    with binary_path.open("rb") as file_handle:
        header_bytes = file_handle.read(20)
    is_elf = len(header_bytes) >= 20 and header_bytes[:4] == b"\x7fELF"
    e_machine: Optional[int] = None
    arch_name: Optional[str] = None
    if is_elf:
        is_big_endian = header_bytes[5] == 2
        if is_big_endian:
            e_machine = int.from_bytes(header_bytes[18:20], byteorder="big")
        else:
            e_machine = int.from_bytes(header_bytes[18:20], byteorder="little")
        arch_lookup = {
            62: "amd64",
            183: "arm64",
            40: "armhf",
            3: "i386",
            243: "riscv64",
        }
        arch_name = arch_lookup.get(e_machine)
    return {
        "exists": True,
        "is_elf": is_elf,
        "e_machine": e_machine,
        "arch": arch_name,
        "size_bytes": int(stat_info.st_size),
        "sha256": compute_file_sha256(binary_path),
        "mode_octal": f"{stat.S_IMODE(stat_info.st_mode):04o}",
    }


def parse_lock_file_kv(lock_path: Path) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    if not lock_path.is_file():
        return parsed
    for raw_line in lock_path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped_line = raw_line.strip()
        if not stripped_line or "=" not in stripped_line:
            continue
        key_part, val_part = stripped_line.split("=", 1)
        parsed[key_part.strip()] = val_part.strip()
    return parsed


def evaluate_native_package_suite_status(
    phases: Sequence[DrillPhaseResult],
    required_phases: Sequence[str] = MANDATORY_NATIVE_PACKAGE_PHASES,
) -> Dict[str, Any]:
    phase_map: Dict[str, DrillPhaseResult] = {
        phase_item.phase_id: phase_item for phase_item in phases
    }
    missing_phases: List[str] = []
    failed_phases: List[str] = []
    pending_phases: List[str] = []
    passed_phases: List[str] = []

    for req_id in required_phases:
        phase_obj = phase_map.get(req_id)
        if phase_obj is None:
            missing_phases.append(req_id)
            continue
        if not phase_obj.real_execution:
            failed_phases.append(f"{req_id} (real_execution=False)")
            continue
        if not phase_obj.assertions:
            failed_phases.append(f"{req_id} (zero assertions recorded)")
            continue
        if any(not assertion_item.passed for assertion_item in phase_obj.assertions):
            failed_phases.append(req_id)
            continue
        if phase_obj.status == "pending_contract":
            pending_phases.append(req_id)
            continue
        if phase_obj.status != "passed":
            failed_phases.append(req_id)
            continue
        passed_phases.append(req_id)

    for extra_id, phase_obj in phase_map.items():
        if extra_id not in required_phases:
            if phase_obj.status == "pending_contract":
                pending_phases.append(extra_id)
            elif (
                phase_obj.status != "passed"
                or not phase_obj.real_execution
                or any(not assertion_item.passed for assertion_item in phase_obj.assertions)
            ):
                failed_phases.append(extra_id)

    overall_passed = (
        len(required_phases) > 0
        and len(missing_phases) == 0
        and len(failed_phases) == 0
        and len(pending_phases) == 0
        and len(passed_phases) == len(required_phases)
    )
    if overall_passed:
        overall_status = "passed"
    elif pending_phases and not failed_phases and not missing_phases:
        overall_status = "failed_pending_contract"
    else:
        overall_status = "failed"

    return {
        "overall_status": overall_status,
        "overall_passed": overall_passed,
        "required_phase_count": len(required_phases),
        "passed_phases": passed_phases,
        "failed_phases": failed_phases,
        "pending_contract_phases": pending_phases,
        "missing_phases": missing_phases,
    }


def record_phase_assertion(
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
    if not passed:
        phase.failure_diagnostics.append(
            f"Assertion {name!r} failed: expected={expected!r}, actual={actual!r} ({detail})"
        )


def query_dpkg_status(package_name: str, cwd: Path) -> Tuple[CommandRecord, str, str]:
    status_cmd = run_recorded_command(
        ["dpkg-query", "-W", "-f=${db:Status-Status}|${Version}", package_name],
        cwd=cwd,
    )
    if status_cmd.exit_code != 0:
        return status_cmd, "not-installed", ""
    parts = status_cmd.stdout.strip().split("|", 1)
    pkg_status = parts[0].strip() if parts else "unknown"
    pkg_version = parts[1].strip() if len(parts) > 1 else ""
    return status_cmd, pkg_status, pkg_version


def query_systemd_unit_state(unit_name: str, cwd: Path) -> Dict[str, Any]:
    active_cmd = run_recorded_command(["systemctl", "is-active", unit_name], cwd=cwd)
    enabled_cmd = run_recorded_command(["systemctl", "is-enabled", unit_name], cwd=cwd)
    show_cmd = run_recorded_command(
        [
            "systemctl",
            "show",
            "-p",
            "MainPID,ActiveState,SubState,Result,ExecMainStatus,FragmentPath,DropInPaths",
            unit_name,
        ],
        cwd=cwd,
    )
    props: Dict[str, str] = {}
    for raw_line in show_cmd.stdout.splitlines():
        if "=" in raw_line:
            prop_key, prop_val = raw_line.split("=", 1)
            props[prop_key.strip()] = prop_val.strip()
    main_pid_str = props.get("MainPID", "0")
    main_pid = int(main_pid_str) if main_pid_str.isdigit() else 0
    journal_cmd = run_recorded_command(
        ["journalctl", "-u", unit_name, "-n", "40", "--no-pager"],
        cwd=cwd,
    )
    return {
        "unit_name": unit_name,
        "is_active_exit_code": active_cmd.exit_code,
        "is_active_stdout": active_cmd.stdout.strip(),
        "is_enabled_exit_code": enabled_cmd.exit_code,
        "is_enabled_stdout": enabled_cmd.stdout.strip(),
        "main_pid": main_pid,
        "properties": props,
        "journal_excerpt": journal_cmd.stdout[-2500:],
        "commands": [active_cmd, enabled_cmd, show_cmd, journal_cmd],
    }


def wait_for_tcp_listener(
    host: str,
    port: int,
    timeout_seconds: float = 15.0,
) -> Dict[str, Any]:
    started_mono = time.monotonic()
    deadline = started_mono + timeout_seconds
    last_error: Optional[str] = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.5):
                return {
                    "listening": True,
                    "host": host,
                    "port": port,
                    "wait_ms": round((time.monotonic() - started_mono) * 1000.0, 2),
                    "error": None,
                }
        except OSError as os_err:
            last_error = f"{type(os_err).__name__}: {os_err}"
            time.sleep(0.25)
    return {
        "listening": False,
        "host": host,
        "port": port,
        "wait_ms": round((time.monotonic() - started_mono) * 1000.0, 2),
        "error": last_error,
    }


def probe_http_endpoint(url: str, timeout_seconds: float = 10.0) -> Dict[str, Any]:
    try:
        request_obj = urllib.request.Request(
            url,
            headers={"User-Agent": "AetherFlow-v4-NativePackageDrill/1.0"},
        )
        with urllib.request.urlopen(request_obj, timeout=timeout_seconds) as response_obj:
            body_bytes = response_obj.read(4096)
            return {
                "reachable": True,
                "status_code": int(response_obj.status),
                "body_excerpt": body_bytes.decode("utf-8", errors="replace")[:500],
                "error": None,
            }
    except urllib.error.HTTPError as http_err:
        return {
            "reachable": True,
            "status_code": int(http_err.code),
            "body_excerpt": "",
            "error": f"HTTPError {http_err.code}",
        }
    except Exception as error_exc:
        return {
            "reachable": False,
            "status_code": None,
            "body_excerpt": "",
            "error": f"{type(error_exc).__name__}: {error_exc}",
        }


def build_native_runner_daemon(
    *,
    api_bin: Path,
    socket_path: Path,
    log_path: Path,
    delete_data: bool = False,
    extra_env: Optional[Dict[str, str]] = None,
) -> RunnerDaemonProcess:
    env_overrides: Dict[str, str] = {
        "AETHERFLOW_ENABLE_RUST_PACKAGES": "1",
        "AETHERFLOW_FORCE_BASH_PACKAGES": "0",
        "AETHERFLOW_PACKAGE_DRY_RUN": "0",
        "DELETE_DATA": "true" if delete_data else "false",
    }
    if extra_env:
        env_overrides.update(extra_env)
    return RunnerDaemonProcess(
        api_bin=api_bin,
        socket_path=socket_path,
        env_overrides=env_overrides,
        log_path=log_path,
    )


def create_labeled_quassel_sqlite_fixture(sqlite_path: Path, owner_user: str) -> Dict[str, Any]:
    sqlite_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(str(sqlite_path))
    try:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS af_test_provisioning_sentinel ("
            "sentinel_id TEXT PRIMARY KEY, "
            "classification TEXT NOT NULL, "
            "note TEXT NOT NULL"
            ");"
        )
        connection.execute(
            "INSERT OR REPLACE INTO af_test_provisioning_sentinel "
            "(sentinel_id, classification, note) VALUES (?, ?, ?);",
            (
                "quassel_storage_preservation_v4",
                "test_provisioning_fixture_only",
                "Synthetic SQLite fixture seeded solely to verify data preservation across update and non-purge remove; not IRC client acceptance.",
            ),
        )
        connection.commit()
    finally:
        connection.close()
    os.chmod(sqlite_path, 0o640)
    if pwd is not None and hasattr(os, "chown"):
        try:
            pw_record = pwd.getpwnam(owner_user)
            os.chown(sqlite_path, pw_record.pw_uid, pw_record.pw_gid)
        except KeyError:
            pass
    return {
        "path": str(sqlite_path),
        "classification": "test_provisioning_fixture_only",
        "sha256": compute_file_sha256(sqlite_path),
    }


def create_labeled_threadfin_config_fixture(config_path: Path, owner_user: str) -> Dict[str, Any]:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "af_fixture_classification": "test_provisioning_fixture_only",
        "af_fixture_purpose": "Seeded solely to verify /var/lib/threadfin/conf preservation across update and DELETE_DATA=false removal; not IPTV stream playback acceptance.",
        "sentinel_id": "threadfin_conf_preservation_v4",
    }
    config_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(config_path, 0o640)
    if pwd is not None and hasattr(os, "chown"):
        try:
            pw_record = pwd.getpwnam(owner_user)
            os.chown(config_path, pw_record.pw_uid, pw_record.pw_gid)
        except KeyError:
            pass
    return {
        "path": str(config_path),
        "classification": "test_provisioning_fixture_only",
        "sha256": compute_file_sha256(config_path),
    }


def run_phase_1_native_provenance(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
    guardrail_info: Dict[str, Any],
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    started_mono = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="binary_and_environment_provenance",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    for binary_label, binary_path in (("aetherflow-api", api_bin), ("af", af_bin)):
        is_exec = binary_path.is_file() and os.access(binary_path, os.X_OK)
        record_phase_assertion(
            phase,
            f"{binary_label}_binary_executable",
            is_exec,
            "executable file exists outside /opt/AetherFlow",
            str(binary_path) if is_exec else "missing or not executable",
        )
        if is_exec:
            phase.artifacts[binary_label] = inspect_elf_binary_metadata(binary_path)

    os_release_map: Dict[str, str] = {}
    os_release_path = Path("/etc/os-release")
    if os_release_path.is_file():
        for raw_line in os_release_path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in raw_line and not raw_line.strip().startswith("#"):
                key_part, val_part = raw_line.split("=", 1)
                os_release_map[key_part.strip()] = val_part.strip().strip('"').strip("'")
    phase.artifacts["os_release"] = os_release_map
    phase.artifacts["guardrails"] = guardrail_info
    phase.artifacts["harness_script_sha256"] = compute_file_sha256(Path(__file__).resolve())

    is_debian_13 = (
        os_release_map.get("ID") == "debian"
        and (
            os_release_map.get("VERSION_ID") == "13"
            or "trixie" in os_release_map.get("VERSION_CODENAME", "").lower()
            or "trixie" in os_release_map.get("PRETTY_NAME", "").lower()
        )
    )
    record_phase_assertion(
        phase,
        "guest_os_is_disposable_debian_13",
        is_debian_13,
        {"ID": "debian", "VERSION_ID": "13"},
        {
            "ID": os_release_map.get("ID"),
            "VERSION_ID": os_release_map.get("VERSION_ID"),
            "VERSION_CODENAME": os_release_map.get("VERSION_CODENAME"),
        },
    )

    ver_cmd = run_recorded_command([str(af_bin), "--json", "version"], cwd=work_root)
    phase.commands.append(ver_cmd)
    ok_ver, ver_payload, ver_detail = evaluate_cli_envelope(ver_cmd.stdout, expected_status="ok")
    record_phase_assertion(
        phase,
        "af_cli_version_envelope",
        ver_cmd.exit_code == 0 and ok_ver,
        {"exit_code": 0, "status": "ok"},
        {"exit_code": ver_cmd.exit_code, "detail": ver_detail, "payload": ver_payload},
    )

    for pkg_id in SUPPORTED_NATIVE_PACKAGES:
        info_cmd = run_recorded_command(
            [str(af_bin), "--json", "package", "info", pkg_id],
            cwd=work_root,
        )
        phase.commands.append(info_cmd)
        ok_info, info_payload, info_detail = evaluate_cli_envelope(
            info_cmd.stdout,
            expected_status="ok",
        )
        info_data = (info_payload or {}).get("data") or {}
        pkg_meta = info_data.get("package") or {}
        record_phase_assertion(
            phase,
            f"af_cli_package_info_{pkg_id}",
            info_cmd.exit_code == 0 and ok_info and pkg_meta.get("name") == pkg_id,
            {"exit_code": 0, "name": pkg_id},
            {"exit_code": info_cmd.exit_code, "detail": info_detail, "payload": info_payload},
        )

    sock_path = work_root / "run/phase1_runner.sock"
    log_path = work_root / "logs/phase1_runner.log"
    daemon = build_native_runner_daemon(
        api_bin=api_bin,
        socket_path=sock_path,
        log_path=log_path,
    )
    try:
        daemon.start()
        health_cmd = run_recorded_command(
            [str(af_bin), "--socket", str(sock_path), "--json", "health"],
            cwd=work_root,
        )
        phase.commands.append(health_cmd)
        ok_health, health_payload, health_detail = evaluate_cli_envelope(
            health_cmd.stdout,
            expected_status="ok",
        )
        health_data = (health_payload or {}).get("data") or {}
        runner_resp = health_data.get("runner_response") or {}
        record_phase_assertion(
            phase,
            "af_cli_uds_runner_health_ok",
            health_cmd.exit_code == 0
            and ok_health
            and runner_resp.get("success") is True
            and runner_resp.get("output") == "ready",
            {"exit_code": 0, "runner_reachable": True},
            {"exit_code": health_cmd.exit_code, "detail": health_detail, "payload": health_payload},
        )
    except Exception as error_exc:
        phase.failure_diagnostics.append(
            f"Unhandled exception in phase 1: {type(error_exc).__name__}: {error_exc}"
        )
        record_phase_assertion(phase, "phase1_unhandled_exception", False, "no exception", str(error_exc))
    finally:
        daemon.stop()

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - started_mono) * 1000.0, 2)
    if any(not assertion_item.passed for assertion_item in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_2_fail2ban_lifecycle(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    started_mono = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="fail2ban_native_lifecycle",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    sshd_config_path = Path("/etc/ssh/sshd_config")
    original_sshd_config: Optional[str] = None
    if sshd_config_path.is_file():
        original_sshd_config = sshd_config_path.read_text(encoding="utf-8", errors="replace")

    sock_path = work_root / "run/phase2_fail2ban_runner.sock"
    log_path = work_root / "logs/phase2_fail2ban_runner.log"
    daemon = build_native_runner_daemon(
        api_bin=api_bin,
        socket_path=sock_path,
        log_path=log_path,
        delete_data=False,
    )

    try:
        if original_sshd_config is not None:
            sshd_config_path.write_text(
                "Port 2222\n" + original_sshd_config,
                encoding="utf-8",
            )

        daemon.start()

        install_ex = perform_package_uds_request(
            str(sock_path),
            "POST",
            "/v1/package",
            body={
                "action": "install",
                "package_id": "fail2ban",
                "script_name": "installpackage-fail2ban",
                "app_port": 0,
            },
            timeout=600.0,
        )
        phase.artifacts["uds_install_exchange"] = asdict(install_ex)
        ok_inst, inst_detail = evaluate_package_stream_exchange(
            install_ex,
            expect_http_status=200,
            expected_engine="declarative_rust",
            expect_success=True,
        )
        record_phase_assertion(
            phase,
            "fail2ban_uds_native_install_stream_succeeded",
            ok_inst,
            "HTTP 200 + X-AetherFlow-Package-Engine=declarative_rust + progress 100%",
            inst_detail,
        )

        dpkg_cmd, dpkg_status, dpkg_ver = query_dpkg_status("fail2ban", work_root)
        phase.commands.append(dpkg_cmd)
        py_sys_cmd, py_sys_status, py_sys_ver = query_dpkg_status("python3-systemd", work_root)
        phase.commands.append(py_sys_cmd)
        record_phase_assertion(
            phase,
            "fail2ban_and_python3_systemd_apt_packages_installed",
            dpkg_status == "installed" and py_sys_status == "installed",
            {"fail2ban": "installed", "python3-systemd": "installed"},
            {"fail2ban": dpkg_status, "python3-systemd": py_sys_status, "version": dpkg_ver},
        )

        jail_local_path = Path("/etc/fail2ban/jail.local")
        jail_content = (
            jail_local_path.read_text(encoding="utf-8", errors="replace")
            if jail_local_path.is_file()
            else ""
        )
        jail_mode = (
            f"{stat.S_IMODE(jail_local_path.stat().st_mode):04o}"
            if jail_local_path.is_file()
            else None
        )
        phase.artifacts["jail_local"] = {
            "exists": jail_local_path.is_file(),
            "mode_octal": jail_mode,
            "content": jail_content,
        }
        record_phase_assertion(
            phase,
            "fail2ban_jail_local_rendered_with_systemd_backend_and_probed_ssh_port",
            jail_local_path.is_file()
            and jail_mode == "0644"
            and "backend  = systemd" in jail_content
            and "[sshd]" in jail_content
            and "enabled = true" in jail_content
            and "port    = 2222,ssh" in jail_content,
            {
                "exists": True,
                "mode_octal": "0644",
                "backend": "systemd",
                "port": "2222,ssh",
            },
            phase.artifacts["jail_local"],
        )

        lock_path = Path("/install/.fail2ban.lock")
        lock_kv = parse_lock_file_kv(lock_path)
        phase.artifacts["lock_after_install"] = lock_kv
        record_phase_assertion(
            phase,
            "fail2ban_lock_file_written_by_declarative_rust",
            lock_path.is_file()
            and lock_kv.get("package") == "fail2ban"
            and lock_kv.get("engine") == "declarative_rust",
            {"exists": True, "package": "fail2ban", "engine": "declarative_rust"},
            lock_kv,
        )

        dropin_path = Path("/etc/systemd/system/fail2ban.service.d/aetherflow-sandbox.conf")
        record_phase_assertion(
            phase,
            "fail2ban_privileged_service_exempt_from_restrictive_sandbox_dropin",
            not dropin_path.exists(),
            {"sandbox_dropin_exists": False},
            {"sandbox_dropin_exists": dropin_path.exists()},
        )

        unit_state_install = query_systemd_unit_state("fail2ban.service", work_root)
        phase.commands.extend(unit_state_install.pop("commands"))
        phase.artifacts["systemd_after_install"] = unit_state_install
        record_phase_assertion(
            phase,
            "fail2ban_systemd_service_active_with_main_pid",
            unit_state_install["is_active_stdout"] == "active"
            and int(unit_state_install["main_pid"]) > 0,
            {"is_active": "active", "main_pid_gt_0": True},
            {
                "is_active": unit_state_install["is_active_stdout"],
                "main_pid": unit_state_install["main_pid"],
            },
        )

        ping_cmd: Optional[CommandRecord] = None
        for attempt_idx in range(20):
            ping_cmd = run_recorded_command(["fail2ban-client", "ping"], cwd=work_root)
            if ping_cmd.exit_code == 0 and "pong" in ping_cmd.stdout.lower():
                break
            if attempt_idx < 19:
                time.sleep(0.5)
        assert ping_cmd is not None
        phase.commands.append(ping_cmd)
        record_phase_assertion(
            phase,
            "fail2ban_daemon_responds_to_client_ping",
            ping_cmd.exit_code == 0 and "pong" in ping_cmd.stdout.lower(),
            {"exit_code": 0, "stdout_contains": "pong"},
            {"exit_code": ping_cmd.exit_code, "stdout": ping_cmd.stdout.strip()},
        )

        skip_cmd = run_recorded_command(
            [str(af_bin), "--socket", str(sock_path), "--json", "package", "install", "fail2ban"],
            cwd=work_root,
        )
        phase.commands.append(skip_cmd)
        ok_skip, skip_payload, skip_detail = evaluate_cli_envelope(
            skip_cmd.stdout,
            expected_status="ok",
        )
        skip_data = (skip_payload or {}).get("data") or {}
        skipped_list = skip_data.get("skipped_already_installed") or []
        record_phase_assertion(
            phase,
            "af_cli_install_idempotent_when_lock_present",
            skip_cmd.exit_code == 0
            and ok_skip
            and "fail2ban" in skipped_list,
            {"exit_code": 0, "skipped_already_installed": ["fail2ban"]},
            {"exit_code": skip_cmd.exit_code, "detail": skip_detail, "data": skip_data},
        )

        update_cmd = run_recorded_command(
            [str(af_bin), "--socket", str(sock_path), "--json", "package", "update", "fail2ban"],
            cwd=work_root,
            timeout=600.0,
        )
        phase.commands.append(update_cmd)
        ok_upd, upd_payload, upd_detail = evaluate_cli_envelope(
            update_cmd.stdout,
            expected_status="ok",
        )
        upd_data = (upd_payload or {}).get("data") or {}
        upd_receipt = upd_data.get("receipt") or {}
        record_phase_assertion(
            phase,
            "af_cli_package_update_fail2ban_succeeded",
            update_cmd.exit_code == 0
            and ok_upd
            and upd_receipt.get("package_id") == "fail2ban"
            and upd_receipt.get("action") == "update"
            and upd_receipt.get("last_progress_percent") == 100,
            {"exit_code": 0, "package_id": "fail2ban", "action": "update", "last_progress_percent": 100},
            {"exit_code": update_cmd.exit_code, "detail": upd_detail, "receipt": upd_receipt},
        )

        unit_state_update = query_systemd_unit_state("fail2ban.service", work_root)
        phase.commands.extend(unit_state_update.pop("commands"))
        phase.artifacts["systemd_after_update"] = unit_state_update
        record_phase_assertion(
            phase,
            "fail2ban_systemd_service_active_after_update",
            unit_state_update["is_active_stdout"] == "active"
            and int(unit_state_update["main_pid"]) > 0,
            {"is_active": "active", "main_pid_gt_0": True},
            {
                "is_active": unit_state_update["is_active_stdout"],
                "main_pid": unit_state_update["main_pid"],
            },
        )

        remove_cmd = run_recorded_command(
            [
                str(af_bin),
                "--socket",
                str(sock_path),
                "--json",
                "package",
                "remove",
                "fail2ban",
            ],
            cwd=work_root,
            timeout=600.0,
        )
        phase.commands.append(remove_cmd)
        ok_rem, rem_payload, rem_detail = evaluate_cli_envelope(
            remove_cmd.stdout,
            expected_status="ok",
        )
        rem_data = (rem_payload or {}).get("data") or {}
        rem_receipts = rem_data.get("receipts") or []
        record_phase_assertion(
            phase,
            "af_cli_package_remove_fail2ban_succeeded",
            remove_cmd.exit_code == 0
            and ok_rem
            and len(rem_receipts) == 1
            and rem_receipts[0].get("package_id") == "fail2ban"
            and rem_receipts[0].get("action") == "remove",
            {"exit_code": 0, "package_id": "fail2ban", "action": "remove"},
            {"exit_code": remove_cmd.exit_code, "detail": rem_detail, "receipts": rem_receipts},
        )

        dpkg_after_cmd, dpkg_after_status, dpkg_after_ver = query_dpkg_status("fail2ban", work_root)
        phase.commands.append(dpkg_after_cmd)
        unit_state_remove = query_systemd_unit_state("fail2ban.service", work_root)
        phase.commands.extend(unit_state_remove.pop("commands"))
        phase.artifacts["systemd_after_remove"] = unit_state_remove
        purged_dirs_state = {
            "/install/.fail2ban.lock": lock_path.exists(),
            "/run/fail2ban": Path("/run/fail2ban").exists(),
        }
        preserved_jail = (
            jail_local_path.read_text(encoding="utf-8", errors="replace")
            if jail_local_path.is_file()
            else None
        )
        phase.artifacts["purged_paths_after_remove"] = purged_dirs_state
        record_phase_assertion(
            phase,
            "fail2ban_remove_cleans_runtime_and_preserves_config_without_delete_data",
            dpkg_after_status != "installed"
            and unit_state_remove["is_active_stdout"] != "active"
            and not any(purged_dirs_state.values())
            and preserved_jail == jail_content,
            {
                "dpkg_installed": False,
                "service_active": False,
                "remaining_paths": False,
                "jail_config_preserved": True,
            },
            {
                "dpkg_status": dpkg_after_status,
                "service_state": unit_state_remove["is_active_stdout"],
                "paths_exist": purged_dirs_state,
                "jail_config_preserved": preserved_jail == jail_content,
            },
        )
    except Exception as error_exc:
        phase.failure_diagnostics.append(
            f"Unhandled exception in phase 2: {type(error_exc).__name__}: {error_exc}"
        )
        record_phase_assertion(phase, "phase2_unhandled_exception", False, "no exception", str(error_exc))
    finally:
        daemon.stop()
        if original_sshd_config is not None:
            sshd_config_path.write_text(original_sshd_config, encoding="utf-8")

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - started_mono) * 1000.0, 2)
    if any(not assertion_item.passed for assertion_item in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_3_quassel_lifecycle(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    started_mono = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="quassel_native_lifecycle_and_preservation",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    custom_install_port = 4244
    custom_update_port = 4245
    sock_keep = work_root / "run/phase3_quassel_keep.sock"
    log_keep = work_root / "logs/phase3_quassel_keep.log"
    sock_purge = work_root / "run/phase3_quassel_purge.sock"
    log_purge = work_root / "logs/phase3_quassel_purge.log"

    daemon_keep = build_native_runner_daemon(
        api_bin=api_bin,
        socket_path=sock_keep,
        log_path=log_keep,
        delete_data=False,
    )
    daemon_purge: Optional[RunnerDaemonProcess] = None

    try:
        daemon_keep.start()

        install_ex = perform_package_uds_request(
            str(sock_keep),
            "POST",
            "/v1/package",
            body={
                "action": "install",
                "package_id": "quassel",
                "script_name": "installpackage-quassel",
                "app_port": custom_install_port,
            },
            timeout=600.0,
        )
        phase.artifacts["uds_install_exchange"] = asdict(install_ex)
        ok_inst, inst_detail = evaluate_package_stream_exchange(
            install_ex,
            expect_http_status=200,
            expected_engine="declarative_rust",
            expect_success=True,
        )
        record_phase_assertion(
            phase,
            "quassel_uds_native_install_stream_succeeded",
            ok_inst,
            "HTTP 200 + declarative_rust + progress 100%",
            inst_detail,
        )

        dpkg_q_cmd, dpkg_q_status, dpkg_q_ver = query_dpkg_status("quassel-core", work_root)
        phase.commands.append(dpkg_q_cmd)
        dpkg_ssl_cmd, dpkg_ssl_status, dpkg_ssl_ver = query_dpkg_status("openssl", work_root)
        phase.commands.append(dpkg_ssl_cmd)
        record_phase_assertion(
            phase,
            "quassel_core_and_openssl_apt_packages_installed",
            dpkg_q_status == "installed" and dpkg_ssl_status == "installed",
            {"quassel-core": "installed", "openssl": "installed"},
            {"quassel-core": dpkg_q_status, "openssl": dpkg_ssl_status, "version": dpkg_q_ver},
        )

        cert_path = Path("/var/lib/quassel/quasselCert.pem")
        cert_exists = cert_path.is_file() and not cert_path.is_symlink()
        cert_mode = f"{stat.S_IMODE(cert_path.stat().st_mode):04o}" if cert_exists else None
        cert_subj_cmd = run_recorded_command(
            ["openssl", "x509", "-in", str(cert_path), "-noout", "-subject", "-fingerprint", "-sha256"],
            cwd=work_root,
        )
        phase.commands.append(cert_subj_cmd)
        record_phase_assertion(
            phase,
            "quassel_tls_certificate_generated_0600_valid_x509",
            cert_exists
            and cert_mode == "0600"
            and cert_subj_cmd.exit_code == 0
            and "quassel.aether.local" in cert_subj_cmd.stdout,
            {"exists": True, "mode": "0600", "subject_cn": "quassel.aether.local"},
            {
                "exists": cert_exists,
                "mode": cert_mode,
                "openssl_exit": cert_subj_cmd.exit_code,
                "openssl_stdout": cert_subj_cmd.stdout.strip(),
            },
        )

        defaults_path = Path("/etc/default/quasselcore")
        defaults_text = (
            defaults_path.read_text(encoding="utf-8", errors="replace")
            if defaults_path.is_file()
            else ""
        )
        af_ver_path = Path("/var/lib/quassel/.af-version")
        af_ver_text = (
            af_ver_path.read_text(encoding="utf-8", errors="replace").strip()
            if af_ver_path.is_file()
            else ""
        )
        lock_path = Path("/install/.quassel.lock")
        lock_kv = parse_lock_file_kv(lock_path)
        phase.artifacts["config_after_install"] = {
            "etc_default_quasselcore": defaults_text,
            "af_version": af_ver_text,
            "lock_kv": lock_kv,
        }
        record_phase_assertion(
            phase,
            "quassel_defaults_custom_port_and_version_recorded",
            f'PORT="{custom_install_port}"' in defaults_text
            and 'LISTEN="0.0.0.0"' in defaults_text
            and bool(af_ver_text)
            and lock_kv.get("version") == af_ver_text
            and lock_kv.get("engine") == "declarative_rust",
            {
                "port": custom_install_port,
                "version_non_empty": True,
                "engine": "declarative_rust",
            },
            phase.artifacts["config_after_install"],
        )

        dropin_path = Path("/etc/systemd/system/quasselcore.service.d/aetherflow-sandbox.conf")
        dropin_text = (
            dropin_path.read_text(encoding="utf-8", errors="replace")
            if dropin_path.is_file()
            else ""
        )
        phase.artifacts["sandbox_dropin"] = {
            "path": str(dropin_path),
            "exists": dropin_path.is_file(),
            "content": dropin_text,
        }
        record_phase_assertion(
            phase,
            "quassel_systemd_sandbox_dropin_applied",
            dropin_path.is_file()
            and "NoNewPrivileges=yes" in dropin_text
            and "ProtectSystem=strict" in dropin_text
            and "/var/lib/quassel" in dropin_text,
            {"exists": True, "NoNewPrivileges": "yes", "ProtectSystem": "strict"},
            phase.artifacts["sandbox_dropin"],
        )

        unit_state_install = query_systemd_unit_state("quasselcore.service", work_root)
        phase.commands.extend(unit_state_install.pop("commands"))
        phase.artifacts["systemd_after_install"] = unit_state_install
        record_phase_assertion(
            phase,
            "quasselcore_systemd_service_active_with_main_pid",
            unit_state_install["is_active_stdout"] == "active"
            and int(unit_state_install["main_pid"]) > 0,
            {"is_active": "active", "main_pid_gt_0": True},
            {
                "is_active": unit_state_install["is_active_stdout"],
                "main_pid": unit_state_install["main_pid"],
                "properties": unit_state_install["properties"],
            },
        )

        listen_probe_install = wait_for_tcp_listener("127.0.0.1", custom_install_port, timeout_seconds=15.0)
        phase.artifacts["listen_probe_install"] = listen_probe_install
        record_phase_assertion(
            phase,
            "quasselcore_listening_on_custom_port_4244",
            bool(listen_probe_install["listening"]),
            {"listening": True, "port": custom_install_port},
            listen_probe_install,
        )

        sqlite_fixture_path = Path("/var/lib/quassel/quassel-storage.sqlite")
        fixture_info = create_labeled_quassel_sqlite_fixture(sqlite_fixture_path, "quasselcore")
        phase.artifacts["test_provisioning_sqlite_fixture"] = fixture_info
        cert_snap_before = snapshot_sentinel(cert_path)
        sqlite_snap_before = snapshot_sentinel(sqlite_fixture_path)

        update_ex = perform_package_uds_request(
            str(sock_keep),
            "POST",
            "/v1/package",
            body={
                "action": "update",
                "package_id": "quassel",
                "script_name": "updatepackage-quassel",
                "app_port": custom_update_port,
            },
            timeout=600.0,
        )
        phase.artifacts["uds_update_exchange"] = asdict(update_ex)
        ok_upd, upd_detail = evaluate_package_stream_exchange(
            update_ex,
            expect_http_status=200,
            expected_engine="declarative_rust",
            expect_success=True,
        )
        record_phase_assertion(
            phase,
            "quassel_uds_native_update_stream_succeeded",
            ok_upd,
            "HTTP 200 + declarative_rust + progress 100%",
            upd_detail,
        )

        cert_unchanged_upd, cert_drifts_upd = verify_sentinel_unchanged(
            cert_snap_before,
            snapshot_sentinel(cert_path),
        )
        sqlite_unchanged_upd, sqlite_drifts_upd = verify_sentinel_unchanged(
            sqlite_snap_before,
            snapshot_sentinel(sqlite_fixture_path),
        )
        defaults_after_upd = (
            defaults_path.read_text(encoding="utf-8", errors="replace")
            if defaults_path.is_file()
            else ""
        )
        record_phase_assertion(
            phase,
            "quassel_update_preserved_tls_cert_and_sqlite_fixture_and_updated_port",
            cert_unchanged_upd
            and sqlite_unchanged_upd
            and f'PORT="{custom_update_port}"' in defaults_after_upd,
            {
                "cert_unchanged": True,
                "sqlite_unchanged": True,
                "port": custom_update_port,
            },
            {
                "cert_drifts": cert_drifts_upd,
                "sqlite_drifts": sqlite_drifts_upd,
                "defaults": defaults_after_upd,
            },
        )

        remove_keep_cmd = run_recorded_command(
            [
                str(af_bin),
                "--socket",
                str(sock_keep),
                "--json",
                "package",
                "remove",
                "quassel",
            ],
            cwd=work_root,
            timeout=600.0,
        )
        phase.commands.append(remove_keep_cmd)
        ok_rem_keep, rem_keep_payload, rem_keep_detail = evaluate_cli_envelope(
            remove_keep_cmd.stdout,
            expected_status="ok",
        )
        record_phase_assertion(
            phase,
            "quassel_remove_with_delete_data_false_succeeded",
            remove_keep_cmd.exit_code == 0 and ok_rem_keep,
            {"exit_code": 0, "status": "ok"},
            {
                "exit_code": remove_keep_cmd.exit_code,
                "detail": rem_keep_detail,
                "payload": rem_keep_payload,
            },
        )

        cert_unchanged_rem, cert_drifts_rem = verify_sentinel_unchanged(
            cert_snap_before,
            snapshot_sentinel(cert_path),
        )
        sqlite_unchanged_rem, sqlite_drifts_rem = verify_sentinel_unchanged(
            sqlite_snap_before,
            snapshot_sentinel(sqlite_fixture_path),
        )
        non_purge_state = {
            "lock_exists": lock_path.exists(),
            "defaults_exists": defaults_path.exists(),
            "af_version_exists": af_ver_path.exists(),
            "dropin_dir_exists": Path("/etc/systemd/system/quasselcore.service.d").exists(),
            "cert_preserved": cert_unchanged_rem,
            "sqlite_fixture_preserved": sqlite_unchanged_rem,
        }
        phase.artifacts["after_remove_preserve_data"] = non_purge_state
        record_phase_assertion(
            phase,
            "quassel_remove_delete_data_false_preserves_cert_and_sqlite_while_removing_runtime_files",
            not non_purge_state["lock_exists"]
            and not non_purge_state["defaults_exists"]
            and not non_purge_state["af_version_exists"]
            and not non_purge_state["dropin_dir_exists"]
            and non_purge_state["cert_preserved"]
            and non_purge_state["sqlite_fixture_preserved"],
            {
                "lock_exists": False,
                "defaults_exists": False,
                "af_version_exists": False,
                "dropin_dir_exists": False,
                "cert_preserved": True,
                "sqlite_fixture_preserved": True,
            },
            {
                **non_purge_state,
                "cert_drifts": cert_drifts_rem,
                "sqlite_drifts": sqlite_drifts_rem,
            },
        )

        daemon_keep.stop()

        if cert_path.exists():
            cert_path.unlink()

        daemon_purge = build_native_runner_daemon(
            api_bin=api_bin,
            socket_path=sock_purge,
            log_path=log_purge,
            delete_data=True,
        )
        daemon_purge.start()

        reinstall_cmd = run_recorded_command(
            [
                str(af_bin),
                "--socket",
                str(sock_purge),
                "--json",
                "package",
                "install",
                "quassel",
                "--port",
                str(custom_install_port),
            ],
            cwd=work_root,
            timeout=600.0,
        )
        phase.commands.append(reinstall_cmd)
        ok_reinst, reinst_payload, reinst_detail = evaluate_cli_envelope(
            reinstall_cmd.stdout,
            expected_status="ok",
        )
        cert_reinst_exists = cert_path.is_file() and not cert_path.is_symlink()
        cert_reinst_mode = (
            f"{stat.S_IMODE(cert_path.stat().st_mode):04o}" if cert_reinst_exists else None
        )
        cert_reinst_cmd = run_recorded_command(
            [
                "openssl",
                "x509",
                "-in",
                str(cert_path),
                "-noout",
                "-subject",
                "-fingerprint",
                "-sha256",
            ],
            cwd=work_root,
        )
        phase.commands.append(cert_reinst_cmd)
        sqlite_unchanged_reinst, sqlite_drifts_reinst = verify_sentinel_unchanged(
            sqlite_snap_before,
            snapshot_sentinel(sqlite_fixture_path),
        )
        record_phase_assertion(
            phase,
            "quassel_reinstall_via_af_cli_generates_cn_cert_when_absent_and_preserves_sqlite",
            reinstall_cmd.exit_code == 0
            and ok_reinst
            and cert_reinst_exists
            and cert_reinst_mode == "0600"
            and cert_reinst_cmd.exit_code == 0
            and "quassel.aether.local" in cert_reinst_cmd.stdout
            and sqlite_unchanged_reinst,
            {
                "exit_code": 0,
                "cert_cn": "quassel.aether.local",
                "cert_mode": "0600",
                "sqlite_preserved": True,
            },
            {
                "exit_code": reinstall_cmd.exit_code,
                "detail": reinst_detail,
                "payload": reinst_payload,
                "cert_mode": cert_reinst_mode,
                "openssl_stdout": cert_reinst_cmd.stdout.strip(),
                "sqlite_preserved": sqlite_unchanged_reinst,
            },
        )

        purge_ex = perform_package_uds_request(
            str(sock_purge),
            "POST",
            "/v1/package",
            body={
                "action": "remove",
                "package_id": "quassel",
                "script_name": "removepackage-quassel",
                "app_port": 0,
            },
            timeout=600.0,
        )
        phase.artifacts["uds_purge_exchange"] = asdict(purge_ex)
        ok_purge, purge_detail = evaluate_package_stream_exchange(
            purge_ex,
            expect_http_status=200,
            expected_engine="declarative_rust",
            expect_success=True,
        )
        purge_paths_state = {
            "/install/.quassel.lock": lock_path.exists(),
            "/etc/default/quasselcore": defaults_path.exists(),
            "/var/lib/quassel": Path("/var/lib/quassel").exists(),
            "/var/log/quassel": Path("/var/log/quassel").exists(),
        }
        phase.artifacts["after_explicit_purge"] = purge_paths_state
        record_phase_assertion(
            phase,
            "quassel_explicit_purge_delete_data_true_removes_data_and_log_directories",
            ok_purge and not any(purge_paths_state.values()),
            {"stream_ok": True, "remaining_paths": False},
            {"stream_detail": purge_detail, "paths_exist": purge_paths_state},
        )
    except Exception as error_exc:
        phase.failure_diagnostics.append(
            f"Unhandled exception in phase 3: {type(error_exc).__name__}: {error_exc}"
        )
        record_phase_assertion(phase, "phase3_unhandled_exception", False, "no exception", str(error_exc))
    finally:
        daemon_keep.stop()
        if daemon_purge is not None:
            daemon_purge.stop()

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - started_mono) * 1000.0, 2)
    if any(not assertion_item.passed for assertion_item in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_4_threadfin_lifecycle(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    started_mono = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="threadfin_native_lifecycle_and_artifact_verification",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    custom_install_port = 34405
    custom_update_port = 34406
    sock_uncached = work_root / "run/phase4_threadfin_uncached.sock"
    log_uncached = work_root / "logs/phase4_threadfin_uncached.log"
    sock_keep = work_root / "run/phase4_threadfin_keep.sock"
    log_keep = work_root / "logs/phase4_threadfin_keep.log"
    sock_purge = work_root / "run/phase4_threadfin_purge.sock"
    log_purge = work_root / "logs/phase4_threadfin_purge.log"
    real_cache_dir = work_root / "threadfin_upstream_cache"
    real_cache_dir.mkdir(parents=True, exist_ok=True)

    daemon_uncached = build_native_runner_daemon(
        api_bin=api_bin,
        socket_path=sock_uncached,
        log_path=log_uncached,
        delete_data=False,
    )
    daemon_keep: Optional[RunnerDaemonProcess] = None
    daemon_purge: Optional[RunnerDaemonProcess] = None

    try:
        daemon_uncached.start()

        uncached_ex = perform_package_uds_request(
            str(sock_uncached),
            "POST",
            "/v1/package",
            body={
                "action": "install",
                "package_id": "threadfin",
                "script_name": "installpackage-threadfin",
                "app_port": custom_install_port,
            },
            timeout=600.0,
        )
        phase.artifacts["uds_uncached_install_exchange"] = asdict(uncached_ex)
        ok_uncached, uncached_detail = evaluate_package_stream_exchange(
            uncached_ex,
            expect_http_status=200,
            expected_engine="declarative_rust",
            expect_success=True,
        )
        record_phase_assertion(
            phase,
            "threadfin_uds_native_install_stream_succeeded",
            ok_uncached,
            "HTTP 200 + declarative_rust + progress 100% from direct upstream URL",
            uncached_detail,
        )
        daemon_uncached.stop()

        upstream_compat_url = (
            f"https://github.com/Threadfin/Threadfin/releases/download/"
            f"{THREADFIN_PINNED_VERSION}/Threadfin_linux_amd64_glibc_2.31_compat"
        )
        staged_compat_path = real_cache_dir / "Threadfin_linux_amd64_compat"
        curl_stage_cmd = run_recorded_command(
            [
                "curl",
                "-fsSL",
                "-o",
                str(staged_compat_path),
                upstream_compat_url,
            ],
            cwd=work_root,
            timeout=180.0,
        )
        phase.commands.append(curl_stage_cmd)

        daemon_keep = build_native_runner_daemon(
            api_bin=api_bin,
            socket_path=sock_keep,
            log_path=log_keep,
            delete_data=False,
            extra_env={"AETHERFLOW_ARTIFACT_CACHE_DIR": str(real_cache_dir)},
        )
        daemon_keep.start()

        install_ex = perform_package_uds_request(
            str(sock_keep),
            "POST",
            "/v1/package",
            body={
                "action": "install",
                "package_id": "threadfin",
                "script_name": "installpackage-threadfin",
                "app_port": custom_install_port,
            },
            timeout=600.0,
        )
        phase.artifacts["uds_cached_install_exchange"] = asdict(install_ex)
        ok_inst, inst_detail = evaluate_package_stream_exchange(
            install_ex,
            expect_http_status=200,
            expected_engine="declarative_rust",
            expect_success=True,
        )
        record_phase_assertion(
            phase,
            "threadfin_uds_native_install_with_verified_upstream_cache_succeeded",
            ok_inst,
            "HTTP 200 + declarative_rust + progress 100%",
            inst_detail,
        )

        binary_path = Path("/usr/local/bin/threadfin")
        elf_meta = inspect_elf_binary_metadata(binary_path)
        phase.artifacts["threadfin_binary_elf"] = elf_meta
        record_phase_assertion(
            phase,
            "threadfin_binary_pinned_sha256_and_elf_amd64_verified",
            elf_meta["exists"]
            and elf_meta["is_elf"]
            and elf_meta["e_machine"] == 62
            and elf_meta["arch"] == "amd64"
            and elf_meta["mode_octal"] == "0755"
            and elf_meta["sha256"] in ALLOWED_THREADFIN_AMD64_DIGESTS,
            {
                "is_elf": True,
                "e_machine": 62,
                "arch": "amd64",
                "mode_octal": "0755",
                "sha256_in": list(ALLOWED_THREADFIN_AMD64_DIGESTS),
            },
            elf_meta,
        )

        af_ver_path = Path("/var/lib/threadfin/.af-version")
        af_ver_text = (
            af_ver_path.read_text(encoding="utf-8", errors="replace").strip()
            if af_ver_path.is_file()
            else ""
        )
        unit_file_path = Path("/etc/systemd/system/threadfin.service")
        unit_file_text = (
            unit_file_path.read_text(encoding="utf-8", errors="replace")
            if unit_file_path.is_file()
            else ""
        )
        dropin_path = Path("/etc/systemd/system/threadfin.service.d/aetherflow-sandbox.conf")
        dropin_text = (
            dropin_path.read_text(encoding="utf-8", errors="replace")
            if dropin_path.is_file()
            else ""
        )
        lock_path = Path("/install/.threadfin.lock")
        lock_kv = parse_lock_file_kv(lock_path)
        phase.artifacts["config_after_install"] = {
            "af_version": af_ver_text,
            "unit_file": unit_file_text,
            "sandbox_dropin": dropin_text,
            "lock_kv": lock_kv,
        }
        record_phase_assertion(
            phase,
            "threadfin_version_unit_port_sandbox_and_lock_verified",
            af_ver_text == THREADFIN_PINNED_VERSION
            and f"-port={custom_install_port}" in unit_file_text
            and "-config=/var/lib/threadfin/conf" in unit_file_text
            and dropin_path.is_file()
            and "PrivateDevices=no" in dropin_text
            and "/var/lib/threadfin" in dropin_text
            and lock_kv.get("version") == THREADFIN_PINNED_VERSION
            and lock_kv.get("engine") == "declarative_rust",
            {
                "version": THREADFIN_PINNED_VERSION,
                "port": custom_install_port,
                "sandbox_dropin": True,
                "engine": "declarative_rust",
            },
            phase.artifacts["config_after_install"],
        )

        unit_state_install = query_systemd_unit_state("threadfin.service", work_root)
        phase.commands.extend(unit_state_install.pop("commands"))
        phase.artifacts["systemd_after_install"] = unit_state_install
        record_phase_assertion(
            phase,
            "threadfin_systemd_service_active_with_main_pid",
            unit_state_install["is_active_stdout"] == "active"
            and int(unit_state_install["main_pid"]) > 0,
            {"is_active": "active", "main_pid_gt_0": True},
            {
                "is_active": unit_state_install["is_active_stdout"],
                "main_pid": unit_state_install["main_pid"],
            },
        )

        listen_probe = wait_for_tcp_listener("127.0.0.1", custom_install_port, timeout_seconds=45.0)
        http_probe = probe_http_endpoint(f"http://127.0.0.1:{custom_install_port}/web/", timeout_seconds=15.0)
        phase.artifacts["network_after_install"] = {
            "listen_probe": listen_probe,
            "http_probe": http_probe,
        }
        record_phase_assertion(
            phase,
            "threadfin_daemon_listening_and_serving_http_on_custom_port_34405",
            bool(listen_probe["listening"]) and bool(http_probe["reachable"]),
            {"listening": True, "http_reachable": True, "port": custom_install_port},
            phase.artifacts["network_after_install"],
        )

        fixture_conf_path = Path("/var/lib/threadfin/conf/af_test_provisioning_sentinel.json")
        fixture_info = create_labeled_threadfin_config_fixture(fixture_conf_path, "threadfin")
        phase.artifacts["test_provisioning_conf_fixture"] = fixture_info
        fixture_snap_before = snapshot_sentinel(fixture_conf_path)

        update_ex = perform_package_uds_request(
            str(sock_keep),
            "POST",
            "/v1/package",
            body={
                "action": "update",
                "package_id": "threadfin",
                "script_name": "updatepackage-threadfin",
                "app_port": custom_update_port,
            },
            timeout=600.0,
        )
        phase.artifacts["uds_update_exchange"] = asdict(update_ex)
        ok_upd, upd_detail = evaluate_package_stream_exchange(
            update_ex,
            expect_http_status=200,
            expected_engine="declarative_rust",
            expect_success=True,
        )
        fixture_unchanged_upd, fixture_drifts_upd = verify_sentinel_unchanged(
            fixture_snap_before,
            snapshot_sentinel(fixture_conf_path),
        )
        unit_after_upd = (
            unit_file_path.read_text(encoding="utf-8", errors="replace")
            if unit_file_path.is_file()
            else ""
        )
        listen_upd_probe = wait_for_tcp_listener("127.0.0.1", custom_update_port, timeout_seconds=45.0)
        record_phase_assertion(
            phase,
            "threadfin_update_preserved_conf_fixture_and_switched_to_port_34406",
            ok_upd
            and fixture_unchanged_upd
            and f"-port={custom_update_port}" in unit_after_upd
            and bool(listen_upd_probe["listening"]),
            {
                "stream_ok": True,
                "fixture_unchanged": True,
                "port": custom_update_port,
                "listening": True,
            },
            {
                "stream_detail": upd_detail,
                "fixture_drifts": fixture_drifts_upd,
                "listen_upd_probe": listen_upd_probe,
            },
        )

        remove_keep_cmd = run_recorded_command(
            [
                str(af_bin),
                "--socket",
                str(sock_keep),
                "--json",
                "package",
                "remove",
                "threadfin",
            ],
            cwd=work_root,
            timeout=600.0,
        )
        phase.commands.append(remove_keep_cmd)
        ok_rem_keep, rem_keep_payload, rem_keep_detail = evaluate_cli_envelope(
            remove_keep_cmd.stdout,
            expected_status="ok",
        )
        fixture_unchanged_rem, fixture_drifts_rem = verify_sentinel_unchanged(
            fixture_snap_before,
            snapshot_sentinel(fixture_conf_path),
        )
        non_purge_state = {
            "lock_exists": lock_path.exists(),
            "binary_exists": binary_path.exists(),
            "af_version_exists": af_ver_path.exists(),
            "unit_file_exists": unit_file_path.exists(),
            "dropin_dir_exists": Path("/etc/systemd/system/threadfin.service.d").exists(),
            "conf_fixture_preserved": fixture_unchanged_rem,
        }
        phase.artifacts["after_remove_preserve_data"] = non_purge_state
        record_phase_assertion(
            phase,
            "threadfin_remove_delete_data_false_preserves_var_lib_threadfin_conf_while_removing_binary_and_unit",
            remove_keep_cmd.exit_code == 0
            and ok_rem_keep
            and not non_purge_state["lock_exists"]
            and not non_purge_state["binary_exists"]
            and not non_purge_state["af_version_exists"]
            and not non_purge_state["unit_file_exists"]
            and not non_purge_state["dropin_dir_exists"]
            and non_purge_state["conf_fixture_preserved"],
            {
                "exit_code": 0,
                "lock_exists": False,
                "binary_exists": False,
                "unit_file_exists": False,
                "conf_fixture_preserved": True,
            },
            {
                **non_purge_state,
                "detail": rem_keep_detail,
                "payload": rem_keep_payload,
                "fixture_drifts": fixture_drifts_rem,
            },
        )

        daemon_keep.stop()

        daemon_purge = build_native_runner_daemon(
            api_bin=api_bin,
            socket_path=sock_purge,
            log_path=log_purge,
            delete_data=True,
            extra_env={"AETHERFLOW_ARTIFACT_CACHE_DIR": str(real_cache_dir)},
        )
        daemon_purge.start()

        reinstall_cmd = run_recorded_command(
            [
                str(af_bin),
                "--socket",
                str(sock_purge),
                "--json",
                "package",
                "install",
                "threadfin",
                "--port",
                str(custom_install_port),
            ],
            cwd=work_root,
            timeout=600.0,
        )
        phase.commands.append(reinstall_cmd)
        ok_reinst, reinst_payload, reinst_detail = evaluate_cli_envelope(
            reinstall_cmd.stdout,
            expected_status="ok",
        )
        fixture_after_reinst = snapshot_sentinel(fixture_conf_path)
        record_phase_assertion(
            phase,
            "threadfin_reinstall_via_af_cli_preserves_existing_conf_fixture_content",
            reinstall_cmd.exit_code == 0
            and ok_reinst
            and fixture_after_reinst.exists
            and fixture_after_reinst.sha256 == fixture_snap_before.sha256,
            {
                "exit_code": 0,
                "fixture_sha256": fixture_snap_before.sha256,
            },
            {
                "exit_code": reinstall_cmd.exit_code,
                "detail": reinst_detail,
                "payload": reinst_payload,
                "fixture_after_reinst": asdict(fixture_after_reinst),
            },
        )

        purge_ex = perform_package_uds_request(
            str(sock_purge),
            "POST",
            "/v1/package",
            body={
                "action": "remove",
                "package_id": "threadfin",
                "script_name": "removepackage-threadfin",
                "app_port": 0,
            },
            timeout=600.0,
        )
        phase.artifacts["uds_purge_exchange"] = asdict(purge_ex)
        ok_purge, purge_detail = evaluate_package_stream_exchange(
            purge_ex,
            expect_http_status=200,
            expected_engine="declarative_rust",
            expect_success=True,
        )
        purge_paths_state = {
            "/install/.threadfin.lock": lock_path.exists(),
            "/usr/local/bin/threadfin": binary_path.exists(),
            "/etc/systemd/system/threadfin.service": unit_file_path.exists(),
            "/var/lib/threadfin": Path("/var/lib/threadfin").exists(),
        }
        phase.artifacts["after_explicit_purge"] = purge_paths_state
        record_phase_assertion(
            phase,
            "threadfin_explicit_purge_delete_data_true_removes_var_lib_threadfin_completely",
            ok_purge and not any(purge_paths_state.values()),
            {"stream_ok": True, "remaining_paths": False},
            {"stream_detail": purge_detail, "paths_exist": purge_paths_state},
        )
    except Exception as error_exc:
        phase.failure_diagnostics.append(
            f"Unhandled exception in phase 4: {type(error_exc).__name__}: {error_exc}"
        )
        record_phase_assertion(phase, "phase4_unhandled_exception", False, "no exception", str(error_exc))
    finally:
        daemon_uncached.stop()
        if daemon_keep is not None:
            daemon_keep.stop()
        if daemon_purge is not None:
            daemon_purge.stop()

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - started_mono) * 1000.0, 2)
    if any(not assertion_item.passed for assertion_item in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_5_cancellation_serialization_and_rollback(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    started_mono = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="cancellation_serialization_and_rollback_safety",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    corrupt_cache_dir = work_root / "corrupt_artifact_cache"
    corrupt_cache_dir.mkdir(parents=True, exist_ok=True)
    corrupt_binary_path = corrupt_cache_dir / "Threadfin_linux_amd64_compat"
    corrupt_elf_bytes = bytearray(4096)
    corrupt_elf_bytes[0:4] = b"\x7fELF"
    corrupt_elf_bytes[5] = 1
    corrupt_elf_bytes[18:20] = (62).to_bytes(2, byteorder="little")
    corrupt_binary_path.write_bytes(bytes(corrupt_elf_bytes))

    sock_cancel = work_root / "run/phase5_cancel.sock"
    log_cancel = work_root / "logs/phase5_cancel.log"
    sock_rollback = work_root / "run/phase5_rollback.sock"
    log_rollback = work_root / "logs/phase5_rollback.log"

    daemon_cancel = build_native_runner_daemon(
        api_bin=api_bin,
        socket_path=sock_cancel,
        log_path=log_cancel,
        delete_data=True,
    )
    daemon_rollback = build_native_runner_daemon(
        api_bin=api_bin,
        socket_path=sock_rollback,
        log_path=log_rollback,
        delete_data=True,
        extra_env={"AETHERFLOW_ARTIFACT_CACHE_DIR": str(corrupt_cache_dir)},
    )

    flock_path = Path("/install/.af-package-executor.flock")
    flock_path.parent.mkdir(parents=True, exist_ok=True)
    threadfin_lock_path = Path("/install/.threadfin.lock")
    if threadfin_lock_path.exists():
        threadfin_lock_path.unlink()

    try:
        daemon_cancel.start()

        inflight_results: List[PackageUdsStreamRecord] = []

        def _inflight_worker() -> None:
            inflight_results.append(
                perform_package_uds_request(
                    str(sock_cancel),
                    "POST",
                    "/v1/package",
                    body={
                        "action": "install",
                        "package_id": "threadfin",
                        "script_name": "installpackage-threadfin",
                        "app_port": 34407,
                    },
                    timeout=120.0,
                )
            )

        with flock_path.open("a+", encoding="utf-8") as flock_handle:
            fcntl.flock(flock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            try:
                worker_thread = threading.Thread(target=_inflight_worker, daemon=True)
                worker_thread.start()
                time.sleep(0.35)

                dup_ex = perform_package_uds_request(
                    str(sock_cancel),
                    "POST",
                    "/v1/package",
                    body={
                        "action": "install",
                        "package_id": "threadfin",
                        "script_name": "installpackage-threadfin",
                        "app_port": 34407,
                    },
                    timeout=30.0,
                )
                phase.artifacts["duplicate_inflight_exchange"] = asdict(dup_ex)
                ok_dup, dup_detail = evaluate_package_stream_exchange(
                    dup_ex,
                    expect_http_status=200,
                    expected_engine="declarative_rust",
                    expect_success=False,
                    expected_error_substring="already has an operation in flight",
                )
                record_phase_assertion(
                    phase,
                    "duplicate_inflight_package_execution_rejected_fail_closed",
                    ok_dup,
                    "runner exit error containing 'already has an operation in flight'",
                    dup_detail,
                )

                cancel_cmd = run_recorded_command(
                    [
                        str(af_bin),
                        "--socket",
                        str(sock_cancel),
                        "--json",
                        "package",
                        "cancel",
                        "threadfin",
                    ],
                    cwd=work_root,
                )
                phase.commands.append(cancel_cmd)
                ok_cancel_env, cancel_payload, cancel_detail = evaluate_cli_envelope(
                    cancel_cmd.stdout,
                    expected_status="ok",
                )
                cancel_data = (cancel_payload or {}).get("data") or {}
                cancel_runner_resp = cancel_data.get("runner_response") or {}
                record_phase_assertion(
                    phase,
                    "af_cli_package_cancel_signalled_inflight_execution",
                    cancel_cmd.exit_code == 0
                    and ok_cancel_env
                    and "cancellation signalled"
                    in str(cancel_runner_resp.get("output", "")).lower(),
                    {"exit_code": 0, "output_contains": "cancellation signalled"},
                    {
                        "exit_code": cancel_cmd.exit_code,
                        "detail": cancel_detail,
                        "payload": cancel_payload,
                    },
                )

                worker_thread.join(timeout=15.0)
            finally:
                fcntl.flock(flock_handle.fileno(), fcntl.LOCK_UN)

        cancelled_ex = inflight_results[0] if inflight_results else None
        phase.artifacts["cancelled_inflight_exchange"] = (
            asdict(cancelled_ex) if cancelled_ex is not None else None
        )
        ok_cancelled = (
            cancelled_ex is not None
            and evaluate_package_stream_exchange(
                cancelled_ex,
                expect_http_status=200,
                expected_engine="declarative_rust",
                expect_success=False,
                expected_error_substring="cancelled",
            )[0]
        )
        record_phase_assertion(
            phase,
            "cancelled_execution_aborts_without_writing_false_positive_lockfile",
            ok_cancelled and not threadfin_lock_path.exists() and flock_path.is_file(),
            {
                "cancelled_stream_error": True,
                "threadfin_lock_exists": False,
                "persistent_flock_exists": True,
            },
            {
                "cancelled_error": cancelled_ex.runner_exit_error if cancelled_ex else None,
                "threadfin_lock_exists": threadfin_lock_path.exists(),
                "persistent_flock_exists": flock_path.is_file(),
            },
        )

        daemon_cancel.stop()

        prior_bin_path = Path("/usr/local/bin/threadfin")
        prior_bin_path.parent.mkdir(parents=True, exist_ok=True)
        prior_bin_path.write_text("PRIOR_SENTINEL_BINARY_CONTENT_DO_NOT_CLOBBER\n", encoding="utf-8")
        os.chmod(prior_bin_path, 0o755)
        prior_snap_before = snapshot_sentinel(prior_bin_path)

        daemon_rollback.start()
        rollback_ex = perform_package_uds_request(
            str(sock_rollback),
            "POST",
            "/v1/package",
            body={
                "action": "install",
                "package_id": "threadfin",
                "script_name": "installpackage-threadfin",
                "app_port": 34408,
            },
            timeout=300.0,
        )
        phase.artifacts["rollback_corrupt_artifact_exchange"] = asdict(rollback_ex)
        ok_rb, rb_detail = evaluate_package_stream_exchange(
            rollback_ex,
            expect_http_status=200,
            expected_engine="declarative_rust",
            expect_success=False,
            expected_error_substring="SHA-256 mismatch",
        )
        prior_unchanged, prior_drifts = verify_sentinel_unchanged(
            prior_snap_before,
            snapshot_sentinel(prior_bin_path),
        )
        leftover_backups = list(Path("/usr/local/bin").glob("threadfin.bak-af.*"))
        record_phase_assertion(
            phase,
            "corrupt_artifact_sha256_mismatch_fails_closed_and_preserves_prior_binary_without_lockfile",
            ok_rb
            and prior_unchanged
            and not threadfin_lock_path.exists()
            and len(leftover_backups) == 0,
            {
                "sha256_mismatch_rejected": True,
                "prior_binary_unchanged": True,
                "lock_exists": False,
                "leftover_backups": 0,
            },
            {
                "stream_detail": rb_detail,
                "prior_drifts": prior_drifts,
                "lock_exists": threadfin_lock_path.exists(),
                "leftover_backups": [str(item) for item in leftover_backups],
            },
        )
    except Exception as error_exc:
        phase.failure_diagnostics.append(
            f"Unhandled exception in phase 5: {type(error_exc).__name__}: {error_exc}"
        )
        record_phase_assertion(phase, "phase5_unhandled_exception", False, "no exception", str(error_exc))
    finally:
        daemon_cancel.stop()
        daemon_rollback.stop()
        for cleanup_path in (
            Path("/usr/local/bin/threadfin"),
            Path("/var/lib/threadfin"),
            Path("/install/.threadfin.lock"),
        ):
            if cleanup_path.is_dir() and not cleanup_path.is_symlink():
                shutil.rmtree(cleanup_path, ignore_errors=True)
            elif cleanup_path.exists():
                try:
                    cleanup_path.unlink()
                except OSError:
                    pass
        subprocess.run(["userdel", "threadfin"], check=False, capture_output=True)
        subprocess.run(["groupdel", "threadfin"], check=False, capture_output=True)

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - started_mono) * 1000.0, 2)
    if any(not assertion_item.passed for assertion_item in phase.assertions):
        phase.status = "failed"
    return phase


def execute_native_package_guest_drill_suite(
    *,
    confirm_disposable_guest: bool,
    work_root: str,
    api_bin: str,
    af_bin: str,
    guest_marker_file: str = DEFAULT_GUEST_MARKER_FILE,
    keep_work_root: bool = False,
) -> Dict[str, Any]:
    guardrail_info = verify_guest_execution_guardrails(
        confirm_disposable_guest=confirm_disposable_guest,
        work_root=work_root,
        api_bin=api_bin,
        af_bin=af_bin,
        guest_marker_file=guest_marker_file,
    )

    work_root_path = Path(guardrail_info["work_root"])
    api_bin_path = Path(guardrail_info["api_bin"])
    af_bin_path = Path(guardrail_info["af_bin"])

    if work_root_path.exists():
        shutil.rmtree(work_root_path)
    work_root_path.mkdir(parents=True, exist_ok=True)

    suite_started = utc_now_iso()
    started_mono = time.monotonic()
    phases: List[DrillPhaseResult] = []
    try:
        phases.append(
            run_phase_1_native_provenance(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
                guardrail_info=guardrail_info,
            )
        )
        phases.append(
            run_phase_2_fail2ban_lifecycle(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
            )
        )
        phases.append(
            run_phase_3_quassel_lifecycle(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
            )
        )
        phases.append(
            run_phase_4_threadfin_lifecycle(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
            )
        )
        phases.append(
            run_phase_5_cancellation_serialization_and_rollback(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
            )
        )
    finally:
        if not keep_work_root and work_root_path.exists():
            shutil.rmtree(work_root_path, ignore_errors=True)

    evaluation = evaluate_native_package_suite_status(phases)
    suite_completed = utc_now_iso()
    return {
        "schema_version": NATIVE_PACKAGE_HARNESS_SCHEMA_VERSION,
        "started_at": suite_started,
        "completed_at": suite_completed,
        "duration_ms": round((time.monotonic() - started_mono) * 1000.0, 2),
        "guardrails": guardrail_info,
        "evaluation": evaluation,
        "phases": [asdict(phase_item) for phase_item in phases],
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AetherFlow v4 Native Package Guest Drills Harness (disposable QEMU/systemd VM only)."
    )
    parser.add_argument(
        "--confirm-disposable-guest",
        action="store_true",
        help="Required explicit confirmation that execution is inside a disposable QEMU/systemd guest.",
    )
    parser.add_argument(
        "--work-root",
        default=f"{ALLOWED_WORK_ROOT_PREFIX}-native-run",
        help=f"Isolated scratch root inside the guest (must start with {ALLOWED_WORK_ROOT_PREFIX}).",
    )
    parser.add_argument(
        "--api-bin",
        required=True,
        help="Absolute path to the staged aetherflow-api binary inside the guest (never /opt/AetherFlow).",
    )
    parser.add_argument(
        "--af-bin",
        required=True,
        help="Absolute path to the staged af binary inside the guest (never /opt/AetherFlow).",
    )
    parser.add_argument(
        "--guest-marker-file",
        default=DEFAULT_GUEST_MARKER_FILE,
        help=f"Path to disposable guest marker file under /run (default: {DEFAULT_GUEST_MARKER_FILE}).",
    )
    parser.add_argument(
        "--json-out",
        default="",
        help="Optional path to write the JSON drill report.",
    )
    parser.add_argument(
        "--keep-work-root",
        action="store_true",
        help="Preserve the isolated --work-root directory after execution for post-mortem inspection.",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_arg_parser()
    parsed_args = parser.parse_args(argv)
    try:
        report = execute_native_package_guest_drill_suite(
            confirm_disposable_guest=bool(parsed_args.confirm_disposable_guest),
            work_root=str(parsed_args.work_root),
            api_bin=str(parsed_args.api_bin),
            af_bin=str(parsed_args.af_bin),
            guest_marker_file=str(parsed_args.guest_marker_file),
            keep_work_root=bool(parsed_args.keep_work_root),
        )
    except GuestSafetyError as safety_exc:
        err_report = {
            "schema_version": NATIVE_PACKAGE_HARNESS_SCHEMA_VERSION,
            "timestamp": utc_now_iso(),
            "overall_status": "blocked_by_guest_safety_guardrail",
            "overall_passed": False,
            "error": str(safety_exc),
        }
        rendered_err = json.dumps(err_report, indent=2, sort_keys=True)
        if parsed_args.json_out:
            out_err_path = Path(parsed_args.json_out)
            out_err_path.parent.mkdir(parents=True, exist_ok=True)
            out_err_path.write_text(rendered_err + "\n", encoding="utf-8")
        print(rendered_err)
        return 2

    rendered = json.dumps(report, indent=2, sort_keys=True)
    if parsed_args.json_out:
        out_path = Path(parsed_args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["evaluation"]["overall_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
