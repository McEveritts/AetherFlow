#!/usr/bin/env python3
"""AetherFlow v4 Privileged Guest Drills Harness.

This stdlib-only Python harness executes ONLY inside a disposable QEMU/systemd
guest VM. It refuses to run on bare-metal hosts, on non-Linux systems, without
root privileges, without explicit disposable-guest markers, or with a work root
outside `/var/tmp/aetherflow-v4-guest-drills*`.

It exercises the real shipped `aetherflow-api` (including `aetherflow-api runner`
over Unix domain sockets) and `af` (`af-cli`) binaries—never mocks—and records
artifact SHA-256 digests, commands, exit statuses, effective UID/GID identities,
exact assertions, and failure diagnostics as structured JSON.
"""

from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import errno
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

try:
    import grp
    import pwd
except ImportError:  # pragma: no cover - Windows unit-test import fallback
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]


HARNESS_SCHEMA_VERSION = "aetherflow.v4.privileged_guest_drills.v1"

ALLOWED_WORK_ROOT_PREFIX = "/var/tmp/aetherflow-v4-guest-drills"
FORBIDDEN_HOST_PATHS: Tuple[str, ...] = (
    "/opt/AetherFlow",
    "/opt/aetherflow",
    "/run/aetherflow/runner.sock",
    "/var/lib/aetherflow",
    "/etc/aetherflow",
    "/etc/AetherFlow",
)

GUEST_ENV_VAR = "AETHERFLOW_DISPOSABLE_GUEST"
GUEST_ENV_REQUIRED_VALUE = "1"
DEFAULT_GUEST_MARKER_FILE = "/run/aetherflow-disposable-guest"
GUEST_MARKER_REQUIRED_TOKEN = "AETHERFLOW_DISPOSABLE_GUEST_V4"

QEMU_VIRT_IDENTIFIERS: Tuple[str, ...] = (
    "qemu",
    "kvm",
    "bochs",
    "standard pc",
)

MANDATORY_DRILL_PHASES: Tuple[str, ...] = (
    "binary_and_environment_provenance",
    "authorized_backup_roundtrip_with_live_wal",
    "arbitrary_root_and_sentinel_deletion_rejection",
    "unprivileged_user_and_socket_authorization_denial",
    "restore_integrity_uid_gid_mode_and_quiescence",
    "held_open_wal_snapshot_recovery",
)


class GuestSafetyError(RuntimeError):
    """Raised when disposable-guest guardrails fail closed."""


class DrillAssertionError(RuntimeError):
    """Raised when a drill phase fails closed."""


@dataclass(frozen=True)
class SentinelSnapshot:
    path: str
    exists: bool
    sha256: Optional[str]
    size_bytes: Optional[int]
    mode_octal: Optional[str]
    uid: Optional[int]
    gid: Optional[int]
    inode: Optional[int]


@dataclass
class AssertionRecord:
    name: str
    passed: bool
    expected: Any
    actual: Any
    detail: str = ""


@dataclass
class CommandRecord:
    argv: List[str]
    command_str: str
    cwd: str
    effective_uid: int
    effective_gid: int
    exit_code: int
    duration_ms: float
    stdout: str
    stderr: str
    parsed_json: Optional[Any] = None


@dataclass
class UdsExchangeRecord:
    socket_path: str
    method: str
    path: str
    effective_uid: int
    effective_gid: int
    request_body: Optional[Dict[str, Any]]
    http_status: Optional[int]
    raw_response: str
    runner_response: Optional[Dict[str, Any]]
    backup_payload: Optional[Dict[str, Any]]
    socket_error: Optional[str]
    duration_ms: float


@dataclass
class DrillPhaseResult:
    phase_id: str
    status: str  # "passed" | "failed" | "pending_contract"
    real_execution: bool
    started_at: str
    completed_at: str
    duration_ms: float
    assertions: List[AssertionRecord] = field(default_factory=list)
    commands: List[CommandRecord] = field(default_factory=list)
    uds_exchanges: List[UdsExchangeRecord] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    failure_diagnostics: List[str] = field(default_factory=list)
    contract_notes: List[str] = field(default_factory=list)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_sentinel(path: Path) -> SentinelSnapshot:
    resolved = str(path)
    if not path.exists() and not path.is_symlink():
        return SentinelSnapshot(
            path=resolved,
            exists=False,
            sha256=None,
            size_bytes=None,
            mode_octal=None,
            uid=None,
            gid=None,
            inode=None,
        )
    st = os.lstat(path)
    is_reg = stat.S_ISREG(st.st_mode)
    return SentinelSnapshot(
        path=resolved,
        exists=True,
        sha256=compute_file_sha256(path) if is_reg else None,
        size_bytes=int(st.st_size),
        mode_octal=f"{stat.S_IMODE(st.st_mode):04o}",
        uid=int(st.st_uid),
        gid=int(st.st_gid),
        inode=int(st.st_ino),
    )


def verify_sentinel_unchanged(
    before: SentinelSnapshot,
    after: SentinelSnapshot,
) -> Tuple[bool, List[str]]:
    drifts: List[str] = []
    if not before.exists:
        drifts.append(f"sentinel did not exist before drill: {before.path}")
    if not after.exists:
        drifts.append(f"sentinel was deleted or missing after drill: {after.path}")
        return False, drifts
    if before.sha256 != after.sha256:
        drifts.append(f"sha256 drift: before={before.sha256} after={after.sha256}")
    if before.size_bytes != after.size_bytes:
        drifts.append(f"size_bytes drift: before={before.size_bytes} after={after.size_bytes}")
    if before.mode_octal != after.mode_octal:
        drifts.append(f"mode drift: before={before.mode_octal} after={after.mode_octal}")
    if before.uid != after.uid or before.gid != after.gid:
        drifts.append(
            f"ownership drift: before={before.uid}:{before.gid} after={after.uid}:{after.gid}"
        )
    if before.inode != after.inode:
        drifts.append(f"inode drift (file replaced): before={before.inode} after={after.inode}")
    return len(drifts) == 0, drifts


def validate_isolated_work_root(work_root: str) -> str:
    import posixpath

    raw = (work_root or "").strip()
    if not raw:
        raise GuestSafetyError("work_root must not be empty")
    if "\x00" in raw or "\\" in raw:
        raise GuestSafetyError("work_root contains invalid characters")
    if not raw.startswith("/"):
        raise GuestSafetyError(f"work_root must be an absolute path: {raw!r}")
    parts = PurePosixPath(raw).parts
    if ".." in parts:
        raise GuestSafetyError(f"work_root must not contain parent traversal '..': {raw!r}")

    normalized = posixpath.normpath(raw)
    for forbidden in FORBIDDEN_HOST_PATHS:
        if normalized == forbidden or normalized.startswith(forbidden + "/"):
            raise GuestSafetyError(
                f"work_root {normalized!r} collides with forbidden host path {forbidden!r}"
            )

    if not (
        normalized == ALLOWED_WORK_ROOT_PREFIX
        or normalized.startswith(ALLOWED_WORK_ROOT_PREFIX + "-")
        or normalized.startswith(ALLOWED_WORK_ROOT_PREFIX + "/")
    ):
        raise GuestSafetyError(
            f"work_root {normalized!r} must reside under {ALLOWED_WORK_ROOT_PREFIX!r}"
        )
    return normalized


def validate_binary_not_in_live_host_tree(binary_path: str, label: str) -> str:
    import posixpath

    raw = (binary_path or "").strip()
    if not raw:
        raise GuestSafetyError(f"{label} binary path must not be empty")
    if "\x00" in raw or "\\" in raw:
        raise GuestSafetyError(f"{label} binary path contains invalid characters: {raw!r}")
    if not raw.startswith("/"):
        raise GuestSafetyError(f"{label} binary path must be absolute: {raw!r}")
    if ".." in PurePosixPath(raw).parts:
        raise GuestSafetyError(f"{label} binary path must not contain '..': {raw!r}")
    normalized = posixpath.normpath(raw)
    for forbidden in ("/opt/AetherFlow", "/opt/aetherflow"):
        if normalized == forbidden or normalized.startswith(forbidden + "/"):
            raise GuestSafetyError(
                f"{label} binary path {normalized!r} is inside forbidden live host path {forbidden!r}"
            )
    return normalized


def verify_guest_execution_guardrails(
    *,
    confirm_disposable_guest: bool,
    work_root: str,
    api_bin: str,
    af_bin: str,
    guest_marker_file: str = DEFAULT_GUEST_MARKER_FILE,
    platform_name: Optional[str] = None,
    euid: Optional[int] = None,
    environ: Optional[Dict[str, str]] = None,
    marker_content: Optional[str] = None,
    virt_Identifiers: Optional[Sequence[str]] = None,
) -> Dict[str, Any]:
    """Fail-closed verification that execution is inside a disposable Linux QEMU/KVM guest."""
    effective_platform = platform_name if platform_name is not None else sys.platform
    if not effective_platform.startswith("linux"):
        raise GuestSafetyError(
            f"privileged guest drills require Linux guest OS; detected platform={effective_platform!r}"
        )

    effective_euid = (
        euid
        if euid is not None
        else (os.geteuid() if hasattr(os, "geteuid") else -1)
    )
    if effective_euid != 0:
        raise GuestSafetyError(
            f"privileged guest drills must run as root (euid=0) inside disposable guest; got euid={effective_euid}"
        )

    if not confirm_disposable_guest:
        raise GuestSafetyError(
            "missing required --confirm-disposable-guest flag; refusing to execute privileged drills"
        )

    env_map = environ if environ is not None else dict(os.environ)
    env_marker = env_map.get(GUEST_ENV_VAR, "").strip()
    if env_marker != GUEST_ENV_REQUIRED_VALUE:
        raise GuestSafetyError(
            f"missing environment guardrail {GUEST_ENV_VAR}={GUEST_ENV_REQUIRED_VALUE!r} (got {env_marker!r})"
        )

    normalized_work_root = validate_isolated_work_root(work_root)
    normalized_api_bin = validate_binary_not_in_live_host_tree(api_bin, "aetherflow-api")
    normalized_af_bin = validate_binary_not_in_live_host_tree(af_bin, "af")

    if not guest_marker_file.startswith("/run/"):
        raise GuestSafetyError(
            f"guest_marker_file must reside under ephemeral /run tmpfs: {guest_marker_file!r}"
        )

    if marker_content is None:
        marker_path = Path(guest_marker_file)
        if not marker_path.is_file():
            raise GuestSafetyError(
                f"guest marker file {guest_marker_file!r} does not exist; create it inside disposable VM first"
            )
        marker_text = marker_path.read_text(encoding="utf-8", errors="replace").strip()
    else:
        marker_text = marker_content.strip()

    if GUEST_MARKER_REQUIRED_TOKEN not in marker_text:
        raise GuestSafetyError(
            f"guest marker file {guest_marker_file!r} missing token {GUEST_MARKER_REQUIRED_TOKEN!r}"
        )

    detected_virt: List[str] = []
    if virt_Identifiers is not None:
        detected_virt = [str(v).strip() for v in virt_Identifiers if str(v).strip()]
    else:
        try:
            proc = subprocess.run(
                ["systemd-detect-virt", "--vm"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                detected_virt.append(proc.stdout.strip())
        except FileNotFoundError:
            pass

        for dmi_file in (
            "/sys/class/dmi/id/product_name",
            "/sys/class/dmi/id/sys_vendor",
            "/sys/class/dmi/id/board_vendor",
            "/sys/hypervisor/type",
        ):
            p = Path(dmi_file)
            if p.is_file():
                try:
                    val = p.read_text(encoding="utf-8", errors="replace").strip()
                    if val:
                        detected_virt.append(val)
                except OSError:
                    pass

    lowered_virt = " | ".join(detected_virt).lower()
    if not any(token in lowered_virt for token in QEMU_VIRT_IDENTIFIERS):
        raise GuestSafetyError(
            f"refusing execution: virtualization probe {detected_virt!r} did not match disposable QEMU/KVM identifiers {QEMU_VIRT_IDENTIFIERS}"
        )

    return {
        "platform": effective_platform,
        "euid": effective_euid,
        "work_root": normalized_work_root,
        "api_bin": normalized_api_bin,
        "af_bin": normalized_af_bin,
        "guest_marker_file": guest_marker_file,
        "detected_virtualization": detected_virt,
    }


def evaluate_cli_envelope(
    output_text: str,
    *,
    expected_status: str = "ok",
    expected_error_code: Optional[str] = None,
) -> Tuple[bool, Optional[Dict[str, Any]], str]:
    """Validate an `af --json` CliResponseEnvelope response."""
    raw = (output_text or "").strip()
    if not raw:
        return False, None, "CLI output was empty; expected JSON envelope"
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        return False, None, f"CLI output was not valid JSON: {exc}"
    if not isinstance(payload, dict):
        return False, None, f"CLI JSON root must be object; got {type(payload).__name__}"

    actual_status = payload.get("status")
    if actual_status != expected_status:
        return (
            False,
            payload,
            f"expected envelope status={expected_status!r}, got {actual_status!r}",
        )

    exit_code = payload.get("exit_code")
    if type(exit_code) is not int or (exit_code != 0 if expected_status == "ok" else exit_code <= 0):
        return False, payload, f"invalid CLI envelope exit_code={exit_code!r} for {expected_status!r}"
    if expected_error_code is not None and payload.get("error_kind") != expected_error_code:
        return False, payload, f"expected error_kind={expected_error_code!r}, got {payload.get('error_kind')!r}"

    return True, payload, "envelope matched"


def evaluate_runner_backup_exchange(
    http_status: Optional[int],
    raw_body: str,
    *,
    expect_http_status: int = 200,
    expect_runner_success: bool = True,
    expected_action: Optional[str] = None,
    expected_error_substring: Optional[str] = None,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Dict[str, Any]], str]:
    """Validate an `af-runner` `/v1/backup` HTTP + JSON exchange."""
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
        return False, None, None, "runner response JSON is not an object"

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

    backup_payload: Optional[Dict[str, Any]] = None
    output_str = runner_env.get("output")
    if isinstance(output_str, str) and output_str.strip():
        try:
            parsed_out = json.loads(output_str)
            if isinstance(parsed_out, dict):
                backup_payload = parsed_out
        except json.JSONDecodeError as exc:
            if expect_runner_success:
                return (
                    False,
                    runner_env,
                    None,
                    f"RunnerResponse.output was not valid BackupRunnerResponse JSON: {exc}",
                )

    if expect_runner_success:
        if not isinstance(backup_payload, dict):
            return (
                False,
                runner_env,
                None,
                "expected BackupRunnerResponse JSON in RunnerResponse.output",
            )
        if not isinstance(backup_payload.get("action"), str) or not backup_payload["action"]:
            return False, runner_env, backup_payload, "BackupRunnerResponse.action must be a nonempty string"
        if expected_action is not None and backup_payload.get("action") != expected_action:
            return (
                False,
                runner_env,
                backup_payload,
                f"expected BackupRunnerResponse.action={expected_action!r}, got {backup_payload.get('action')!r}",
            )

    return True, runner_env, backup_payload, "runner backup exchange matched"


def evaluate_drill_suite_status(
    phases: Sequence[DrillPhaseResult],
    required_phases: Sequence[str] = MANDATORY_DRILL_PHASES,
) -> Dict[str, Any]:
    """Fail-closed evaluation of all mandatory drill phases.

    Never reports pass from absence of execution, skipped phases, or pending contracts.
    """
    phase_map: Dict[str, DrillPhaseResult] = {p.phase_id: p for p in phases}
    missing_phases: List[str] = []
    failed_phases: List[str] = []
    pending_phases: List[str] = []
    passed_phases: List[str] = []

    for req_id in required_phases:
        phase = phase_map.get(req_id)
        if phase is None:
            missing_phases.append(req_id)
            continue
        if not phase.real_execution:
            failed_phases.append(f"{req_id} (real_execution=False)")
            continue
        if not phase.assertions:
            failed_phases.append(f"{req_id} (zero assertions recorded)")
            continue
        if any(not a.passed for a in phase.assertions):
            failed_phases.append(req_id)
            continue
        if phase.status == "pending_contract":
            pending_phases.append(req_id)
            continue
        if phase.status != "passed":
            failed_phases.append(req_id)
            continue
        passed_phases.append(req_id)

    for extra_id, phase in phase_map.items():
        if extra_id not in required_phases:
            if phase.status == "pending_contract":
                pending_phases.append(extra_id)
            elif phase.status != "passed" or not phase.real_execution or any(
                not a.passed for a in phase.assertions
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


class _UnixDomainHTTPConnection(http.client.HTTPConnection):
    """Stdlib HTTP/1.1 connection over AF_UNIX stream socket."""

    def __init__(self, socket_path: str, timeout: float = 15.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


def perform_uds_http_request(
    socket_path: str,
    method: str,
    path: str,
    body: Optional[Dict[str, Any]] = None,
    timeout: float = 15.0,
    run_as_uid: Optional[int] = None,
    run_as_gid: Optional[int] = None,
) -> UdsExchangeRecord:
    """Send a real HTTP/1.1 request over a Unix domain socket, optionally as an unprivileged UID/GID."""
    start = time.monotonic()
    if run_as_uid is not None or run_as_gid is not None:
        target_uid = int(run_as_uid if run_as_uid is not None else os.geteuid())
        target_gid = int(run_as_gid if run_as_gid is not None else os.getegid())
        helper_code = (
            "import http.client, json, os, socket, sys\n"
            "sock_path, method, path, body_json, uid, gid, timeout = sys.argv[1:8]\n"
            "uid, gid, timeout = int(uid), int(gid), float(timeout)\n"
            "os.setgroups([])\n"
            "os.setgid(gid)\n"
            "os.setuid(uid)\n"
            "class U(http.client.HTTPConnection):\n"
            "    def connect(self):\n"
            "        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)\n"
            "        s.settimeout(timeout)\n"
            "        s.connect(sock_path)\n"
            "        self.sock = s\n"
            "try:\n"
            "    conn = U('localhost')\n"
            "    headers = {'Host': 'unix'}\n"
            "    payload = None\n"
            "    if body_json:\n"
            "        payload = body_json.encode('utf-8')\n"
            "        headers['Content-Type'] = 'application/json'\n"
            "        headers['Content-Length'] = str(len(payload))\n"
            "    conn.request(method, path, body=payload, headers=headers)\n"
            "    resp = conn.getresponse()\n"
            "    raw = resp.read().decode('utf-8', errors='replace')\n"
            "    print(json.dumps({'status': resp.status, 'raw': raw, 'error': None, 'euid': os.geteuid(), 'egid': os.getegid()}))\n"
            "except Exception as exc:\n"
            "    print(json.dumps({'status': None, 'raw': '', 'error': f'{type(exc).__name__}: {exc}', 'euid': os.geteuid(), 'egid': os.getegid()}))\n"
        )
        proc = subprocess.run(
            [
                sys.executable,
                "-c",
                helper_code,
                socket_path,
                method,
                path,
                json.dumps(body) if body is not None else "",
                str(target_uid),
                str(target_gid),
                str(timeout),
            ],
            capture_output=True,
            text=True,
            timeout=timeout + 5.0,
            check=False,
        )
        duration_ms = round((time.monotonic() - start) * 1000.0, 2)
        try:
            res = json.loads(proc.stdout.strip())
        except json.JSONDecodeError:
            res = {
                "status": None,
                "raw": proc.stdout,
                "error": proc.stderr.strip() or f"subproc exit {proc.returncode}",
                "euid": target_uid,
                "egid": target_gid,
            }
        return _build_uds_record(
            socket_path=socket_path,
            method=method,
            path=path,
            effective_uid=res.get("euid", target_uid),
            effective_gid=res.get("egid", target_gid),
            request_body=body,
            http_status=res.get("status"),
            raw_response=res.get("raw") or "",
            socket_error=res.get("error"),
            duration_ms=duration_ms,
        )

    effective_uid = os.geteuid() if hasattr(os, "geteuid") else 0
    effective_gid = os.getegid() if hasattr(os, "getegid") else 0
    http_status: Optional[int] = None
    raw_response = ""
    socket_error: Optional[str] = None
    try:
        conn = _UnixDomainHTTPConnection(socket_path, timeout=timeout)
        headers: Dict[str, str] = {"Host": "unix"}
        encoded_body: Optional[bytes] = None
        if body is not None:
            encoded_body = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(encoded_body))
        conn.request(method, path, body=encoded_body, headers=headers)
        resp = conn.getresponse()
        http_status = int(resp.status)
        raw_response = resp.read().decode("utf-8", errors="replace")
        conn.close()
    except Exception as exc:  # noqa: BLE001
        socket_error = f"{type(exc).__name__}: {exc}"

    duration_ms = round((time.monotonic() - start) * 1000.0, 2)
    return _build_uds_record(
        socket_path=socket_path,
        method=method,
        path=path,
        effective_uid=effective_uid,
        effective_gid=effective_gid,
        request_body=body,
        http_status=http_status,
        raw_response=raw_response,
        socket_error=socket_error,
        duration_ms=duration_ms,
    )


def _build_uds_record(
    *,
    socket_path: str,
    method: str,
    path: str,
    effective_uid: int,
    effective_gid: int,
    request_body: Optional[Dict[str, Any]],
    http_status: Optional[int],
    raw_response: str,
    socket_error: Optional[str],
    duration_ms: float,
) -> UdsExchangeRecord:
    runner_response: Optional[Dict[str, Any]] = None
    backup_payload: Optional[Dict[str, Any]] = None
    if raw_response.strip():
        try:
            parsed = json.loads(raw_response)
            if isinstance(parsed, dict):
                runner_response = parsed
                out_str = parsed.get("output")
                if isinstance(out_str, str) and out_str.strip():
                    try:
                        inner = json.loads(out_str)
                        if isinstance(inner, dict):
                            backup_payload = inner
                    except json.JSONDecodeError:
                        pass
        except json.JSONDecodeError:
            pass

    return UdsExchangeRecord(
        socket_path=socket_path,
        method=method,
        path=path,
        effective_uid=effective_uid,
        effective_gid=effective_gid,
        request_body=request_body,
        http_status=http_status,
        raw_response=raw_response,
        runner_response=runner_response,
        backup_payload=backup_payload,
        socket_error=socket_error,
        duration_ms=duration_ms,
    )


def run_recorded_command(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Optional[Dict[str, str]] = None,
    run_as_uid: Optional[int] = None,
    run_as_gid: Optional[int] = None,
    timeout: float = 30.0,
) -> CommandRecord:
    """Execute a real binary command and record exit status, UID/GID, stdout/stderr, and JSON envelope."""
    cmd_list = [str(x) for x in argv]
    effective_uid = int(
        run_as_uid
        if run_as_uid is not None
        else (os.geteuid() if hasattr(os, "geteuid") else 0)
    )
    effective_gid = int(
        run_as_gid
        if run_as_gid is not None
        else (os.getegid() if hasattr(os, "getegid") else 0)
    )

    def _preexec() -> None:
        if run_as_uid is not None or run_as_gid is not None:
            os.setgroups([])
            os.setgid(effective_gid)
            os.setuid(effective_uid)

    merged_env = dict(os.environ)
    if env:
        merged_env.update(env)

    start = time.monotonic()
    proc = subprocess.run(
        cmd_list,
        cwd=str(cwd),
        env=merged_env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        preexec_fn=_preexec if (run_as_uid is not None or run_as_gid is not None) else None,
    )
    duration_ms = round((time.monotonic() - start) * 1000.0, 2)
    parsed_json: Optional[Any] = None
    out_stripped = (proc.stdout if proc.returncode == 0 else proc.stderr).strip()
    if out_stripped.startswith("{") or out_stripped.startswith("["):
        try:
            parsed_json = json.loads(out_stripped)
        except json.JSONDecodeError:
            parsed_json = None

    return CommandRecord(
        argv=cmd_list,
        command_str=shlex.join(cmd_list),
        cwd=str(cwd),
        effective_uid=effective_uid,
        effective_gid=effective_gid,
        exit_code=int(proc.returncode),
        duration_ms=duration_ms,
        stdout=proc.stdout,
        stderr=proc.stderr,
        parsed_json=parsed_json,
    )


class HeldOpenWalSession:
    """Holds a real SQLite database open in WAL mode with live uncheckpointed WAL frames
    and an active reader/writer transaction lock while backups are captured.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._proc: Optional[subprocess.Popen[str]] = None
        self.committed_rows: List[Tuple[str, str]] = []
        self.uncommitted_key: str = "uncommitted_inflight_txn_must_not_leak"

    def start(self) -> Dict[str, Any]:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.committed_rows = [
            ("schema_marker", "v4_wal_live_drill"),
            ("committed_row_1", "alpha_committed_before_wal_lock"),
            ("committed_row_2", "bravo_committed_in_wal_frames"),
            ("committed_row_3", "charlie_committed_in_wal_frames"),
        ]
        worker_script = (
            "import json, os, sqlite3, sys, time\n"
            "db_path = sys.argv[1]\n"
            "rows = json.loads(sys.argv[2])\n"
            "uncommitted_key = sys.argv[3]\n"
            "conn_w = sqlite3.connect(db_path, timeout=30.0, isolation_level=None)\n"
            "conn_w.execute('PRAGMA journal_mode=WAL;')\n"
            "conn_w.execute('PRAGMA synchronous=NORMAL;')\n"
            "conn_w.execute('PRAGMA wal_autocheckpoint=0;')\n"
            "conn_w.execute('PRAGMA user_version=404;')\n"
            "conn_w.execute('CREATE TABLE IF NOT EXISTS drill_kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);')\n"
            "conn_w.execute('BEGIN IMMEDIATE;')\n"
            "for k, v in rows:\n"
            "    conn_w.execute('INSERT OR REPLACE INTO drill_kv (k, v) VALUES (?, ?);', (k, v))\n"
            "conn_w.execute('COMMIT;')\n"
            "# Open a second reader connection holding a read snapshot on the committed state\n"
            "conn_r = sqlite3.connect(db_path, timeout=30.0, isolation_level=None)\n"
            "conn_r.execute('BEGIN DEFERRED;')\n"
            "count = conn_r.execute('SELECT COUNT(*) FROM drill_kv;').fetchone()[0]\n"
            "# Start an uncommitted write transaction so dirty/uncommitted frames or locks are active\n"
            "conn_w.execute('BEGIN IMMEDIATE;')\n"
            "conn_w.execute('INSERT OR REPLACE INTO drill_kv (k, v) VALUES (?, ?);', (uncommitted_key, 'dirty_uncommitted'))\n"
            "wal_path = db_path + '-wal'\n"
            "shm_path = db_path + '-shm'\n"
            "info = {\n"
            "    'pid': os.getpid(),\n"
            "    'committed_count': count,\n"
            "    'wal_exists': os.path.exists(wal_path),\n"
            "    'wal_size': os.path.getsize(wal_path) if os.path.exists(wal_path) else 0,\n"
            "    'shm_exists': os.path.exists(shm_path),\n"
            "    'shm_size': os.path.getsize(shm_path) if os.path.exists(shm_path) else 0,\n"
            "}\n"
            "print(json.dumps(info), flush=True)\n"
            "for line in sys.stdin:\n"
            "    if line.strip() == 'STOP':\n"
            "        break\n"
            "conn_w.execute('ROLLBACK;')\n"
            "conn_r.execute('ROLLBACK;')\n"
            "conn_r.close()\n"
            "conn_w.close()\n"
        )
        self._proc = subprocess.Popen(
            [
                sys.executable,
                "-c",
                worker_script,
                str(self.db_path),
                json.dumps(self.committed_rows),
                self.uncommitted_key,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert self._proc.stdout is not None
        ready_line = self._proc.stdout.readline().strip()
        if not ready_line:
            stderr_out = self._proc.stderr.read() if self._proc.stderr else ""
            raise DrillAssertionError(f"HeldOpenWalSession worker failed to start: {stderr_out}")
        return json.loads(ready_line)

    def stop(self) -> None:
        if self._proc is None:
            return
        try:
            if self._proc.stdin:
                self._proc.stdin.write("STOP\n")
                self._proc.stdin.flush()
            self._proc.wait(timeout=5.0)
        except Exception:  # noqa: BLE001
            self._proc.kill()
            self._proc.wait(timeout=5.0)
        finally:
            self._proc = None


class RunnerDaemonProcess:
    """Manages a real `aetherflow-api runner` UDS daemon instance inside the guest work root."""

    def __init__(
        self,
        *,
        api_bin: Path,
        socket_path: Path,
        env_overrides: Dict[str, str],
        log_path: Path,
    ) -> None:
        self.api_bin = api_bin
        self.socket_path = socket_path
        self.env_overrides = env_overrides
        self.log_path = log_path
        self._proc: Optional[subprocess.Popen[str]] = None
        self._log_handle: Optional[Any] = None

    def start(self, wait_timeout: float = 10.0) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists():
            self.socket_path.unlink()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log_handle = self.log_path.open("w", encoding="utf-8")

        env = dict(os.environ)
        for key in (
            "AETHERFLOW_BACKUP_ISOLATED_ROOT",
            "AETHERFLOW_BACKUP_DIR",
            "AETHERFLOW_DB_PATH",
            "AETHERFLOW_RESTORE_STAGING_ROOT",
            "AETHERFLOW_BACKUP_DRY_RUN_QUIESCENCE",
            "AETHERFLOW_ALLOWED_RUNNER_UIDS",
        ):
            env.pop(key, None)
        env["AETHERFLOW_RUNNER_SOCK"] = str(self.socket_path)
        env.update(self.env_overrides)

        self._proc = subprocess.Popen(
            [str(self.api_bin), "runner"],
            stdout=self._log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )

        deadline = time.monotonic() + wait_timeout
        while time.monotonic() < deadline:
            if self._proc.poll() is not None:
                raise DrillAssertionError(
                    f"aetherflow-api runner exited prematurely with code {self._proc.returncode}; log={self.read_logs()!r}"
                )
            if self.socket_path.exists():
                ex = perform_uds_http_request(str(self.socket_path), "GET", "/v1/health", timeout=2.0)
                if ex.http_status == 200:
                    return
            time.sleep(0.1)

        raise DrillAssertionError(
            f"timed out waiting for aetherflow-api runner socket {self.socket_path}; log={self.read_logs()!r}"
        )

    def read_logs(self) -> str:
        if self.log_path.is_file():
            return self.log_path.read_text(encoding="utf-8", errors="replace")
        return ""

    def stop(self) -> None:
        if self._proc is not None:
            if self._proc.poll() is None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    self._proc.wait(timeout=5.0)
            self._proc = None
        if self._log_handle is not None:
            try:
                self._log_handle.close()
            except Exception:  # noqa: BLE001
                pass
            self._log_handle = None


def resolve_unprivileged_identity() -> Tuple[int, int, str]:
    """Locate an unprivileged UID/GID (such as `nobody` or `65534`) for negative authorization drills."""
    for candidate in ("nobody", "daemon", "_apt", "systemd-network"):
        try:
            pw = pwd.getpwnam(candidate)
            if pw.pw_uid > 0 and pw.pw_uid != os.geteuid():
                return int(pw.pw_uid), int(pw.pw_gid), pw.pw_name
        except KeyError:
            continue
    return 65534, 65534, "uid_65534"


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
    if not passed:
        phase.failure_diagnostics.append(
            f"Assertion {name!r} failed: expected={expected!r}, actual={actual!r} ({detail})"
        )


def seed_isolated_root_filesystem(iso_root: Path, owner_uid: int = 0, owner_gid: int = 0) -> Dict[str, Path]:
    """Create a realistic isolated root layout for archive/restore drills inside work_root."""
    var_lib = iso_root / "var/lib/aetherflow"
    backups_dir = var_lib / "backups"
    etc_af = iso_root / "etc/aetherflow"
    etc_legacy = iso_root / "etc/AetherFlow"
    opt_cfg = iso_root / "opt/AetherFlow/dashboard/config"
    systemd_dir = iso_root / "etc/systemd/system"

    for d in (var_lib, backups_dir, etc_af, etc_legacy, opt_cfg, systemd_dir):
        d.mkdir(parents=True, exist_ok=True)

    env_file = etc_af / "aetherflow.env"
    env_file.write_text("AETHERFLOW_ENV=disposable_guest_drill_v4\nSECRET_KEY=original_secret_value\n", encoding="utf-8")
    os.chown(env_file, owner_uid, owner_gid)
    os.chmod(env_file, 0o600)

    lock_file = etc_legacy / ".Lock"
    lock_file.write_text("lock_marker=v4_original\n", encoding="utf-8")
    os.chown(lock_file, owner_uid, owner_gid)
    os.chmod(lock_file, 0o640)

    settings_file = opt_cfg / "settings.json"
    settings_file.write_text(json.dumps({"theme": "nexus", "version": 4}, indent=2) + "\n", encoding="utf-8")
    os.chown(settings_file, owner_uid, owner_gid)
    os.chmod(settings_file, 0o644)

    unit_file = systemd_dir / "aetherflow-api.service"
    unit_file.write_text("[Unit]\nDescription=Isolated AetherFlow API Marker\n", encoding="utf-8")
    os.chown(unit_file, owner_uid, owner_gid)
    os.chmod(unit_file, 0o644)

    return {
        "iso_root": iso_root,
        "var_lib": var_lib,
        "backups_dir": backups_dir,
        "db_path": var_lib / "aetherflow.sqlite",
        "env_file": env_file,
        "lock_file": lock_file,
        "settings_file": settings_file,
        "unit_file": unit_file,
    }


def run_phase_1_provenance(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
    guardrail_info: Dict[str, Any],
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    t0 = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="binary_and_environment_provenance",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    for label, bin_path in (("aetherflow-api", api_bin), ("af", af_bin)):
        exists = bin_path.is_file() and os.access(bin_path, os.X_OK)
        _record_assertion(
            phase,
            f"{label}_binary_executable",
            exists,
            "executable file exists",
            str(bin_path) if exists else "missing or not executable",
        )
        if exists:
            st = bin_path.stat()
            phase.artifacts[label] = {
                "path": str(bin_path),
                "sha256": compute_file_sha256(bin_path),
                "size_bytes": int(st.st_size),
                "mode_octal": f"{stat.S_IMODE(st.st_mode):04o}",
                "uid": int(st.st_uid),
                "gid": int(st.st_gid),
            }

    if af_bin.is_file():
        ver_cmd = run_recorded_command([str(af_bin), "--json", "version"], cwd=work_root)
        phase.commands.append(ver_cmd)
        ok_env, payload, detail = evaluate_cli_envelope(ver_cmd.stdout, expected_status="ok")
        _record_assertion(
            phase,
            "af_cli_version_envelope",
            ver_cmd.exit_code == 0 and ok_env,
            {"exit_code": 0, "status": "ok"},
            {"exit_code": ver_cmd.exit_code, "detail": detail, "payload": payload},
        )

    unpriv_uid, unpriv_gid, unpriv_name = resolve_unprivileged_identity()
    phase.artifacts["identities"] = {
        "runner_euid": os.geteuid(),
        "runner_egid": os.getegid(),
        "unprivileged_uid": unpriv_uid,
        "unprivileged_gid": unpriv_gid,
        "unprivileged_name": unpriv_name,
    }
    phase.artifacts["guardrails"] = guardrail_info

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
    if any(not a.passed for a in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_2_backup_roundtrip_with_live_wal(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    t0 = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="authorized_backup_roundtrip_with_live_wal",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    iso_root = work_root / "phase2_roundtrip_iso"
    layout = seed_isolated_root_filesystem(iso_root)
    db_path = layout["db_path"]
    backups_dir = layout["backups_dir"]
    sock_path = work_root / "run/phase2_runner.sock"
    log_path = work_root / "logs/phase2_runner.log"

    wal_session = HeldOpenWalSession(db_path)
    daemon = RunnerDaemonProcess(
        api_bin=api_bin,
        socket_path=sock_path,
        env_overrides={"AETHERFLOW_BACKUP_ISOLATED_ROOT": str(iso_root)},
        log_path=log_path,
    )
    try:
        wal_info = wal_session.start()
        phase.artifacts["live_wal_state"] = wal_info
        _record_assertion(
            phase,
            "live_sqlite_wal_and_shm_present_during_backup",
            bool(wal_info.get("wal_exists")) and int(wal_info.get("wal_size", 0)) > 0 and bool(wal_info.get("shm_exists")),
            {"wal_exists": True, "wal_size_gt_0": True, "shm_exists": True},
            wal_info,
        )

        daemon.start()

        # 1. Create SQLite backup via UDS runner (/v1/backup create_sqlite) while WAL is held open
        create_sqlite_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={
                "action": "create_sqlite",
                "app_version": "v4.0.0-drill",
                "timestamp_slug": "20261103T060001Z",
            },
        )
        phase.uds_exchanges.append(create_sqlite_ex)
        ok_cs, _, cs_payload, cs_detail = evaluate_runner_backup_exchange(
            create_sqlite_ex.http_status,
            create_sqlite_ex.raw_response,
            expect_http_status=200,
            expect_runner_success=True,
            expected_action="create_sqlite",
        )
        _record_assertion(
            phase,
            "uds_runner_create_sqlite_with_live_wal",
            ok_cs,
            "HTTP 200 + create_sqlite success",
            cs_detail,
        )
        sqlite_artifact_name = (
            (cs_payload or {}).get("filename")
            if isinstance(cs_payload, dict)
            else None
        )

        # 2. Create full Archive backup via UDS runner (/v1/backup create_archive) while WAL is held open
        create_arch_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={
                "action": "create_archive",
                "app_version": "v4.0.0-drill",
                "timestamp_slug": "20261103T060002Z",
            },
        )
        phase.uds_exchanges.append(create_arch_ex)
        ok_ca, _, ca_payload, ca_detail = evaluate_runner_backup_exchange(
            create_arch_ex.http_status,
            create_arch_ex.raw_response,
            expect_http_status=200,
            expect_runner_success=True,
            expected_action="create_archive",
        )
        _record_assertion(
            phase,
            "uds_runner_create_archive_with_live_wal",
            ok_ca,
            "HTTP 200 + create_archive success",
            ca_detail,
        )
        archive_artifact_name = (
            (ca_payload or {}).get("filename")
            if isinstance(ca_payload, dict)
            else None
        )

        # 3. Also exercise `af --json backup create --sqlite-only` CLI while WAL is held open
        cli_create_cmd = run_recorded_command(
            [
                str(af_bin),
                "--root",
                str(iso_root),
                "--json",
                "backup",
                "create",
                "--sqlite-only",
                "--backup-dir",
                str(backups_dir),
                "--db-path",
                str(db_path),
                "--timestamp",
                "20261103T060003Z",
            ],
            cwd=work_root,
        )
        phase.commands.append(cli_create_cmd)
        ok_cli_c, cli_c_env, cli_c_detail = evaluate_cli_envelope(cli_create_cmd.stdout, expected_status="ok")
        _record_assertion(
            phase,
            "af_cli_backup_create_with_live_wal",
            cli_create_cmd.exit_code == 0 and ok_cli_c,
            "exit 0 + ok envelope",
            cli_c_detail,
        )
        cli_sqlite_name = (
            Path(((cli_c_env or {}).get("data") or {}).get("primary_artifact_path", "")).name
            if isinstance(cli_c_env, dict)
            else None
        )

        # 4. List inventory via both UDS runner and `af --json backup list`
        list_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={"action": "list"},
        )
        phase.uds_exchanges.append(list_ex)
        ok_list, _, list_payload, list_detail = evaluate_runner_backup_exchange(
            list_ex.http_status,
            list_ex.raw_response,
            expect_http_status=200,
            expect_runner_success=True,
            expected_action="list",
        )
        listed_names = [
            item.get("filename")
            for item in ((list_payload or {}).get("details") or [])
            if isinstance(item, dict)
        ]
        _record_assertion(
            phase,
            "uds_runner_list_contains_created_artifacts",
            ok_list
            and sqlite_artifact_name in listed_names
            and archive_artifact_name in listed_names
            and cli_sqlite_name in listed_names,
            [sqlite_artifact_name, archive_artifact_name, cli_sqlite_name],
            listed_names,
            detail=list_detail,
        )

        cli_list_cmd = run_recorded_command(
            [
                str(af_bin),
                "--root",
                str(iso_root),
                "--json",
                "backup",
                "list",
                "--backup-dir",
                str(backups_dir),
            ],
            cwd=work_root,
        )
        phase.commands.append(cli_list_cmd)
        ok_cli_l, _, cli_l_detail = evaluate_cli_envelope(cli_list_cmd.stdout, expected_status="ok")
        _record_assertion(
            phase,
            "af_cli_backup_list_envelope",
            cli_list_cmd.exit_code == 0 and ok_cli_l,
            "exit 0 + ok envelope",
            cli_l_detail,
        )

        # 5. Verify both artifacts via UDS runner and `af --json backup verify`
        for art_name in (sqlite_artifact_name, archive_artifact_name):
            if not art_name:
                continue
            art_path = backups_dir / art_name
            phase.artifacts[art_name] = {
                "path": str(art_path),
                "sha256": compute_file_sha256(art_path) if art_path.is_file() else None,
            }
            ver_ex = perform_uds_http_request(
                str(sock_path),
                "POST",
                "/v1/backup",
                body={"action": "verify", "filename": art_name},
            )
            phase.uds_exchanges.append(ver_ex)
            ok_v, _, v_payload, v_detail = evaluate_runner_backup_exchange(
                ver_ex.http_status,
                ver_ex.raw_response,
                expect_http_status=200,
                expect_runner_success=True,
                expected_action="verify",
            )
            verified_flag = (v_payload or {}).get("verified") is True
            _record_assertion(
                phase,
                f"uds_runner_verify_{art_name}",
                ok_v and verified_flag,
                {"ok": True, "verified": True},
                {"ok": ok_v, "verified": verified_flag, "detail": v_detail},
            )

            cli_ver_cmd = run_recorded_command(
                [
                    str(af_bin),
                    "--root",
                    str(iso_root),
                    "--json",
                    "backup",
                    "verify",
                    art_name,
                    "--backup-dir",
                    str(backups_dir),
                ],
                cwd=work_root,
            )
            phase.commands.append(cli_ver_cmd)
            ok_cv, _, cv_detail = evaluate_cli_envelope(cli_ver_cmd.stdout, expected_status="ok")
            _record_assertion(
                phase,
                f"af_cli_verify_{art_name}",
                cli_ver_cmd.exit_code == 0 and ok_cv,
                "exit 0 + ok envelope",
                cv_detail,
            )

        # 6. Tamper check: corrupting the `.sha256` sidecar of `cli_sqlite_name` must fail verification
        if cli_sqlite_name:
            sidecar_path = backups_dir / f"{cli_sqlite_name}.sha256"
            orig_sidecar = sidecar_path.read_text(encoding="utf-8")
            sidecar_path.write_text("0" * 64 + f"  {cli_sqlite_name}\n", encoding="utf-8")
            tamper_ex = perform_uds_http_request(
                str(sock_path),
                "POST",
                "/v1/backup",
                body={"action": "verify", "filename": cli_sqlite_name},
            )
            phase.uds_exchanges.append(tamper_ex)
            _record_assertion(
                phase,
                "tampered_sidecar_fails_verification",
                tamper_ex.http_status == 400
                and bool(tamper_ex.runner_response)
                and not bool(tamper_ex.runner_response.get("success", True)),
                "HTTP 400 + RunnerResponse.success == False",
                {"http_status": tamper_ex.http_status, "runner_response": tamper_ex.runner_response},
            )
            # Restore original sidecar so authorized delete can verify and remove it cleanly
            sidecar_path.write_text(orig_sidecar, encoding="utf-8")

        # 7. Delete roundtrip: delete `sqlite_artifact_name` via UDS runner and `cli_sqlite_name` via `af backup delete`
        if sqlite_artifact_name:
            del_ex = perform_uds_http_request(
                str(sock_path),
                "POST",
                "/v1/backup",
                body={"action": "delete", "filename": sqlite_artifact_name},
            )
            phase.uds_exchanges.append(del_ex)
            ok_del, _, _, del_detail = evaluate_runner_backup_exchange(
                del_ex.http_status,
                del_ex.raw_response,
                expect_http_status=200,
                expect_runner_success=True,
                expected_action="delete",
            )
            _record_assertion(
                phase,
                "uds_runner_delete_verified_backup",
                ok_del and not (backups_dir / sqlite_artifact_name).exists(),
                "HTTP 200 + artifact removed from disk",
                del_detail,
            )

        if cli_sqlite_name:
            cli_del_cmd = run_recorded_command(
                [
                    str(af_bin),
                    "--root",
                    str(iso_root),
                    "--json",
                    "backup",
                    "delete",
                    cli_sqlite_name,
                    "--backup-dir",
                    str(backups_dir),
                ],
                cwd=work_root,
            )
            phase.commands.append(cli_del_cmd)
            ok_cdel, _, cdel_detail = evaluate_cli_envelope(cli_del_cmd.stdout, expected_status="ok")
            _record_assertion(
                phase,
                "af_cli_delete_verified_backup",
                cli_del_cmd.exit_code == 0 and ok_cdel and not (backups_dir / cli_sqlite_name).exists(),
                "exit 0 + artifact removed from disk",
                cdel_detail,
            )

    except Exception as exc:  # noqa: BLE001
        phase.failure_diagnostics.append(f"Unhandled exception in phase 2: {type(exc).__name__}: {exc}")
        _record_assertion(phase, "phase2_unhandled_exception", False, "no exception", str(exc))
    finally:
        daemon.stop()
        wal_session.stop()

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
    if any(not a.passed for a in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_3_arbitrary_root_and_sentinel_rejection(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    t0 = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="arbitrary_root_and_sentinel_deletion_rejection",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    iso_root = work_root / "phase3_boundary_iso" / "configured-root"
    layout = seed_isolated_root_filesystem(iso_root)
    backups_dir = layout["backups_dir"]
    db_path = layout["db_path"]

    # Seed a valid SQLite DB
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE IF NOT EXISTS t (id INTEGER PRIMARY KEY);")
    conn.commit()
    conn.close()

    # Create three root-owned sentinels:
    # 1. Inside backup_dir with non-backup extension (`root_sentinel_keep.conf`)
    # 2. Inside backup_dir masquerading as `.sqlite` but WITHOUT a verified inventory sidecar (`untracked_sentinel.sqlite`)
    # 3. Outside backup_dir in `work_root / "outside_sentinel/root_outside_sentinel.sqlite"`
    sentinel_conf = backups_dir / "root_sentinel_keep.conf"
    sentinel_conf.write_text("ROOT_OWNED_SENTINEL_CONF=DO_NOT_DELETE\n", encoding="utf-8")
    os.chown(sentinel_conf, 0, 0)
    os.chmod(sentinel_conf, 0o600)

    sentinel_untracked_sqlite = backups_dir / "untracked_sentinel.sqlite"
    sentinel_untracked_sqlite.write_bytes(b"SQLite format 3\x00ROOT_SENTINEL_UNTRACKED_PAYLOAD")
    os.chown(sentinel_untracked_sqlite, 0, 0)
    os.chmod(sentinel_untracked_sqlite, 0o600)

    outside_dir = work_root / "phase3_outside_root"
    outside_dir.mkdir(parents=True, exist_ok=True)
    sentinel_outside = outside_dir / "root_outside_sentinel.sqlite"
    sentinel_outside.write_bytes(b"SQLite format 3\x00OUTSIDE_ROOT_SENTINEL_PAYLOAD")
    os.chown(sentinel_outside, 0, 0)
    os.chmod(sentinel_outside, 0o600)

    snap_conf_before = snapshot_sentinel(sentinel_conf)
    snap_untracked_before = snapshot_sentinel(sentinel_untracked_sqlite)
    snap_outside_before = snapshot_sentinel(sentinel_outside)

    sock_path = work_root / "run/phase3_runner.sock"
    log_path = work_root / "logs/phase3_runner.log"
    daemon = RunnerDaemonProcess(
        api_bin=api_bin,
        socket_path=sock_path,
        env_overrides={"AETHERFLOW_BACKUP_ISOLATED_ROOT": str(iso_root)},
        log_path=log_path,
    )
    try:
        daemon.start()

        # Create one legitimate backup so restore_preflight / restore_execute have a real filename
        legit_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={
                "action": "create_archive",
                "app_version": "v4.0.0-drill",
                "timestamp_slug": "20261103T061000Z",
            },
        )
        phase.uds_exchanges.append(legit_ex)
        legit_filename = (
            (legit_ex.backup_payload or {}).get("filename")
        )
        if not legit_filename:
            raise ValueError("Runner did not return a real backup filename for the boundary drill")

        # 1. Request-selected arbitrary `backup_dir` override outside server-owned backup root -> HTTP 403
        arb_bdir_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={
                "action": "create_sqlite",
                "backup_dir": str(outside_dir),
                "timestamp_slug": "20261103T061001Z",
            },
        )
        phase.uds_exchanges.append(arb_bdir_ex)
        ok_bdir, _, _, bdir_detail = evaluate_runner_backup_exchange(
            arb_bdir_ex.http_status,
            arb_bdir_ex.raw_response,
            expect_http_status=403,
            expect_runner_success=False,
            expected_error_substring="untrusted backup_dir override",
        )
        _record_assertion(
            phase,
            "reject_arbitrary_request_backup_dir_override",
            ok_bdir,
            "HTTP 403 untrusted backup_dir override",
            bdir_detail,
        )

        # 2. Request-selected arbitrary `db_path` override outside server-owned DB path -> HTTP 403
        arb_db_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={
                "action": "create_sqlite",
                "db_path": str(sentinel_outside),
                "timestamp_slug": "20261103T061002Z",
            },
        )
        phase.uds_exchanges.append(arb_db_ex)
        ok_db, _, _, db_detail = evaluate_runner_backup_exchange(
            arb_db_ex.http_status,
            arb_db_ex.raw_response,
            expect_http_status=403,
            expect_runner_success=False,
            expected_error_substring="untrusted db_path override",
        )
        _record_assertion(
            phase,
            "reject_arbitrary_request_db_path_override",
            ok_db,
            "HTTP 403 untrusted db_path override",
            db_detail,
        )

        # 3. Request-selected arbitrary `target_root` override on restore_preflight & restore_execute -> HTTP 403
        for r_action in ("restore_preflight", "restore_execute"):
            arb_tr_ex = perform_uds_http_request(
                str(sock_path),
                "POST",
                "/v1/backup",
                body={
                    "action": r_action,
                    "filename": legit_filename,
                    "target_root": str(outside_dir),
                    "confirm_destructive_restore": True,
                    "allow_overwrite": True,
                },
            )
            phase.uds_exchanges.append(arb_tr_ex)
            ok_tr, _, _, tr_detail = evaluate_runner_backup_exchange(
                arb_tr_ex.http_status,
                arb_tr_ex.raw_response,
                expect_http_status=403,
                expect_runner_success=False,
                expected_error_substring="untrusted target_root",
            )
            _record_assertion(
                phase,
                f"reject_arbitrary_target_root_on_{r_action}",
                ok_tr,
                "HTTP 403 untrusted target_root",
                tr_detail,
            )

        # 4. Reject parent traversal `..` in `backup_dir`, `target_root`, and `filename` -> HTTP 400
        trav_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={
                "action": "delete",
                "filename": "../phase3_outside_root/root_outside_sentinel.sqlite",
            },
        )
        phase.uds_exchanges.append(trav_ex)
        _record_assertion(
            phase,
            "reject_parent_traversal_filename_delete",
            trav_ex.http_status == 400
            and bool(trav_ex.runner_response)
            and not bool(trav_ex.runner_response.get("success", True)),
            "HTTP 400 on '../' filename",
            {"http_status": trav_ex.http_status, "runner_response": trav_ex.runner_response},
        )

        # 5. Reject deletion of unknown / uninventoried files (`root_sentinel_keep.conf`, `untracked_sentinel.sqlite`, `nonexistent.sqlite`)
        for bad_name in (
            "root_sentinel_keep.conf",
            "untracked_sentinel.sqlite",
            "nonexistent-backup-20261103T000000Z.sqlite",
        ):
            del_bad_ex = perform_uds_http_request(
                str(sock_path),
                "POST",
                "/v1/backup",
                body={"action": "delete", "filename": bad_name},
            )
            phase.uds_exchanges.append(del_bad_ex)
            _record_assertion(
                phase,
                f"uds_reject_delete_unknown_or_sentinel_{bad_name}",
                del_bad_ex.http_status == 400
                and bool(del_bad_ex.runner_response)
                and not bool(del_bad_ex.runner_response.get("success", True)),
                "HTTP 400 rejection",
                {"http_status": del_bad_ex.http_status, "runner_response": del_bad_ex.runner_response},
            )

            cli_bad_del = run_recorded_command(
                [
                    str(af_bin),
                    "--root",
                    str(iso_root),
                    "--json",
                    "backup",
                    "delete",
                    bad_name,
                    "--backup-dir",
                    str(backups_dir),
                ],
                cwd=work_root,
            )
            phase.commands.append(cli_bad_del)
            _record_assertion(
                phase,
                f"af_cli_reject_delete_unknown_or_sentinel_{bad_name}",
                cli_bad_del.exit_code != 0,
                "non-zero exit code",
                {"exit_code": cli_bad_del.exit_code, "stdout": cli_bad_del.stdout},
            )

        # 6. Verify all three root-owned sentinels are 100% intact (SHA-256, size, UID/GID, mode, inode)
        for label, before_snap, path_obj in (
            ("sentinel_conf", snap_conf_before, sentinel_conf),
            ("sentinel_untracked_sqlite", snap_untracked_before, sentinel_untracked_sqlite),
            ("sentinel_outside", snap_outside_before, sentinel_outside),
        ):
            after_snap = snapshot_sentinel(path_obj)
            unchanged, drifts = verify_sentinel_unchanged(before_snap, after_snap)
            phase.artifacts[label] = {
                "before": asdict(before_snap),
                "after": asdict(after_snap),
                "drifts": drifts,
            }
            _record_assertion(
                phase,
                f"root_owned_{label}_preserved_intact",
                unchanged,
                "zero sentinel drift (SHA-256, mode, UID/GID, inode preserved)",
                drifts if drifts else "intact",
            )

    except Exception as exc:  # noqa: BLE001
        phase.failure_diagnostics.append(f"Unhandled exception in phase 3: {type(exc).__name__}: {exc}")
        _record_assertion(phase, "phase3_unhandled_exception", False, "no exception", str(exc))
    finally:
        daemon.stop()

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
    if any(not a.passed for a in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_4_unprivileged_authorization_denial(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    t0 = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="unprivileged_user_and_socket_authorization_denial",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    unpriv_uid, unpriv_gid, unpriv_name = resolve_unprivileged_identity()
    phase.artifacts["unprivileged_identity"] = {
        "uid": unpriv_uid,
        "gid": unpriv_gid,
        "name": unpriv_name,
    }

    iso_root = work_root / "phase4_auth_iso"
    layout = seed_isolated_root_filesystem(iso_root)
    # Traverse permissions on work_root and run dir so unprivileged user can reach the socket inode
    os.chmod(work_root, 0o755)
    run_dir = work_root / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(run_dir, 0o755)

    sock_path = run_dir / "phase4_runner.sock"
    log_path = work_root / "logs/phase4_runner.log"
    daemon = RunnerDaemonProcess(
        api_bin=api_bin,
        socket_path=sock_path,
        env_overrides={"AETHERFLOW_BACKUP_ISOLATED_ROOT": str(iso_root)},
        log_path=log_path,
    )
    try:
        daemon.start()

        # 1. Default socket mode 0660 (root:root) blocks unprivileged user at filesystem permission layer
        st_sock = os.stat(sock_path)
        sock_mode = f"{stat.S_IMODE(st_sock.st_mode):04o}"
        _record_assertion(
            phase,
            "runner_socket_default_mode_0660",
            sock_mode == "0660",
            "0660",
            sock_mode,
        )

        dac_ex = perform_uds_http_request(
            str(sock_path),
            "GET",
            "/v1/health",
            run_as_uid=unpriv_uid,
            run_as_gid=unpriv_gid,
        )
        phase.uds_exchanges.append(dac_ex)
        _record_assertion(
            phase,
            "unprivileged_user_denied_by_socket_dac_0660",
            dac_ex.http_status is None
            and dac_ex.socket_error is not None
            and ("PermissionError" in dac_ex.socket_error or "Errno 13" in dac_ex.socket_error),
            "PermissionError (EACCES) on 0660 socket",
            {"http_status": dac_ex.http_status, "socket_error": dac_ex.socket_error},
        )

        # 2. Kernel SO_PEERCRED authorization enforcement:
        # Even if socket permissions are relaxed to 0666 so the unprivileged UID can connect(),
        # `authorize_runner_peer_credentials` in `af-runner` inspects SO_PEERCRED and rejects
        # the unauthorized UID (closing the stream / returning HTTP 403).
        os.chmod(sock_path, 0o666)
        for endpoint, method, req_body in (
            ("/v1/health", "GET", None),
            (
                "/v1/backup",
                "POST",
                {"action": "create_sqlite", "timestamp_slug": "20261103T062000Z"},
            ),
            (
                "/v1/backup",
                "POST",
                {"action": "delete", "filename": "any.sqlite"},
            ),
        ):
            peercred_ex = perform_uds_http_request(
                str(sock_path),
                method,
                endpoint,
                body=req_body,
                run_as_uid=unpriv_uid,
                run_as_gid=unpriv_gid,
            )
            phase.uds_exchanges.append(peercred_ex)
            denied_by_peercred = (
                peercred_ex.http_status == 403
                or (
                    peercred_ex.http_status is None
                    and peercred_ex.socket_error is not None
                )
            )
            _record_assertion(
                phase,
                f"unprivileged_uid_denied_by_so_peercred_{method}_{endpoint.strip('/').replace('/', '_')}",
                denied_by_peercred,
                "rejected by SO_PEERCRED (connection closed or HTTP 403)",
                {
                    "http_status": peercred_ex.http_status,
                    "socket_error": peercred_ex.socket_error,
                    "raw_response": peercred_ex.raw_response,
                },
            )

        # 3. `af --socket <sock> --json health` executed as unprivileged UID must fail with exit code 3 (RunnerIpcFailure)
        unpriv_af_health = run_recorded_command(
            [str(af_bin), "--socket", str(sock_path), "--json", "health"],
            cwd=work_root,
            run_as_uid=unpriv_uid,
            run_as_gid=unpriv_gid,
        )
        phase.commands.append(unpriv_af_health)
        ok_err_env, _, err_detail = evaluate_cli_envelope(
            unpriv_af_health.stderr,
            expected_status="error",
            expected_error_code="runner_ipc_failure",
        )
        _record_assertion(
            phase,
            "af_cli_health_as_unprivileged_uid_rejected_over_uds",
            unpriv_af_health.exit_code == 3 and ok_err_env,
            {"exit_code": 3, "error_code": "runner_ipc_failure"},
            {"exit_code": unpriv_af_health.exit_code, "detail": err_detail},
        )

        # Restore 0660 mode and verify runner log recorded the peer rejection
        os.chmod(sock_path, 0o660)
        runner_logs = daemon.read_logs()
        phase.artifacts["runner_peercred_log_excerpt"] = runner_logs[-1000:]
        _record_assertion(
            phase,
            "runner_logged_unauthorized_peer_rejection",
            "Rejected unauthorized UNIX socket peer" in runner_logs
            or "unauthorized unix socket peer" in runner_logs,
            "log contains unauthorized peer rejection message",
            runner_logs[-400:],
        )

        # 4. Unprivileged user invoking `af --json backup create` without `--root` or `--operator-privileged`
        # must fail closed with exit code 5 (`privilege_required`).
        unpriv_af_backup = run_recorded_command(
            [
                str(af_bin),
                "--json",
                "backup",
                "create",
                "--sqlite-only",
            ],
            cwd=work_root,
            run_as_uid=unpriv_uid,
            run_as_gid=unpriv_gid,
        )
        phase.commands.append(unpriv_af_backup)
        ok_priv_env, _, priv_detail = evaluate_cli_envelope(
            unpriv_af_backup.stderr,
            expected_status="error",
            expected_error_code="privilege_required",
        )
        _record_assertion(
            phase,
            "af_cli_backup_create_as_unprivileged_uid_denied_exit_5",
            unpriv_af_backup.exit_code == 5 and ok_priv_env,
            {"exit_code": 5, "error_code": "privilege_required"},
            {"exit_code": unpriv_af_backup.exit_code, "detail": priv_detail},
        )

    except Exception as exc:  # noqa: BLE001
        phase.failure_diagnostics.append(f"Unhandled exception in phase 4: {type(exc).__name__}: {exc}")
        _record_assertion(phase, "phase4_unhandled_exception", False, "no exception", str(exc))
    finally:
        daemon.stop()

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
    if any(not a.passed for a in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_5_restore_integrity_and_quiescence(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    t0 = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="restore_integrity_uid_gid_mode_and_quiescence",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    unpriv_uid, unpriv_gid, _ = resolve_unprivileged_identity()
    iso_root = work_root / "phase5_restore_iso"
    # Seed isolated root with specific non-root ownership (unpriv_uid:unpriv_gid) and strict file modes
    layout = seed_isolated_root_filesystem(iso_root, owner_uid=unpriv_uid, owner_gid=unpriv_gid)
    db_path = layout["db_path"]
    backups_dir = layout["backups_dir"]
    env_file = layout["env_file"]
    lock_file = layout["lock_file"]
    settings_file = layout["settings_file"]

    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("CREATE TABLE restore_verify (id INTEGER PRIMARY KEY, label TEXT NOT NULL);")
    conn.execute("INSERT INTO restore_verify (id, label) VALUES (1, 'golden_snapshot_row');")
    conn.commit()
    conn.close()
    os.chown(db_path, unpriv_uid, unpriv_gid)
    os.chmod(db_path, 0o640)

    phase.artifacts["pre_vacuum_db_sha256"] = compute_file_sha256(db_path)
    golden_env_sha = compute_file_sha256(env_file)
    golden_lock_sha = compute_file_sha256(lock_file)

    sock_iso = work_root / "run/phase5_iso_runner.sock"
    log_iso = work_root / "logs/phase5_iso_runner.log"
    daemon_iso = RunnerDaemonProcess(
        api_bin=api_bin,
        socket_path=sock_iso,
        env_overrides={
            "AETHERFLOW_BACKUP_ISOLATED_ROOT": str(iso_root),
            "AETHERFLOW_TRUSTED_SQLITE_UID": str(unpriv_uid),
            "AETHERFLOW_TRUSTED_SQLITE_GID": str(unpriv_gid),
        },
        log_path=log_iso,
    )

    # Set up a real disposable systemd unit in the guest `/etc/systemd/system` to test real
    # `CommandQuiescenceController` (`/bin/systemctl stop|start|is-active`) when
    # `AETHERFLOW_BACKUP_ISOLATED_ROOT` is NOT set on the runner.
    drill_unit_name = "aetherflow-v4-drill-quiesce.service"
    drill_unit_path = Path("/etc/systemd/system") / drill_unit_name
    sock_quiesce = work_root / "run/phase5_quiesce_runner.sock"
    log_quiesce = work_root / "logs/phase5_quiesce_runner.log"
    quiesce_staging_root = work_root / "phase5_quiesce_staging"
    quiesce_staging_root.mkdir(parents=True, exist_ok=True)

    daemon_quiesce: Optional[RunnerDaemonProcess] = None
    try:
        daemon_iso.start()

        # 1. Create golden archive backup containing DB + config files with recorded UID/GID/mode in manifest
        create_ex = perform_uds_http_request(
            str(sock_iso),
            "POST",
            "/v1/backup",
            body={
                "action": "create_archive",
                "app_version": "v4.0.0-drill",
                "timestamp_slug": "20261103T063000Z",
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
            "create_golden_archive_for_restore",
            ok_cr,
            "HTTP 200 create_archive",
            cr_detail,
        )
        archive_filename = (cr_payload or {}).get("filename")
        golden_db_sha = (((cr_payload or {}).get("details") or {}).get("sqlite_snapshot") or {}).get("sha256")
        if not isinstance(golden_db_sha, str) or len(golden_db_sha) != 64:
            raise ValueError("Runner did not return a verified SQLite snapshot checksum")
        assert isinstance(archive_filename, str) and archive_filename

        # 2. Unconfirmed destructive restore MUST fail closed via both UDS runner (HTTP 400) and CLI (exit 6)
        unconf_ex = perform_uds_http_request(
            str(sock_iso),
            "POST",
            "/v1/backup",
            body={
                "action": "restore_execute",
                "filename": archive_filename,
                "target_root": str(iso_root),
                "confirm_destructive_restore": False,
                "allow_overwrite": True,
            },
        )
        phase.uds_exchanges.append(unconf_ex)
        _record_assertion(
            phase,
            "uds_restore_without_confirmation_fails_closed",
            unconf_ex.http_status == 400
            and bool(unconf_ex.runner_response)
            and not bool(unconf_ex.runner_response.get("success", True)),
            "HTTP 400 when confirm_destructive_restore=False",
            {"http_status": unconf_ex.http_status, "runner_response": unconf_ex.runner_response},
        )

        unconf_cli = run_recorded_command(
            [
                str(af_bin),
                "--root",
                str(iso_root),
                "--json",
                "backup",
                "restore",
                archive_filename,
                "--backup-dir",
                str(backups_dir),
                "--target-root",
                str(iso_root),
            ],
            cwd=work_root,
        )
        phase.commands.append(unconf_cli)
        ok_unconf_env, _, unconf_detail = evaluate_cli_envelope(
            unconf_cli.stderr,
            expected_status="error",
            expected_error_code="unsupported_operation",
        )
        _record_assertion(
            phase,
            "af_cli_restore_without_confirmation_exits_6",
            unconf_cli.exit_code == 6 and ok_unconf_env,
            {"exit_code": 6, "error_code": "unsupported_operation"},
            {"exit_code": unconf_cli.exit_code, "detail": unconf_detail},
        )

        # 3. Corrupt live target files, alter ownership/modes to root:root 0777, and plant stale -wal/-shm sidecars
        env_file.write_text("CORRUPTED_ENV=1\n", encoding="utf-8")
        os.chown(env_file, 0, 0)
        os.chmod(env_file, 0o777)

        lock_file.write_text("CORRUPTED_LOCK=1\n", encoding="utf-8")
        os.chown(lock_file, 0, 0)
        os.chmod(lock_file, 0o777)

        conn_c = sqlite3.connect(str(db_path))
        conn_c.execute("DELETE FROM restore_verify;")
        conn_c.execute("INSERT INTO restore_verify (id, label) VALUES (999, 'mutated_post_backup');")
        conn_c.commit()
        conn_c.close()
        os.chown(db_path, 0, 0)
        os.chmod(db_path, 0o777)

        stale_wal = Path(f"{db_path}-wal")
        stale_shm = Path(f"{db_path}-shm")
        stale_wal.write_bytes(b"STALE_WAL_BYTES_MUST_BE_UNLINKED")
        stale_shm.write_bytes(b"STALE_SHM_BYTES_MUST_BE_UNLINKED")

        # 4. Install and start a real disposable systemd unit in the guest, then run a second runner
        # configured with explicit `AETHERFLOW_BACKUP_DIR`, `AETHERFLOW_DB_PATH`, and
        # `AETHERFLOW_RESTORE_STAGING_ROOT` (with `AETHERFLOW_BACKUP_ISOLATED_ROOT` UNSET and
        # `AETHERFLOW_BACKUP_DRY_RUN_QUIESCENCE=0`) so `CommandQuiescenceController` executes real
        # `/bin/systemctl stop`, `/bin/systemctl start`, and `/bin/systemctl is-active --quiet`!
        phase.contract_notes.append(
            "Contract note: af-runner sets dry_quiesce=true when AETHERFLOW_BACKUP_ISOLATED_ROOT is non-empty "
            "(crates/af-runner/src/lib.rs:881-887). To exercise real CommandQuiescenceController (/bin/systemctl) "
            "against an isolated target root, the runner must be launched with AETHERFLOW_BACKUP_ISOLATED_ROOT unset "
            "and AETHERFLOW_BACKUP_DIR, AETHERFLOW_DB_PATH, and AETHERFLOW_RESTORE_STAGING_ROOT set."
        )

        drill_unit_path.write_text(
            "[Unit]\n"
            "Description=AetherFlow v4 Privileged Guest Drill Quiescence Target\n"
            "\n"
            "[Service]\n"
            "Type=simple\n"
            f"ExecStart={sys.executable} -c 'import time; time.sleep(3600)'\n"
            "Restart=no\n",
            encoding="utf-8",
        )
        phase.commands.append(run_recorded_command(["systemctl", "daemon-reload"], cwd=work_root))
        phase.commands.append(run_recorded_command(["systemctl", "start", drill_unit_name], cwd=work_root))
        pre_active_cmd = run_recorded_command(["systemctl", "is-active", drill_unit_name], cwd=work_root)
        phase.commands.append(pre_active_cmd)
        pre_pid_cmd = run_recorded_command(
            ["systemctl", "show", "-p", "MainPID", "--value", drill_unit_name],
            cwd=work_root,
        )
        phase.commands.append(pre_pid_cmd)
        pre_main_pid = int(pre_pid_cmd.stdout.strip() or "0")

        _record_assertion(
            phase,
            "systemd_quiesce_target_unit_active_before_restore",
            pre_active_cmd.exit_code == 0 and pre_main_pid > 0,
            {"active": True, "MainPID_gt_0": True},
            {"exit_code": pre_active_cmd.exit_code, "MainPID": pre_main_pid},
        )

        # Copy the golden archive + sidecars into `quiesce_staging_root` or point `AETHERFLOW_BACKUP_DIR` at `backups_dir`
        # and `AETHERFLOW_RESTORE_STAGING_ROOT` at `iso_root` so `validate_runner_restore_target_root` permits `iso_root`!
        daemon_quiesce = RunnerDaemonProcess(
            api_bin=api_bin,
            socket_path=sock_quiesce,
            env_overrides={
                "AETHERFLOW_BACKUP_DIR": str(backups_dir),
                "AETHERFLOW_DB_PATH": str(db_path),
                "AETHERFLOW_RESTORE_STAGING_ROOT": str(iso_root),
                "AETHERFLOW_BACKUP_DRY_RUN_QUIESCENCE": "0",
                "AETHERFLOW_TRUSTED_SQLITE_UID": str(unpriv_uid),
                "AETHERFLOW_TRUSTED_SQLITE_GID": str(unpriv_gid),
            },
            log_path=log_quiesce,
        )
        daemon_quiesce.start()

        restore_ex = perform_uds_http_request(
            str(sock_quiesce),
            "POST",
            "/v1/backup",
            body={
                "action": "restore_execute",
                "filename": archive_filename,
                "target_root": str(iso_root),
                "confirm_destructive_restore": True,
                "allow_overwrite": True,
                "quiesce_services": [drill_unit_name],
            },
        )
        phase.uds_exchanges.append(restore_ex)
        ok_rest, _, rest_payload, rest_detail = evaluate_runner_backup_exchange(
            restore_ex.http_status,
            restore_ex.raw_response,
            expect_http_status=200,
            expect_runner_success=True,
            expected_action="restore_execute",
        )
        _record_assertion(
            phase,
            "uds_restore_execute_with_mandatory_service_quiescence",
            ok_rest,
            "HTTP 200 + restore_execute success",
            rest_detail,
        )

        restore_report = (rest_payload or {}).get("details") or {}
        quiesced_list = restore_report.get("quiesced_services") or []
        _record_assertion(
            phase,
            "restore_report_records_quiesced_systemd_service",
            drill_unit_name in quiesced_list,
            [drill_unit_name],
            quiesced_list,
        )

        # Verify systemd service was actually stopped and restarted (MainPID changed and service is active)
        post_active_cmd = run_recorded_command(["systemctl", "is-active", drill_unit_name], cwd=work_root)
        phase.commands.append(post_active_cmd)
        post_pid_cmd = run_recorded_command(
            ["systemctl", "show", "-p", "MainPID", "--value", drill_unit_name],
            cwd=work_root,
        )
        phase.commands.append(post_pid_cmd)
        post_main_pid = int(post_pid_cmd.stdout.strip() or "0")
        _record_assertion(
            phase,
            "systemd_unit_stopped_and_restarted_by_quiescence_controller",
            post_active_cmd.exit_code == 0 and post_main_pid > 0 and post_main_pid != pre_main_pid,
            {"active": True, "MainPID_restarted": True, "pre_pid": pre_main_pid},
            {"exit_code": post_active_cmd.exit_code, "post_pid": post_main_pid, "pre_pid": pre_main_pid},
        )

        # 5. Verify restored file contents (SHA-256), UID/GID, and file modes (0600, 0640, 0640)
        _record_assertion(
            phase,
            "restored_sqlite_db_sha256_and_contents_match_golden",
            compute_file_sha256(db_path) == golden_db_sha,
            golden_db_sha,
            compute_file_sha256(db_path),
        )
        with sqlite3.connect(f"file:{db_path}?mode=ro", uri=True) as restored_database:
            restored_rows = restored_database.execute("SELECT id, label FROM restore_verify ORDER BY id").fetchall()
            integrity = restored_database.execute("PRAGMA integrity_check").fetchone()[0]
        _record_assertion(
            phase,
            "restored_sqlite_committed_rows_and_integrity",
            integrity == "ok" and restored_rows == [(1, "golden_snapshot_row")],
            {"integrity": "ok", "rows": [(1, "golden_snapshot_row")]},
            {"integrity": integrity, "rows": restored_rows},
        )
        _record_assertion(
            phase,
            "restored_env_file_sha256_matches_golden",
            compute_file_sha256(env_file) == golden_env_sha,
            golden_env_sha,
            compute_file_sha256(env_file),
        )
        _record_assertion(
            phase,
            "restored_lock_file_sha256_matches_golden",
            compute_file_sha256(lock_file) == golden_lock_sha,
            golden_lock_sha,
            compute_file_sha256(lock_file),
        )

        for label, fpath, expected_mode in (
            ("env_file_0600", env_file, "0600"),
            ("lock_file_0640", lock_file, "0640"),
            ("db_file_0640", db_path, "0640"),
        ):
            st = os.stat(fpath)
            actual_mode = f"{stat.S_IMODE(st.st_mode):04o}"
            _record_assertion(
                phase,
                f"restored_{label}_uid_gid_and_mode_integrity",
                int(st.st_uid) == unpriv_uid
                and int(st.st_gid) == unpriv_gid
                and actual_mode == expected_mode,
                {"uid": unpriv_uid, "gid": unpriv_gid, "mode": expected_mode},
                {"uid": int(st.st_uid), "gid": int(st.st_gid), "mode": actual_mode},
            )

        # 6. Verify stale -wal and -shm sidecars were unlinked during SQLite restore
        _record_assertion(
            phase,
            "stale_wal_and_shm_sidecars_unlinked_on_restore",
            not stale_wal.exists() and not stale_shm.exists(),
            {"wal_exists": False, "shm_exists": False},
            {"wal_exists": stale_wal.exists(), "shm_exists": stale_shm.exists()},
        )

        # 7. Verify rollback when a requested quiesce service fails to stop (non-existent unit)
        env_file.write_text("PRE_FAILED_RESTORE_SENTINEL=keep_on_abort\n", encoding="utf-8")
        before_failed_stop = [snapshot_sentinel(path) for path in (env_file, lock_file, db_path)]
        failed_quiesce_ex = perform_uds_http_request(
            str(sock_quiesce),
            "POST",
            "/v1/backup",
            body={
                "action": "restore_execute",
                "filename": archive_filename,
                "target_root": str(iso_root),
                "confirm_destructive_restore": True,
                "allow_overwrite": True,
                "quiesce_services": ["nonexistent-aetherflow-unit-must-fail.service"],
            },
        )
        phase.uds_exchanges.append(failed_quiesce_ex)
        unchanged_after_failed_stop = [
            verify_sentinel_unchanged(before, snapshot_sentinel(Path(before.path)))
            for before in before_failed_stop
        ]
        stop_failure_response = failed_quiesce_ex.runner_response or {}
        _record_assertion(
            phase,
            "restore_fails_closed_when_quiesce_stop_fails_and_preserves_live_target",
            failed_quiesce_ex.http_status == 500
            and stop_failure_response.get("success") is False
            and "service quiescence failed" in stop_failure_response.get("error", "")
            and all(result[0] for result in unchanged_after_failed_stop),
            "HTTP 500 service quiescence failure + all live target metadata and bytes untouched",
            {
                "http_status": failed_quiesce_ex.http_status,
                "env_content": env_file.read_text(encoding="utf-8").strip(),
                "sentinel_checks": unchanged_after_failed_stop,
            },
        )

    except Exception as exc:  # noqa: BLE001
        phase.failure_diagnostics.append(f"Unhandled exception in phase 5: {type(exc).__name__}: {exc}")
        _record_assertion(phase, "phase5_unhandled_exception", False, "no exception", str(exc))
    finally:
        if daemon_quiesce is not None:
            daemon_quiesce.stop()
        daemon_iso.stop()
        if drill_unit_path.exists():
            subprocess.run(["systemctl", "stop", drill_unit_name], check=False, capture_output=True)
            try:
                drill_unit_path.unlink()
            except OSError:
                pass
            subprocess.run(["systemctl", "daemon-reload"], check=False, capture_output=True)

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
    if any(not a.passed for a in phase.assertions):
        phase.status = "failed"
    return phase


def run_phase_6_held_open_wal_snapshot_recovery(
    *,
    work_root: Path,
    api_bin: Path,
    af_bin: Path,
) -> DrillPhaseResult:
    started_at = utc_now_iso()
    t0 = time.monotonic()
    phase = DrillPhaseResult(
        phase_id="held_open_wal_snapshot_recovery",
        status="passed",
        real_execution=True,
        started_at=started_at,
        completed_at=started_at,
        duration_ms=0.0,
    )

    source_iso = work_root / "phase6_wal_source_iso"
    source_layout = seed_isolated_root_filesystem(source_iso)
    source_db = source_layout["db_path"]
    source_backups = source_layout["backups_dir"]

    recovery_iso = work_root / "phase6_wal_recovery_iso"
    recovery_layout = seed_isolated_root_filesystem(recovery_iso)
    recovery_db = recovery_layout["db_path"]

    sock_path = work_root / "run/phase6_runner.sock"
    log_path = work_root / "logs/phase6_runner.log"

    wal_session = HeldOpenWalSession(source_db)
    daemon = RunnerDaemonProcess(
        api_bin=api_bin,
        socket_path=sock_path,
        env_overrides={
            "AETHERFLOW_BACKUP_ISOLATED_ROOT": str(source_iso),
            "AETHERFLOW_RESTORE_STAGING_ROOT": str(recovery_iso),
        },
        log_path=log_path,
    )
    try:
        wal_info = wal_session.start()
        phase.artifacts["source_live_wal_state"] = wal_info
        daemon.start()

        # 1. Capture both an archive backup and a standalone SQLite backup while `wal_session` holds:
        #    - committed rows strictly in uncheckpointed `-wal` frames (`wal_autocheckpoint=0`)
        #    - an active reader transaction lock
        #    - an uncommitted write transaction (`uncommitted_inflight_txn_must_not_leak`)
        arch_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={
                "action": "create_archive",
                "app_version": "v4.0.0-drill",
                "timestamp_slug": "20261103T064001Z",
            },
        )
        phase.uds_exchanges.append(arch_ex)
        ok_arch, _, arch_payload, arch_detail = evaluate_runner_backup_exchange(
            arch_ex.http_status,
            arch_ex.raw_response,
            expect_http_status=200,
            expect_runner_success=True,
            expected_action="create_archive",
        )
        _record_assertion(
            phase,
            "capture_archive_snapshot_from_held_open_wal_db",
            ok_arch,
            "HTTP 200 create_archive",
            arch_detail,
        )
        arch_filename = (arch_payload or {}).get("filename")
        assert isinstance(arch_filename, str) and arch_filename

        # 2. Seed `recovery_db` with pre-existing dirty WAL/SHM files, then restore the snapshot into `recovery_iso`
        conn_dirty = sqlite3.connect(str(recovery_db))
        conn_dirty.execute("PRAGMA journal_mode=WAL;")
        conn_dirty.execute("CREATE TABLE old_garbage (x TEXT);")
        conn_dirty.commit()
        conn_dirty.close()
        Path(f"{recovery_db}-wal").write_bytes(b"OLD_DIRTY_WAL_FRAMES")
        Path(f"{recovery_db}-shm").write_bytes(b"OLD_DIRTY_SHM_FRAMES")

        rest_ex = perform_uds_http_request(
            str(sock_path),
            "POST",
            "/v1/backup",
            body={
                "action": "restore_execute",
                "filename": arch_filename,
                "target_root": str(recovery_iso),
                "confirm_destructive_restore": True,
                "allow_overwrite": True,
            },
        )
        phase.uds_exchanges.append(rest_ex)
        ok_rest, _, _, rest_detail = evaluate_runner_backup_exchange(
            rest_ex.http_status,
            rest_ex.raw_response,
            expect_http_status=200,
            expect_runner_success=True,
            expected_action="restore_execute",
        )
        _record_assertion(
            phase,
            "restore_held_open_wal_snapshot_into_recovery_root",
            ok_rest,
            "HTTP 200 restore_execute",
            rest_detail,
        )

        # 3. Also test `af --json backup restore` CLI recovery into a second clean directory
        cli_recovery_iso = work_root / "phase6_cli_wal_recovery_iso"
        cli_recovery_layout = seed_isolated_root_filesystem(cli_recovery_iso)
        shutil.copytree(source_backups, cli_recovery_layout["backups_dir"], dirs_exist_ok=True)
        cli_rest_cmd = run_recorded_command(
            [
                str(af_bin),
                "--root",
                str(cli_recovery_iso),
                "--json",
                "backup",
                "restore",
                arch_filename,
                "--backup-dir",
                str(cli_recovery_layout["backups_dir"]),
                "--target-root",
                str(cli_recovery_iso),
                "--confirm-destructive-restore",
                "--allow-overwrite",
            ],
            cwd=work_root,
        )
        phase.commands.append(cli_rest_cmd)
        ok_cli_r, _, cli_r_detail = evaluate_cli_envelope(cli_rest_cmd.stdout, expected_status="ok")
        _record_assertion(
            phase,
            "af_cli_restore_held_open_wal_snapshot",
            cli_rest_cmd.exit_code == 0 and ok_cli_r,
            "exit 0 + ok envelope",
            cli_r_detail,
        )

        # 4. Inspect both recovered SQLite databases:
        #    - PRAGMA integrity_check == "ok"
        #    - PRAGMA quick_check == "ok"
        #    - PRAGMA user_version == 404
        #    - All committed WAL rows (`committed_row_1..3`, `schema_marker`) are present
        #    - Uncommitted in-flight write row (`uncommitted_inflight_txn_must_not_leak`) is NOT present
        for label, target_db in (
            ("uds_recovered_db", recovery_db),
            ("cli_recovered_db", cli_recovery_layout["db_path"]),
        ):
            r_conn = sqlite3.connect(str(target_db))
            try:
                integrity = r_conn.execute("PRAGMA integrity_check;").fetchone()[0]
                quick = r_conn.execute("PRAGMA quick_check;").fetchone()[0]
                user_ver = r_conn.execute("PRAGMA user_version;").fetchone()[0]
                rows = dict(r_conn.execute("SELECT k, v FROM drill_kv ORDER BY k;").fetchall())
            finally:
                r_conn.close()

            expected_rows = dict(wal_session.committed_rows)
            uncommitted_present = wal_session.uncommitted_key in rows
            phase.artifacts[label] = {
                "path": str(target_db),
                "sha256": compute_file_sha256(target_db),
                "integrity_check": integrity,
                "quick_check": quick,
                "user_version": user_ver,
                "recovered_rows": rows,
                "uncommitted_present": uncommitted_present,
            }
            _record_assertion(
                phase,
                f"{label}_sqlite_integrity_and_wal_snapshot_consistency",
                integrity == "ok"
                and quick == "ok"
                and int(user_ver) == 404
                and rows == expected_rows
                and not uncommitted_present,
                {
                    "integrity_check": "ok",
                    "quick_check": "ok",
                    "user_version": 404,
                    "rows": expected_rows,
                    "uncommitted_present": False,
                },
                phase.artifacts[label],
            )

    except Exception as exc:  # noqa: BLE001
        phase.failure_diagnostics.append(f"Unhandled exception in phase 6: {type(exc).__name__}: {exc}")
        _record_assertion(phase, "phase6_unhandled_exception", False, "no exception", str(exc))
    finally:
        daemon.stop()
        wal_session.stop()

    phase.completed_at = utc_now_iso()
    phase.duration_ms = round((time.monotonic() - t0) * 1000.0, 2)
    if any(not a.passed for a in phase.assertions):
        phase.status = "failed"
    return phase


def execute_guest_drill_suite(
    *,
    confirm_disposable_guest: bool,
    work_root: str,
    api_bin: str,
    af_bin: str,
    guest_marker_file: str = DEFAULT_GUEST_MARKER_FILE,
    keep_work_root: bool = False,
) -> Dict[str, Any]:
    """Run all 6 mandatory privileged guest drill phases and return the structured JSON report."""
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
    t0 = time.monotonic()
    phases: List[DrillPhaseResult] = []
    try:
        phases.append(
            run_phase_1_provenance(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
                guardrail_info=guardrail_info,
            )
        )
        phases.append(
            run_phase_2_backup_roundtrip_with_live_wal(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
            )
        )
        phases.append(
            run_phase_3_arbitrary_root_and_sentinel_rejection(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
            )
        )
        phases.append(
            run_phase_4_unprivileged_authorization_denial(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
            )
        )
        phases.append(
            run_phase_5_restore_integrity_and_quiescence(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
            )
        )
        phases.append(
            run_phase_6_held_open_wal_snapshot_recovery(
                work_root=work_root_path,
                api_bin=api_bin_path,
                af_bin=af_bin_path,
            )
        )
    finally:
        if not keep_work_root and work_root_path.exists():
            shutil.rmtree(work_root_path, ignore_errors=True)

    evaluation = evaluate_drill_suite_status(phases)
    suite_completed = utc_now_iso()
    return {
        "schema_version": HARNESS_SCHEMA_VERSION,
        "started_at": suite_started,
        "completed_at": suite_completed,
        "duration_ms": round((time.monotonic() - t0) * 1000.0, 2),
        "guardrails": guardrail_info,
        "evaluation": evaluation,
        "phases": [asdict(p) for p in phases],
    }


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="AetherFlow v4 Privileged Guest Drills Harness (disposable QEMU/systemd VM only)."
    )
    parser.add_argument(
        "--confirm-disposable-guest",
        action="store_true",
        help="Required explicit confirmation that execution is inside a disposable QEMU/systemd guest.",
    )
    parser.add_argument(
        "--work-root",
        default=f"{ALLOWED_WORK_ROOT_PREFIX}-run",
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
    args = parser.parse_args(argv)
    try:
        report = execute_guest_drill_suite(
            confirm_disposable_guest=bool(args.confirm_disposable_guest),
            work_root=str(args.work_root),
            api_bin=str(args.api_bin),
            af_bin=str(args.af_bin),
            guest_marker_file=str(args.guest_marker_file),
            keep_work_root=bool(args.keep_work_root),
        )
    except GuestSafetyError as exc:
        err_report = {
            "schema_version": HARNESS_SCHEMA_VERSION,
            "timestamp": utc_now_iso(),
            "overall_status": "blocked_by_guest_safety_guardrail",
            "overall_passed": False,
            "error": str(exc),
        }
        rendered = json.dumps(err_report, indent=2, sort_keys=True)
        if args.json_out:
            Path(args.json_out).write_text(rendered + "\n", encoding="utf-8")
        print(rendered)
        return 2

    rendered = json.dumps(report, indent=2, sort_keys=True)
    if args.json_out:
        out_path = Path(args.json_out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0 if report["evaluation"]["overall_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
