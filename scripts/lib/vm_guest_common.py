"""Shared guest drill primitives, UDS HTTP clients, sentinels, and system inspection helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import socket
import stat
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple
import urllib.error
import urllib.request

try:
    import fcntl
    import grp
    import pwd
except ImportError:  # pragma: no cover - Windows unit-test import fallback
    fcntl = None  # type: ignore[assignment]
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]


PROGRESS_LINE_RE = re.compile(r"^\[PROGRESS:(\d{1,3})\]\s+(.+)$")
RUNNER_EXIT_ERROR_PREFIX = "__RUNNER_EXIT_ERROR__:"

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




def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def utc_now_iso_z() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_file_digest(path: Path, algorithm: str = "sha256") -> str:
    """Computes the lowercase hex digest (`sha256` or `sha512`) of `path`."""
    algo = algorithm.lower()
    if algo == "sha256":
        hasher = hashlib.sha256()
    elif algo == "sha512":
        hasher = hashlib.sha512()
    else:
        raise ValueError(f"unsupported hash algorithm: {algorithm!r}")

    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_file_sha256(path: Path) -> str:
    return compute_file_digest(path, "sha256")


def record_phase_assertion(
    phase: DrillPhaseResult,
    name: str,
    passed: bool,
    expected: Any,
    actual: Any,
    detail: str = "",
    *,
    record_diagnostic: bool = True,
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
    if record_diagnostic and not passed:
        phase.failure_diagnostics.append(
            f"Assertion {name!r} failed: expected={expected!r}, actual={actual!r} ({detail})"
        )


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
    required_phases: Sequence[str] = (),
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



_UnixStreamHTTPConnection = _UnixDomainHTTPConnection

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
        connection = _UnixDomainHTTPConnection(socket_path, timeout=timeout)
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


def probe_http_endpoint(url: str, timeout_seconds: float = 10.0, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    try:
        request_obj = urllib.request.Request(
            url,
            headers={"User-Agent": "AetherFlow-v4-NativePackageDrill/1.0", **(headers or {})},
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


