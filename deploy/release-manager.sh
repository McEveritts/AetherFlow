#!/bin/bash
###############################################################################
# AetherFlow Release Manager v4.0 — Pull-Based Atomic Release Engine
#
# Pulls pre-built, checksum-verified releases from GitHub Releases
# (or builds in fallback --from-source mode), snapshots the live SQLite database
# with a WAL-safe online backup, atomically swaps /opt/AetherFlow/current,
# restarts systemd units (aetherflow-runner + aetherflow-api), and runs a deep
# readiness probe with automatic rollback.
#
# The live database is resolved by resolve_db_path. It is often not
# ${DATA_DIR}/${SQLITE_DB} on hosts upgraded from the pre-FHS layout.
#
# Usage:
#   release-manager.sh deploy [--channel stable|nightly] [--from-source] [--dry-run] [--offline]
#   release-manager.sh rollback [--dry-run]
#   release-manager.sh cleanup [--dry-run]
#   release-manager.sh migrate-systemd [--dry-run]
#
# --dry-run keeps every write under ${DRY_RUN_ROOT:-/tmp/aetherflow-dryrun},
# downloads and verifies the real release artifact, and snapshots a sqlite3
# .backup copy of the resolved live database. It does not restart systemd.
# --offline (or AF_OFFLINE=1) with --dry-run keeps the network-free placeholder
# artifact used by CI.
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Pre-scan CLI Arguments for --root, --config, and --job-status-file ───────
CLI_ROOT_OVERRIDE=""
CLI_CONF_OVERRIDE="${AETHERFLOW_RELEASE_CONF:-}"
SELF_UPDATE_STATUS_FILE="${AETHERFLOW_SELF_UPDATE_STATUS_FILE:-}"
SELF_UPDATE_JOB_UNIT="${AETHERFLOW_SELF_UPDATE_JOB_UNIT:-}"
LAST_LOG_ERROR=""

_prev_arg=""
for _arg in "$@"; do
    case "${_prev_arg}" in
        --root)
            CLI_ROOT_OVERRIDE="${_arg}"
            _prev_arg=""
            continue
            ;;
        --config)
            CLI_CONF_OVERRIDE="${_arg}"
            _prev_arg=""
            continue
            ;;
        --job-status-file)
            SELF_UPDATE_STATUS_FILE="${_arg}"
            _prev_arg=""
            continue
            ;;
        --job-unit)
            SELF_UPDATE_JOB_UNIT="${_arg}"
            _prev_arg=""
            continue
            ;;
    esac
    case "${_arg}" in
        --root|--config|--job-status-file|--job-unit)
            _prev_arg="${_arg}"
            ;;
    esac
done

write_self_update_status_receipt() {
    local status_str="$1"
    local completed_bool="$2"
    local success_bool="$3"
    local exit_code_val="$4"
    local err_msg="$5"

    [[ -n "${SELF_UPDATE_STATUS_FILE}" ]] || return 0
    # The scheduler creates the directory and receipt and pins the directory's
    # device/inode. Never bootstrap or rebind a worker receipt by a pathname.
    if command -v python3 >/dev/null 2>&1; then
        python3 - "${SELF_UPDATE_STATUS_FILE}" "${status_str}" "${completed_bool}" "${success_bool}" "${SELF_UPDATE_JOB_UNIT}" "${exit_code_val}" "${err_msg}" "${AETHERFLOW_SELF_UPDATE_DIRECTORY_DEV:-}" "${AETHERFLOW_SELF_UPDATE_DIRECTORY_INO:-}" <<'PY'
import fcntl, json, os, pathlib, stat, sys, uuid
final_path, status_str, completed_s, success_s, job_unit, exit_s, err_msg, device, inode = sys.argv[1:]
if not device.isdecimal() or not inode.isdecimal():
    sys.exit("Scheduled self-update receipt directory identity is required")
expected_directory = (int(device), int(inode))
path = pathlib.Path(final_path)
def identity(metadata):
    return metadata.st_dev, metadata.st_ino

class Directory:
    def __init__(self, name):
        parts = pathlib.PurePosixPath(name).parts
        if not parts or parts[0] != "/" or ".." in parts:
            raise RuntimeError("Receipt and lock paths must be absolute and non-traversing")
        self.chain = [(None, os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC))]
        try:
            for component in parts[1:]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=self.fd)
                self.chain.append((component, child))
            self.verify()
        except BaseException:
            self.close()
            raise

    @property
    def fd(self):
        return self.chain[-1][1]

    def verify(self):
        for index, (component, descriptor) in enumerate(self.chain):
            held = os.fstat(descriptor)
            if not stat.S_ISDIR(held.st_mode) or held.st_nlink == 0:
                raise RuntimeError("Receipt or lock directory disappeared")
            if index:
                entry = os.stat(component, dir_fd=self.chain[index - 1][1], follow_symlinks=False)
                if not stat.S_ISDIR(entry.st_mode) or identity(entry) != identity(held):
                    raise RuntimeError("Receipt or lock directory identity changed")

    def close(self):
        for _, descriptor in reversed(self.chain):
            os.close(descriptor)
        self.chain = []

def verify_file(directory, name, descriptor):
    directory.verify()
    held = os.fstat(descriptor)
    entry = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
    if not stat.S_ISREG(held.st_mode) or held.st_nlink != 1 or identity(entry) != identity(held) or not stat.S_ISREG(entry.st_mode):
        raise RuntimeError("Receipt or lock is not a private regular file with a stable identity")

def open_file(directory, name, flags, mode=0o600):
    directory.verify()
    descriptor = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, mode, dir_fd=directory.fd)
    try:
        verify_file(directory, name, descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise

directory = Directory(str(path.parent))
lock_fd = None
try:
    if identity(os.fstat(directory.fd)) != expected_directory:
        raise RuntimeError("Scheduled self-update receipt directory identity changed")
    lock_name = path.name + ".lock"
    lock_fd = open_file(directory, lock_name, os.O_RDWR | os.O_CREAT)
    fcntl.flock(lock_fd, fcntl.LOCK_EX)
    verify_file(directory, lock_name, lock_fd)
    source_fd = open_file(directory, path.name, os.O_RDONLY)
    with os.fdopen(source_fd, "rb") as source:
        raw = source.read(256 * 1024 + 1)
        if len(raw) > 256 * 1024:
            raise RuntimeError("Self-update receipt exceeds the size limit")
        current = json.loads(raw)
        verify_file(directory, path.name, source.fileno())
        source_identity = identity(os.fstat(source.fileno()))
    if current.get("job_unit") != job_unit or not job_unit:
        raise RuntimeError("Self-update receipt identity does not match")
    if type(current.get("completed")) is not bool:
        raise RuntimeError("Self-update receipt completion is invalid")
    if current["completed"]:
        sys.exit("Self-update admission was closed; refusing a late worker" if status_str == "running" else 0)
    if current.get("status") not in ("launching", "running"):
        raise RuntimeError("Self-update receipt is not an active admission")
    payload = {
        "status": status_str,
        "completed": completed_s == "true",
        "success": success_s == "true",
        "job_unit": job_unit,
        "error": err_msg,
        "exit_code": None if exit_s == "null" else int(exit_s),
    }
    temporary = path.name + ".tmp." + uuid.uuid4().hex
    try:
        output_fd = open_file(directory, temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        with os.fdopen(output_fd, "w", encoding="utf-8") as output:
            # Keep the runner reader's existing readability contract.
            os.fchmod(output.fileno(), 0o644)
            json.dump(payload, output)
            output.flush()
            os.fsync(output.fileno())
            verify_file(directory, temporary, output.fileno())
            verify_file(directory, lock_name, lock_fd)
            target = os.stat(path.name, dir_fd=directory.fd, follow_symlinks=False)
            if not stat.S_ISREG(target.st_mode) or target.st_nlink != 1 or identity(target) != source_identity:
                raise RuntimeError("Self-update receipt changed during update")
            os.replace(temporary, path.name, src_dir_fd=directory.fd, dst_dir_fd=directory.fd)
            temporary = None
            verify_file(directory, path.name, output.fileno())
            os.fsync(directory.fd)
    finally:
        if temporary is not None:
            try:
                os.unlink(temporary, dir_fd=directory.fd)
            except FileNotFoundError:
                pass
finally:
    if lock_fd is not None:
        os.close(lock_fd)
    directory.close()
PY
    else
        printf '%s\n' 'python3 is required for a locked self-update receipt' >&2
        return 1
    fi
}

ACTIVE_STAGE_DIR=""
RECOVERY_OPERATION_ID=""
RECOVERY_STARTED_AT=""
RECOVERY_COMMAND=""
RECOVERY_CHANNEL=""
RECOVERY_PHASE=""
RECOVERY_CANDIDATE_RELEASE=""
RECOVERY_PREVIOUS_RELEASE=""
RECOVERY_SNAPSHOT_PATH=""
RECOVERY_OWNS_JOURNAL=false
INFERRED_POST_SWAP_CANDIDATE=""
RECOVERY_FROM_UNFINISHED_POST_SWAP=false

save_recovery_state() {
    local phase="$1"
    local err_msg="${2:-}"
    [[ -n "${RELEASES_DIR:-}" && -n "${RECOVERY_OPERATION_ID:-}" ]] || return 0
    command -v python3 >/dev/null 2>&1 || return 0
    RECOVERY_PHASE="${phase}"
    RECOVERY_OWNS_JOURNAL=true
    python3 - "${RELEASES_DIR}" "${RECOVERY_OPERATION_ID}" "${RECOVERY_COMMAND}" "${RECOVERY_CHANNEL}" "${DRY_RUN:-false}" "${phase}" "${RECOVERY_CANDIDATE_RELEASE}" "${RECOVERY_PREVIOUS_RELEASE}" "${RESOLVED_DB_PATH:-}" "${RESOLVED_DB_SOURCE:-}" "${RECOVERY_SNAPSHOT_PATH}" "${RECOVERY_STARTED_AT}" "${err_msg}" <<'PY'
import datetime, json, os, pathlib, stat, sys, uuid

(
    releases_dir_s,
    op_id,
    cmd,
    channel,
    dry_run_s,
    phase,
    cand_rel,
    prev_rel,
    db_path,
    db_source,
    snap_path,
    started_at,
    err_msg,
) = sys.argv[1:]

releases_dir = pathlib.Path(releases_dir_s)
if releases_dir.is_symlink():
    raise SystemExit(f"Refusing symlinked releases directory: {releases_dir}")
releases_dir.mkdir(parents=True, exist_ok=True)
target = releases_dir / ".recovery_state.json"
if target.is_symlink():
    raise SystemExit(f"Refusing symlinked recovery journal: {target}")

now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
payload = {
    "operation_id": op_id,
    "command": cmd,
    "channel": "nightly" if channel == "experimental" else (channel or "stable"),
    "dry_run": dry_run_s == "true",
    "phase": phase,
    "candidate_release": cand_rel or None,
    "previous_release": prev_rel or None,
    "resolved_db_path": db_path or None,
    "resolved_db_source": db_source or None,
    "snapshot_path": snap_path or None,
    "started_at": started_at or now,
    "updated_at": now,
}
if err_msg:
    payload["last_error"] = err_msg

data = json.dumps(payload, indent=2).encode("utf-8") + b"\n"
tmp_name = releases_dir / f".recovery_state.json.tmp.{os.getpid()}.{uuid.uuid4().hex}"
fd = os.open(str(tmp_name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
try:
    with os.fdopen(fd, "wb") as fh:
        os.fchmod(fh.fileno(), 0o600)
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(str(tmp_name), str(target))
    tmp_name = None
finally:
    if tmp_name is not None:
        try:
            os.unlink(str(tmp_name))
        except OSError:
            pass
PY
}

finalize_recovery_state_on_exit() {
    local rc="$1"
    [[ "${rc}" -ne 0 && "${RECOVERY_OWNS_JOURNAL}" == true ]] || return 0
    [[ "${RECOVERY_PHASE}" != "complete" && "${RECOVERY_PHASE}" != "failed" ]] || return 0
    local msg="${LAST_LOG_ERROR:-release-manager exited with status ${rc}}"
    case "${RECOVERY_PHASE}" in
        stage0_fhs_layout|stage1_scaffold|stage1_5_snapshot)
            if [[ -n "${RECOVERY_CANDIDATE_RELEASE}" && -d "${RECOVERY_CANDIDATE_RELEASE}" && ! -L "${RECOVERY_CANDIDATE_RELEASE}" ]]; then
                local cur_real="" prev_real="" cand_real=""
                [[ -L "${CURRENT_LINK:-}" ]] && cur_real="$(readlink -f "${CURRENT_LINK}" 2>/dev/null || true)"
                [[ -f "${RELEASES_DIR:-}/.previous_release" ]] && prev_real="$(readlink -f "$(cat "${RELEASES_DIR}/.previous_release")" 2>/dev/null || true)"
                cand_real="$(readlink -f "${RECOVERY_CANDIDATE_RELEASE}" 2>/dev/null || true)"
                if [[ -n "${cand_real}" && "${cand_real}" == "${RELEASES_DIR%/}/"* && "${cand_real}" != "${cur_real}" && "${cand_real}" != "${prev_real}" ]]; then
                    rm -rf "${RECOVERY_CANDIDATE_RELEASE}" 2>/dev/null || true
                fi
            fi
            save_recovery_state "failed" "${msg}" || true
            ;;
        stage5_cleanup|stage6_migrate_systemd)
            save_recovery_state "failed" "${msg}" || true
            ;;
        stage4_rollback)
            if [[ "${RECOVERY_FROM_UNFINISHED_POST_SWAP}" == true ]]; then
                save_recovery_state "stage4_rollback" "${msg}" || true
            else
                save_recovery_state "failed" "${msg}" || true
            fi
            ;;
        stage2_symlink_swap|stage3_health_probe)
            save_recovery_state "${RECOVERY_PHASE}" "${msg}" || true
            ;;
    esac
}

finalize_self_update_status_on_exit() {
    local rc="$1"
    [[ -n "${SELF_UPDATE_STATUS_FILE}" ]] || return 0
    if [[ "${rc}" -eq 0 ]]; then
        write_self_update_status_receipt "succeeded" "true" "true" "0" ""
    else
        local msg="${LAST_LOG_ERROR:-release-manager exited with status ${rc}}"
        write_self_update_status_receipt "failed" "true" "false" "${rc}" "${msg}"
    fi
}

cleanup_on_exit() {
    local rc="$1"
    if [[ -n "${ACTIVE_STAGE_DIR:-}" && -d "${ACTIVE_STAGE_DIR}" && ! -L "${ACTIVE_STAGE_DIR}" ]]; then
        rm -rf "${ACTIVE_STAGE_DIR}" 2>/dev/null || true
    fi
    ACTIVE_STAGE_DIR=""
    finalize_recovery_state_on_exit "${rc}"
    finalize_self_update_status_on_exit "${rc}"
}

if [[ -n "${SELF_UPDATE_STATUS_FILE}" ]]; then
    write_self_update_status_receipt "running" "false" "false" "null" "" || exit 1
fi
trap 'cleanup_on_exit $?' EXIT

EFFECTIVE_RELEASE_ROOT=""
if [[ -n "${CLI_ROOT_OVERRIDE}" && -n "${AETHERFLOW_RELEASE_ROOT:-}" ]]; then
    if [[ "${CLI_ROOT_OVERRIDE%/}" != "${AETHERFLOW_RELEASE_ROOT%/}" ]]; then
        LAST_LOG_ERROR="Conflicting isolated release roots: --root=${CLI_ROOT_OVERRIDE} vs AETHERFLOW_RELEASE_ROOT=${AETHERFLOW_RELEASE_ROOT}"
        echo "[FATAL] ${LAST_LOG_ERROR}"
        exit 4
    fi
    EFFECTIVE_RELEASE_ROOT="${CLI_ROOT_OVERRIDE%/}"
elif [[ -n "${CLI_ROOT_OVERRIDE}" ]]; then
    EFFECTIVE_RELEASE_ROOT="${CLI_ROOT_OVERRIDE%/}"
elif [[ -n "${AETHERFLOW_RELEASE_ROOT:-}" ]]; then
    EFFECTIVE_RELEASE_ROOT="${AETHERFLOW_RELEASE_ROOT%/}"
fi

if [[ -n "${EFFECTIVE_RELEASE_ROOT}" ]]; then
    if [[ "${EFFECTIVE_RELEASE_ROOT}" == *".."* ]]; then
        LAST_LOG_ERROR="Isolated release root must not contain '..': ${EFFECTIVE_RELEASE_ROOT}"
        echo "[FATAL] ${LAST_LOG_ERROR}"
        exit 4
    fi
    export AETHERFLOW_RELEASE_ROOT="${EFFECTIVE_RELEASE_ROOT}"
    : "${RELEASES_DIR:=${EFFECTIVE_RELEASE_ROOT}/opt/AetherFlow/releases}"
    : "${CURRENT_LINK:=${EFFECTIVE_RELEASE_ROOT}/opt/AetherFlow/current}"
    : "${REPO_DIR:=${EFFECTIVE_RELEASE_ROOT}/opt/AetherFlow}"
    : "${LEGACY_OPT_ROOT:=${EFFECTIVE_RELEASE_ROOT}/opt/AetherFlow}"
    : "${DRY_RUN_ROOT:=${EFFECTIVE_RELEASE_ROOT}/tmp/aetherflow-dryrun}"
    : "${LOG_FILE:=${EFFECTIVE_RELEASE_ROOT}/var/log/aetherflow/deploy.log}"
    : "${DATA_DIR:=${EFFECTIVE_RELEASE_ROOT}/var/lib/aetherflow}"
    : "${ENV_DIR:=${EFFECTIVE_RELEASE_ROOT}/etc/aetherflow}"
    : "${ENV_FILE:=${EFFECTIVE_RELEASE_ROOT}/etc/aetherflow/aetherflow.env}"
    : "${SYSTEMD_UNITS_SRC:=${EFFECTIVE_RELEASE_ROOT}/opt/AetherFlow/deploy/systemd}"
    : "${SYSTEMD_UNITS_DST:=${EFFECTIVE_RELEASE_ROOT}/etc/systemd/system}"
    : "${CLI_BIN_DIR:=${EFFECTIVE_RELEASE_ROOT}/usr/local/bin}"
fi

load_conf_file_safely() {
    local conf_path="$1"
    if command -v python3 >/dev/null 2>&1; then
        local parsed_records=""
        if ! parsed_records="$(python3 - "${conf_path}" "${SCRIPT_DIR}" <<'PY'
import base64, re, sys

conf_path = sys.argv[1]
script_dir = sys.argv[2]
allowed_keys = {
    "RELEASES_DIR", "CURRENT_LINK", "REPO_DIR", "LEGACY_OPT_ROOT", "DRY_RUN_ROOT",
    "GITHUB_REPO", "RELEASE_CHANNEL", "ARTIFACT_NAME", "RELEASE_ASSET_NAME", "CHECKSUM_NAME", "GIT_BRANCH",
    "GIT_REMOTE", "NODE_HEAP_MB", "HEALTH_ENDPOINT", "HEALTH_RETRIES",
    "HEALTH_INTERVAL", "MAX_RELEASES", "LOG_FILE", "DATA_DIR", "ENV_DIR", "ENV_FILE",
    "SQLITE_DB", "SNAPSHOT_TIMEOUT", "SYSTEMD_UNITS_SRC", "SYSTEMD_UNITS_DST",
    "CLI_BIN_DIR", "AETHERFLOW_RELEASE_ROOT", "AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH",
}
key_re = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

def decode_value(raw, key, line_no):
    s = raw.strip()
    if not s:
        return "", False
    if s[0] == "'":
        if len(s) < 2 or not s.endswith("'") or "'" in s[1:-1]:
            raise ValueError(f"unterminated single-quoted value for {key} at line {line_no}")
        return s[1:-1], False
    if s[0] == '"':
        inner = s[1:]
        out = []
        idx = 0
        closed = False
        while idx < len(inner):
            ch = inner[idx]
            if ch == "\\":
                idx += 1
                if idx >= len(inner):
                    raise ValueError(f"trailing backslash for {key} at line {line_no}")
                esc = inner[idx]
                if esc == "n":
                    out.append("\n")
                elif esc == "r":
                    out.append("\r")
                elif esc == "t":
                    out.append("\t")
                elif esc in ('"', "\\", "$", "`"):
                    out.append(esc)
                else:
                    out.append("\\")
                    out.append(esc)
            elif ch == '"':
                trailing = inner[idx + 1:].strip()
                if trailing and not trailing.startswith("#"):
                    raise ValueError(f"unexpected trailing characters for {key} at line {line_no}")
                closed = True
                break
            elif ch == "`":
                raise ValueError(f"unescaped backtick command substitution for {key} at line {line_no}")
            elif ch == "$" and idx + 1 < len(inner) and inner[idx + 1] == "(":
                raise ValueError(f"unescaped command substitution for {key} at line {line_no}")
            else:
                out.append(ch)
            idx += 1
        if not closed:
            raise ValueError(f"unterminated double-quoted value for {key} at line {line_no}")
        decoded = "".join(out)
        prefix = "${" + key + ":-"
        if decoded.startswith(prefix) and decoded.endswith("}"):
            fallback = decoded[len(prefix):-1].replace("${SCRIPT_DIR}", script_dir)
            if "$(" in fallback or "`" in fallback or "${" in fallback:
                raise ValueError(f"unsupported shell expansion in default for {key} at line {line_no}")
            return fallback, True
        if "${SCRIPT_DIR}" in s:
            decoded = decoded.replace("${SCRIPT_DIR}", script_dir)
        return decoded, False
    for idx, ch in enumerate(s):
        if ch.isspace() and s[idx:].strip().startswith("#"):
            s = s[:idx].strip()
            break
    if any(tok in s for tok in ("$(", "`", ";", "|", "&", "<", ">")):
        raise ValueError(f"disallowed shell metacharacter in unquoted value for {key} at line {line_no}")
    prefix = "${" + key + ":-"
    if s.startswith(prefix) and s.endswith("}"):
        fallback = s[len(prefix):-1].replace("${SCRIPT_DIR}", script_dir)
        if "$(" in fallback or "`" in fallback or "${" in fallback:
            raise ValueError(f"unsupported shell expansion in default for {key} at line {line_no}")
        return fallback, True
    if "${" in s.replace("${SCRIPT_DIR}", ""):
        raise ValueError(f"unsupported parameter expansion for {key} at line {line_no}")
    return s.replace("${SCRIPT_DIR}", script_dir), False

try:
    with open(conf_path, "r", encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    for idx, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export") and len(line) > 6 and line[6].isspace():
            line = line[6:].lstrip()
        if "=" not in line:
            raise ValueError(f"malformed configuration line {idx}")
        k_raw, v_raw = line.split("=", 1)
        key = k_raw.strip()
        if not key_re.match(key) or key not in allowed_keys:
            raise ValueError(f"unsupported configuration key {key!r} at line {idx}")
        val, is_default = decode_value(v_raw, key, idx)
        mode = "DEFAULT" if is_default else "SET"
        encoded_val = base64.b64encode(val.encode("utf-8")).decode("ascii")
        sys.stdout.write(f"{mode}:{key}:{encoded_val}\n")
except Exception as exc:
    sys.stderr.write(str(exc) + "\n")
    sys.exit(4)
PY
)"; then
            LAST_LOG_ERROR="Invalid configuration syntax in ${conf_path}"
            echo "[FATAL] ${LAST_LOG_ERROR}"
            exit 4
        fi
        local rec mode key encoded_val val rest
        while IFS= read -r rec; do
            [[ -n "${rec}" ]] || continue
            mode="${rec%%:*}"
            rest="${rec#*:}"
            key="${rest%%:*}"
            encoded_val="${rest#*:}"
            val="$(python3 -c 'import base64, sys; sys.stdout.write(base64.b64decode(sys.argv[1]).decode("utf-8"))' "${encoded_val}")"
            if [[ "${mode}" == "DEFAULT" ]]; then
                if [[ -z "${!key:-}" ]]; then
                    printf -v "${key}" '%s' "${val}"
                fi
            else
                printf -v "${key}" '%s' "${val}"
            fi
        done <<< "${parsed_records}"
        return 0
    fi

    LAST_LOG_ERROR="python3 is required to safely parse ${conf_path}"
    echo "[FATAL] ${LAST_LOG_ERROR}"
    exit 4
}

# ── Load Configuration ───────────────────────────────────────────────────────
if [[ -n "${CLI_CONF_OVERRIDE}" ]]; then
    CONF_FILE="${CLI_CONF_OVERRIDE}"
elif [[ -n "${EFFECTIVE_RELEASE_ROOT}" && -f "${EFFECTIVE_RELEASE_ROOT}/opt/AetherFlow/deploy/release-manager.conf" ]]; then
    CONF_FILE="${EFFECTIVE_RELEASE_ROOT}/opt/AetherFlow/deploy/release-manager.conf"
else
    CONF_FILE="${SCRIPT_DIR}/release-manager.conf"
fi

if [[ -f "${CONF_FILE}" && ! -L "${CONF_FILE}" ]]; then
    load_conf_file_safely "${CONF_FILE}"
elif [[ -n "${CLI_CONF_OVERRIDE}" || -z "${EFFECTIVE_RELEASE_ROOT}" ]]; then
    LAST_LOG_ERROR="Configuration file not found or invalid: ${CONF_FILE}"
    echo "[FATAL] ${LAST_LOG_ERROR}"
    exit 4
fi

: "${SQLITE_DB:=aetherflow.sqlite}"
: "${SNAPSHOT_TIMEOUT:=10}"
: "${MAX_RELEASES:=5}"
: "${HEALTH_RETRIES:=15}"
: "${HEALTH_INTERVAL:=2}"
# Default to the public deep readiness gate. Explicit HEALTH_ENDPOINT overrides
# are preserved; any override used for deployment must report full application
# readiness to supply an equivalent release gate.
: "${HEALTH_ENDPOINT:=http://127.0.0.1:8080/health/ready}"
if [[ -z "${ARTIFACT_NAME:-}" ]]; then
    if [[ -n "${RELEASE_ASSET_NAME:-}" ]]; then
        ARTIFACT_NAME="${RELEASE_ASSET_NAME}"
    else
        case "$(uname -m 2>/dev/null || echo x86_64)" in
            x86_64|amd64) _af_default_arch="amd64" ;;
            aarch64|arm64) _af_default_arch="arm64" ;;
            armv7*|armhf) _af_default_arch="armv7" ;;
            *) _af_default_arch="amd64" ;;
        esac
        ARTIFACT_NAME="aetherflow-linux-${_af_default_arch}.tar.gz"
        unset _af_default_arch
    fi
fi
: "${CHECKSUM_NAME:=SHA256SUMS}"
: "${GITHUB_REPO:=McEveritts/AetherFlow}"

validate_path_within_isolated_root() {
    local var_name="$1"
    local candidate="$2"
    [[ -n "${EFFECTIVE_RELEASE_ROOT}" ]] || return 0
    if [[ -z "${candidate}" || "${candidate}" != /* || "${candidate}" == *".."* ]]; then
        LAST_LOG_ERROR="Configured ${var_name}=${candidate} must be a normalized absolute path without '..' under ${EFFECTIVE_RELEASE_ROOT}"
        echo "[FATAL] ${LAST_LOG_ERROR}"
        exit 4
    fi
    if [[ "${candidate}" != "${EFFECTIVE_RELEASE_ROOT}" && "${candidate}" != "${EFFECTIVE_RELEASE_ROOT}/"* ]]; then
        LAST_LOG_ERROR="Configured ${var_name}=${candidate} escapes isolated release root ${EFFECTIVE_RELEASE_ROOT}"
        echo "[FATAL] ${LAST_LOG_ERROR}"
        exit 4
    fi
}

if [[ -n "${EFFECTIVE_RELEASE_ROOT}" ]]; then
    : "${CLI_BIN_DIR:=${EFFECTIVE_RELEASE_ROOT}/usr/local/bin}"
    for _root_check_var in RELEASES_DIR CURRENT_LINK REPO_DIR LEGACY_OPT_ROOT DRY_RUN_ROOT LOG_FILE DATA_DIR ENV_DIR ENV_FILE SYSTEMD_UNITS_DST CLI_BIN_DIR; do
        validate_path_within_isolated_root "${_root_check_var}" "${!_root_check_var:-}"
    done
fi

# ── Parse CLI Arguments ──────────────────────────────────────────────────────
COMMAND="deploy"
if [[ $# -gt 0 && "$1" != -* ]]; then
    COMMAND="$1"
    shift || true
fi

DRY_RUN=false
FROM_SOURCE=false
OFFLINE=false
CHANNEL="${RELEASE_CHANNEL:-stable}"

case "${AF_OFFLINE:-}" in
    1|true|TRUE|yes|YES) OFFLINE=true ;;
esac

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --offline)
            OFFLINE=true
            shift
            ;;
        --from-source)
            FROM_SOURCE=true
            shift
            ;;
        --channel)
            CHANNEL="${2:-stable}"
            shift 2
            ;;
        --root|--config|--job-status-file|--job-unit)
            shift 2 || shift
            ;;
        deploy|rollback|cleanup|migrate-systemd)
            COMMAND="$1"
            shift
            ;;
        stable|nightly|experimental)
            CHANNEL="$1"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

case "${CHANNEL}" in
    experimental) CHANNEL="nightly" ;;
    stable|nightly) ;;
    *) printf 'Unsupported release channel: %s (expected stable or nightly)\n' "${CHANNEL}" >&2; exit 2 ;;
esac

verify_isolated_systemd_lifecycle_authorized() {
    [[ -n "${EFFECTIVE_RELEASE_ROOT}" && "${EFFECTIVE_RELEASE_ROOT}" != "/" ]] || return 0
    [[ "${DRY_RUN}" == false ]] || return 0
    if [[ "${AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE:-}" != "1" ]]; then
        LAST_LOG_ERROR="Refusing live systemd/PM2 lifecycle mutation under isolated root ${EFFECTIVE_RELEASE_ROOT} without AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE=1 and /etc/aetherflow-disposable-guest; pass --dry-run on non-disposable hosts."
        echo "[FATAL] ${LAST_LOG_ERROR}"
        exit 4
    fi
    if [[ ! -f "/etc/aetherflow-disposable-guest" || -L "/etc/aetherflow-disposable-guest" ]]; then
        LAST_LOG_ERROR="Refusing live systemd/PM2 lifecycle mutation under isolated root ${EFFECTIVE_RELEASE_ROOT}: missing regular file /etc/aetherflow-disposable-guest."
        echo "[FATAL] ${LAST_LOG_ERROR}"
        exit 4
    fi
}

case "${COMMAND}" in
    deploy|rollback|migrate-systemd)
        verify_isolated_systemd_lifecycle_authorized
        ;;
esac

# Captured before the dry-run rewrite so resolution still sees the host layout.
CONFIG_ENV_FILE="${ENV_FILE}"
CONFIG_DATA_DIR="${DATA_DIR}"
LEGACY_OPT_ROOT="${LEGACY_OPT_ROOT:-/opt/AetherFlow}"
LEGACY_BIN_ROOT="${LEGACY_BIN_ROOT:-/usr/local/bin/AetherFlow}"
DRY_RUN_ROOT="${DRY_RUN_ROOT:-/tmp/aetherflow-dryrun}"
RESOLVED_DB_PATH=""
RESOLVED_DB_SOURCE=""

# ── Dry-Run Override ─────────────────────────────────────────────────────────
# Writes stay under DRY_RUN_ROOT. CONFIG_ENV_FILE / CONFIG_DATA_DIR stay put
# so the live database can be resolved and copied with sqlite3 .backup.
if [[ "${DRY_RUN}" == true ]]; then
    RELEASES_DIR="${DRY_RUN_ROOT}/releases"
    CURRENT_LINK="${DRY_RUN_ROOT}/current"
    REPO_DIR="${DRY_RUN_ROOT}/repo"
    DATA_DIR="${DRY_RUN_ROOT}/data"
    ENV_DIR="${DRY_RUN_ROOT}/etc"
    ENV_FILE="${DRY_RUN_ROOT}/etc/aetherflow.env"
    LOG_FILE="${DRY_RUN_ROOT}/deploy.log"
    CLI_BIN_DIR="${DRY_RUN_ROOT}/usr/local/bin"
    mkdir -p "${REPO_DIR}" "${DATA_DIR}" "${ENV_DIR}"
fi

# ── Logging ──────────────────────────────────────────────────────────────────
if [[ "${LOG_FILE}" != "/dev/null" ]]; then
    _log_parent="$(dirname "${LOG_FILE}")"
    if [[ -L "${_log_parent}" || -L "${LOG_FILE}" || ( -e "${LOG_FILE}" && ! -f "${LOG_FILE}" ) ]]; then
        echo "[FATAL] Refusing unsafe or symlinked LOG_FILE path: ${LOG_FILE}" >&2
        exit 4
    fi
    mkdir -p "${_log_parent}"
fi

json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '%s' "${s}"
}

append_log_line_locked() {
    local line="$1"
    [[ "${LOG_FILE}" != "/dev/null" ]] || return 0
    if command -v python3 >/dev/null 2>&1; then
        python3 - "${LOG_FILE}" "${line}" <<'PY' || return 1
import fcntl, os, stat, sys

target, line = sys.argv[1], sys.argv[2]
parent = os.path.dirname(target) or "."
pst = os.lstat(parent)
if stat.S_ISLNK(pst.st_mode) or not stat.S_ISDIR(pst.st_mode):
    raise SystemExit(1)
flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(target, flags, 0o640)
try:
    fcntl.flock(fd, fcntl.LOCK_SH)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise SystemExit(1)
        data = (line + "\n").encode("utf-8", errors="replace")
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
finally:
    os.close(fd)
PY
        return 0
    fi
    if [[ -L "${LOG_FILE}" ]]; then
        return 1
    fi
    printf '%s\n' "${line}" >> "${LOG_FILE}"
}

log() {
    local level="$1"
    shift
    local msg="$*"
    local ts esc_level esc_msg
    ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    esc_level="$(json_escape "${level}")"
    esc_msg="$(json_escape "${msg}")"
    local line="{\"ts\":\"${ts}\",\"level\":\"${esc_level}\",\"msg\":\"${esc_msg}\"}"
    printf '%s\n' "${line}"
    append_log_line_locked "${line}" || true
}

log_info()  { log "INFO"  "$@"; }
log_warn()  { log "WARN"  "$@"; }
log_error() { LAST_LOG_ERROR="$*"; log "ERROR" "$@"; }
log_fatal() { LAST_LOG_ERROR="$*"; log "FATAL" "$@"; exit 4; }

EPOCH="$(date +%s)"
RELEASE_DIR="${RELEASES_DIR}/${EPOCH}"

###############################################################################
# Database path resolution
###############################################################################
# Last non-empty assignment wins. Comments and blank lines are ignored.
# The file is parsed; it is never sourced.
read_env_file_value() {
    local file="$1"
    local key="$2"
    [[ -f "${file}" ]] || return 1

    if command -v python3 >/dev/null 2>&1; then
        python3 - "${file}" "${key}" <<'PY'
import sys

path, target_key = sys.argv[1], sys.argv[2]
prefix = target_key + "="
found = ""

def decode_val(raw):
    s = raw.strip()
    if len(s) >= 2 and s[0] == "'" and s[-1] == "'":
        return s[1:-1]
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        inner = s[1:-1]
        out = []
        idx = 0
        while idx < len(inner):
            ch = inner[idx]
            if ch == "\\" and idx + 1 < len(inner):
                idx += 1
                esc = inner[idx]
                if esc == "n":
                    out.append("\n")
                elif esc == "r":
                    out.append("\r")
                elif esc == "t":
                    out.append("\t")
                elif esc in ('"', "\\", "$", "`"):
                    out.append(esc)
                else:
                    out.append("\\")
                    out.append(esc)
            else:
                out.append(ch)
            idx += 1
        return "".join(out)
    return s

try:
    with open(path, "r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.rstrip("\r\n").lstrip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export") and len(line) > 6 and line[6].isspace():
                line = line[6:].lstrip()
            if not line.startswith(prefix):
                continue
            val = decode_val(line[len(prefix):])
            if val:
                found = val
except Exception:
    sys.exit(1)

if not found:
    sys.exit(1)
sys.stdout.write(found)
PY
        return
    fi

    local line body val found=""
    while IFS= read -r line || [[ -n "${line}" ]]; do
        line="${line%$'\r'}"
        line="${line#"${line%%[![:space:]]*}"}"
        [[ -z "${line}" || "${line}" == \#* ]] && continue
        body="${line}"
        if [[ "${body}" == export[[:space:]]* ]]; then
            body="${body#export}"
            body="${body#"${body%%[![:space:]]*}"}"
        fi
        [[ "${body}" == "${key}="* ]] || continue
        val="${body#"${key}="}"
        if [[ "${val}" == \"*\" ]]; then
            val="${val#\"}"
            val="${val%\"}"
        elif [[ "${val}" == \'*\' ]]; then
            val="${val#\'}"
            val="${val%\'}"
        fi
        [[ -n "${val}" ]] && found="${val}"
    done < "${file}"

    [[ -n "${found}" ]] || return 1
    printf '%s' "${found}"
}

# `systemctl show -p Environment` prints one or more `Environment=K=V K2=V2`
# lines. Values may be quoted. Missing systemctl or a missing unit yields nothing.
read_systemd_environment_value() {
    local key="$1"
    local blob="$2"
    [[ -n "${blob}" ]] || return 1

    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "${blob}" | python3 -c '
import shlex, sys
key = sys.argv[1]
chunks = []
for line in sys.stdin.read().splitlines():
    line = line.strip()
    if line.startswith("Environment="):
        line = line[len("Environment="):]
    chunks.append(line)
text = " ".join(chunks).strip()
if not text:
    sys.exit(1)
try:
    tokens = shlex.split(text, posix=True)
except ValueError:
    sys.exit(1)
found = ""
for token in tokens:
    if "=" not in token:
        continue
    name, value = token.split("=", 1)
    if name == key and value:
        found = value
if not found:
    sys.exit(1)
sys.stdout.write(found)
' "${key}"
        return
    fi

    local token name value found=""
    local payload="${blob//$'\n'/ }"
    payload="${payload#Environment=}"
    # shellcheck disable=SC2086
    for token in ${payload}; do
        [[ "${token}" == *=* ]] || continue
        name="${token%%=*}"
        value="${token#*=}"
        value="${value%\"}"
        value="${value#\"}"
        if [[ "${name}" == "${key}" && -n "${value}" ]]; then
            found="${value}"
        fi
    done
    [[ -n "${found}" ]] || return 1
    printf '%s' "${found}"
}

resolve_db_path_quiet() {
    RESOLVED_DB_PATH=""
    RESOLVED_DB_SOURCE=""

    local env_af="${AF_DB_PATH:-}"
    local env_db="${DB_PATH:-}"
    local env_alias="${AETHERFLOW_DB_PATH:-}"

    if [[ -n "${env_af}" && -n "${env_db}" && "${env_af%/}" != "${env_db%/}" ]]; then
        log_fatal "Conflicting database path environment overrides: AF_DB_PATH=${env_af} vs DB_PATH=${env_db}"
    fi
    if [[ -n "${env_af}" && -n "${env_alias}" && "${env_af%/}" != "${env_alias%/}" ]]; then
        log_fatal "Conflicting database path environment overrides: AF_DB_PATH=${env_af} vs AETHERFLOW_DB_PATH=${env_alias}"
    fi
    if [[ -n "${env_db}" && -n "${env_alias}" && "${env_db%/}" != "${env_alias%/}" ]]; then
        log_fatal "Conflicting database path environment overrides: DB_PATH=${env_db} vs AETHERFLOW_DB_PATH=${env_alias}"
    fi

    if [[ -n "${env_af}" ]]; then
        RESOLVED_DB_PATH="${env_af}"
        RESOLVED_DB_SOURCE="AF_DB_PATH"
    elif [[ -n "${env_db}" ]]; then
        RESOLVED_DB_PATH="${env_db}"
        RESOLVED_DB_SOURCE="DB_PATH"
    elif [[ -n "${env_alias}" ]]; then
        RESOLVED_DB_PATH="${env_alias}"
        RESOLVED_DB_SOURCE="AETHERFLOW_DB_PATH"
    else
        local file_af="" file_db="" file_alias=""
        file_af="$(read_env_file_value "${CONFIG_ENV_FILE}" "AF_DB_PATH" || true)"
        file_db="$(read_env_file_value "${CONFIG_ENV_FILE}" "DB_PATH" || true)"
        file_alias="$(read_env_file_value "${CONFIG_ENV_FILE}" "AETHERFLOW_DB_PATH" || true)"

        if [[ -n "${EFFECTIVE_RELEASE_ROOT}" ]]; then
            if [[ -n "${file_af}" && -n "${file_db}" && "${file_af%/}" != "${file_db%/}" ]]; then
                log_fatal "Conflicting database path entries in ${CONFIG_ENV_FILE}: AF_DB_PATH=${file_af} vs DB_PATH=${file_db}"
            fi
            if [[ -n "${file_af}" && -n "${file_alias}" && "${file_af%/}" != "${file_alias%/}" ]]; then
                log_fatal "Conflicting database path entries in ${CONFIG_ENV_FILE}: AF_DB_PATH=${file_af} vs AETHERFLOW_DB_PATH=${file_alias}"
            fi
            if [[ -n "${file_db}" && -n "${file_alias}" && "${file_db%/}" != "${file_alias%/}" ]]; then
                log_fatal "Conflicting database path entries in ${CONFIG_ENV_FILE}: DB_PATH=${file_db} vs AETHERFLOW_DB_PATH=${file_alias}"
            fi
        fi

        if [[ -n "${file_af}" ]]; then
            RESOLVED_DB_PATH="${file_af}"
            RESOLVED_DB_SOURCE="env-file:${CONFIG_ENV_FILE}:AF_DB_PATH"
        elif [[ -n "${file_db}" ]]; then
            RESOLVED_DB_PATH="${file_db}"
            RESOLVED_DB_SOURCE="env-file:${CONFIG_ENV_FILE}:DB_PATH"
        elif [[ -n "${file_alias}" ]]; then
            RESOLVED_DB_PATH="${file_alias}"
            RESOLVED_DB_SOURCE="env-file:${CONFIG_ENV_FILE}:AETHERFLOW_DB_PATH"
        elif [[ -z "${EFFECTIVE_RELEASE_ROOT}" ]]; then
            local unit_blob="" val=""
            if command -v systemctl >/dev/null 2>&1; then
                unit_blob="$(systemctl show -p Environment aetherflow-api 2>/dev/null || true)"
            fi
            if [[ -n "${unit_blob}" ]] && val="$(read_systemd_environment_value "DB_PATH" "${unit_blob}")"; then
                RESOLVED_DB_PATH="${val}"
                RESOLVED_DB_SOURCE="systemd:aetherflow-api:DB_PATH"
            elif [[ -n "${unit_blob}" ]] && val="$(read_systemd_environment_value "AETHERFLOW_DB_PATH" "${unit_blob}")"; then
                RESOLVED_DB_PATH="${val}"
                RESOLVED_DB_SOURCE="systemd:aetherflow-api:AETHERFLOW_DB_PATH"
            fi
        fi
    fi

    if [[ -z "${RESOLVED_DB_PATH}" ]]; then
        RESOLVED_DB_PATH="${CONFIG_DATA_DIR}/${SQLITE_DB}"
        RESOLVED_DB_SOURCE="DATA_DIR"
    fi

    if [[ "${RESOLVED_DB_PATH}" == *".."* ]]; then
        log_fatal "Resolved database path must not contain '..': ${RESOLVED_DB_PATH}"
    fi
    validate_path_within_isolated_root "RESOLVED_DB_PATH (${RESOLVED_DB_SOURCE})" "${RESOLVED_DB_PATH}"
}

resolve_db_path() {
    resolve_db_path_quiet
    log_info "Resolved database path: ${RESOLVED_DB_PATH} (source: ${RESOLVED_DB_SOURCE})"
}

sqlite_online_backup() {
    local src="$1"
    local dest="$2"
    local dest_dir escaped
    dest_dir="$(dirname "${dest}")"
    mkdir -p "${dest_dir}"
    escaped="${dest//\'/\'\'}"
    # --readonly: .backup reads the source and writes only dest. Opening a hot
    # WAL read-write would checkpoint it, which a dry-run must not do.
    sqlite3 --readonly "${src}" ".backup '${escaped}'"
}

sqlite_integrity() {
    local db="$1"
    local result=""
    if ! python3 - "${db}" <<'PY'
import os
import stat
import sys

descriptor = os.open(sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
with os.fdopen(descriptor, "rb") as database:
    if not stat.S_ISREG(os.fstat(database.fileno()).st_mode) or database.read(16) != b"SQLite format 3\x00":
        raise SystemExit(1)
PY
    then
        printf 'error'
        return 0
    fi
    # Do not pipe through head: pipefail plus SIGPIPE makes a good check look failed.
    result="$(sqlite3 -readonly "${db}" "PRAGMA integrity_check;" 2>/dev/null || true)"
    result="${result%%$'\n'*}"
    result="$(printf '%s' "${result}" | tr -d '[:space:]')"
    printf '%s' "${result:-error}"
}

###############################################################################
# STAGE 0: FHS State & Secret Migration
###############################################################################
ensure_fhs_layout() {
    log_info "=== STAGE 0: Verifying FHS State & Secret Layout ==="
    mkdir -p "${RELEASES_DIR}" "${DATA_DIR}" "${ENV_DIR}"

    if [[ "${DRY_RUN}" == false ]]; then
        if id -u aetherflow &>/dev/null; then
            chown -R aetherflow:aetherflow "${DATA_DIR}"
            chmod 0700 "${DATA_DIR}"
            if [[ "${EUID:-$(id -u)}" -eq 0 && -z "${EFFECTIVE_RELEASE_ROOT:-}" ]]; then
                local host_dir
                for host_dir in /var/log/aetherflow /run/aetherflow; do
                    if [[ -L "${host_dir}" ]]; then
                        log_fatal "Refusing symlinked host directory: ${host_dir}"
                    fi
                    mkdir -p "${host_dir}"
                    chown root:aetherflow "${host_dir}"
                    chmod 0750 "${host_dir}"
                done
                if [[ -L /install ]]; then
                    log_fatal "Refusing symlinked host directory: /install"
                fi
                install -d -m 0750 -o root -g aetherflow /install
            fi
        elif [[ "${EUID:-$(id -u)}" -eq 0 && -z "${EFFECTIVE_RELEASE_ROOT:-}" ]]; then
            if [[ -L /install ]]; then
                log_fatal "Refusing symlinked host directory: /install"
            fi
            install -d -m 0750 -o root -g root /install
        fi
    fi

    resolve_db_path

    # Resolve any confined v3 release slot symlink (e.g. /opt/AetherFlow/current -> releases/v3.x.y)
    # so upgrades from slot-based v3 layouts also migrate backend/data/aetherflow.sqlite and backend/.env.
    local -a legacy_slot_roots=()
    local slot_candidate resolved_slot canonical_releases_dir canonical_repo_dir canonical_leg_root
    canonical_releases_dir="$(readlink -f "${RELEASES_DIR:-}" 2>/dev/null || true)"
    canonical_repo_dir="$(readlink -f "${REPO_DIR:-}" 2>/dev/null || true)"
    canonical_leg_root="$(readlink -f "${LEGACY_OPT_ROOT:-}" 2>/dev/null || true)"
    for slot_candidate in "${CURRENT_LINK:-}" "${REPO_DIR:-}/current" "${LEGACY_OPT_ROOT:-}/current"; do
        [[ -n "${slot_candidate}" && -e "${slot_candidate}" ]] || continue
        resolved_slot="$(readlink -f "${slot_candidate}" 2>/dev/null || true)"
        [[ -n "${resolved_slot}" && -d "${resolved_slot}" ]] || continue
        if [[ ( -n "${canonical_releases_dir}" && "${resolved_slot}" == "${canonical_releases_dir}/"* ) || \
              ( -n "${canonical_repo_dir}" && "${resolved_slot}" == "${canonical_repo_dir}/"* ) || \
              ( -n "${canonical_leg_root}" && "${resolved_slot}" == "${canonical_leg_root}/"* ) ]]; then
            legacy_slot_roots+=("${resolved_slot}")
        fi
    done

    # Only migrate a legacy DB when the resolved live path IS the FHS file and
    # that file is missing. Copying into DATA_DIR while the process uses another
    # path creates a divergent stale database (this host's /var/lib copy).
    local fhs_db="${CONFIG_DATA_DIR}/${SQLITE_DB}"
    if [[ "${RESOLVED_DB_PATH}" == "${fhs_db}" && ! -f "${fhs_db}" ]]; then
        local -a legacy_db_candidates=(
            "${LEGACY_OPT_ROOT}/backend/data/${SQLITE_DB}"
            "${LEGACY_OPT_ROOT}/backend/${SQLITE_DB}"
        )
        if [[ ${#legacy_slot_roots[@]} -gt 0 ]]; then
            local slot_root
            for slot_root in "${legacy_slot_roots[@]}"; do
                legacy_db_candidates+=(
                    "${slot_root}/backend/data/${SQLITE_DB}"
                    "${slot_root}/backend/${SQLITE_DB}"
                )
            done
        fi
        local legacy_db
        for legacy_db in "${legacy_db_candidates[@]}"; do
            if [[ -f "${legacy_db}" && ! -L "${legacy_db}" ]]; then
                if [[ "${DRY_RUN}" == true ]]; then
                    log_info "[DRY-RUN] Would migrate legacy SQLite database from ${legacy_db} to ${fhs_db}; dry-run does not write outside ${DRY_RUN_ROOT}."
                    break
                fi
                log_info "Migrating legacy SQLite database from ${legacy_db} to ${fhs_db}..."
                mkdir -p "$(dirname "${fhs_db}")"
                if command -v sqlite3 >/dev/null 2>&1; then
                    sqlite_online_backup "${legacy_db}" "${fhs_db}"
                else
                    cp -pf "${legacy_db}" "${fhs_db}"
                fi
                if id -u aetherflow &>/dev/null; then
                    chown aetherflow:aetherflow "${fhs_db}"
                    chmod 0600 "${fhs_db}"
                fi
                break
            fi
        done
    elif [[ "${RESOLVED_DB_PATH}" != "${fhs_db}" ]]; then
        log_info "Skipping legacy database copy into ${fhs_db}; live database is ${RESOLVED_DB_PATH} (source: ${RESOLVED_DB_SOURCE})."
    fi

    # Migrate legacy .env only on a real deploy. Dry-run must not copy secrets.
    if [[ "${DRY_RUN}" == false && ! -f "${CONFIG_ENV_FILE}" ]]; then
        local -a legacy_env_candidates=(
            "${LEGACY_OPT_ROOT}/backend/.env"
            "${LEGACY_OPT_ROOT}/.env"
        )
        if [[ ${#legacy_slot_roots[@]} -gt 0 ]]; then
            local slot_root_env
            for slot_root_env in "${legacy_slot_roots[@]}"; do
                legacy_env_candidates+=(
                    "${slot_root_env}/backend/.env"
                    "${slot_root_env}/.env"
                )
            done
        fi
        local legacy_env
        for legacy_env in "${legacy_env_candidates[@]}"; do
            if [[ -f "${legacy_env}" && ! -L "${legacy_env}" ]]; then
                log_info "Migrating legacy environment secrets from ${legacy_env} to ${CONFIG_ENV_FILE}..."
                mkdir -p "$(dirname "${CONFIG_ENV_FILE}")"
                cp -pf "${legacy_env}" "${CONFIG_ENV_FILE}"
                chmod 0600 "${CONFIG_ENV_FILE}"
                break
            fi
        done
    fi
}

###############################################################################
# STAGE 1: Release Scaffold (Pull Pre-Built Signed Artifact or Source Fallback)
###############################################################################
is_v4_or_newer_release_tag() {
    local tag="${1:-}"
    [[ "${tag}" =~ ^v([4-9]|[1-9][0-9]+)\.[0-9]+\.[0-9]+(-[A-Za-z0-9]+([._-][A-Za-z0-9]+)*)?$ ]]
}

resolve_github_token_for_url() {
    local url="$1"
    [[ "${url}" == https://api.github.com/* || "${url}" == https://github.com/* ]] || return 1
    local tok="${AF_GITHUB_TOKEN:-${GITHUB_TOKEN:-${GH_TOKEN:-}}}"
    [[ -n "${tok}" ]] || return 1
    printf '%s' "${tok}"
}

github_https_curl() {
    local max_bytes="$1"
    local url="${!#}"
    shift
    local -a extra_args=("$@")
    local hdr_file=""
    local gh_tok=""
    if gh_tok="$(resolve_github_token_for_url "${url}" 2>/dev/null)"; then
        hdr_file="$(umask 0077; mktemp "${TMPDIR:-/tmp}/af-curl-hdr.XXXXXX")" || hdr_file=""
        if [[ -n "${hdr_file}" ]]; then
            printf 'Authorization: Bearer %s\n' "${gh_tok}" > "${hdr_file}"
            extra_args=(-H "@${hdr_file}" "${extra_args[@]}")
        fi
    fi
    local rc=0
    curl --proto '=https' --proto-redir '=https' --max-filesize "${max_bytes}" "${extra_args[@]}" || rc=$?
    [[ -n "${hdr_file}" ]] && rm -f "${hdr_file}"
    return "${rc}"
}

resolve_release_tag() {
    local channel="$1"
    local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases"
    local releases_json
    releases_json="$(github_https_curl 16777216 -sfL --max-time 15 "${api_url}" 2>/dev/null)" || true

    if [[ "${channel}" == "nightly" ]]; then
        if [[ -n "${releases_json}" ]] && command -v python3 &>/dev/null; then
            local nightly_tag=""
            nightly_tag="$(printf '%s' "${releases_json}" | python3 -I -c '
import json, re, sys
nightly_re = re.compile(r"^v([4-9]|[1-9][0-9]+)\.[0-9]+\.[0-9]+-[Nn]ightly\.[0-9]+(?:\.[0-9]+)?$")
try:
    for r in json.load(sys.stdin):
        if not isinstance(r, dict) or r.get("draft"):
            continue
        tag = (r.get("tag_name") or "").strip()
        target = (r.get("target_commitish") or "").strip().lower()
        if (
            nightly_re.fullmatch(tag)
            and target != "experimental"
            and (bool(r.get("prerelease")) or target == "nightly")
        ):
            print(tag)
            break
except Exception:
    pass
' 2>/dev/null)"
            if [[ -n "${nightly_tag}" ]] && is_v4_or_newer_release_tag "${nightly_tag}"; then
                printf '%s\n' "${nightly_tag}"
                return 0
            fi
        fi
        return 1
    fi

    if [[ -z "${releases_json}" ]]; then
        local latest_url latest_tag
        latest_url="$(github_https_curl 1048576 -fsSL --max-time 15 -o /dev/null -w '%{url_effective}' "https://github.com/${GITHUB_REPO}/releases/latest" 2>/dev/null)" || return 1
        latest_tag="${latest_url##*/}"
        [[ "${latest_url}" == "https://github.com/${GITHUB_REPO}/releases/tag/"* && "${latest_tag}" =~ ^v([4-9]|[1-9][0-9]+)\.[0-9]+\.[0-9]+$ ]] || return 1
        printf '%s\n' "${latest_tag}"
        return 0
    fi

    if command -v python3 &>/dev/null; then
        local stable_tag=""
        stable_tag="$(printf '%s' "${releases_json}" | python3 -I -c '
import json, re, sys
tag_re = re.compile(r"^v([4-9]|[1-9][0-9]+)\.[0-9]+\.[0-9]+$")
try:
    for r in json.load(sys.stdin):
        if not isinstance(r, dict) or r.get("draft") or r.get("prerelease"):
            continue
        tag = (r.get("tag_name") or "").strip()
        target = (r.get("target_commitish") or "").strip().lower()
        if tag_re.fullmatch(tag) and target not in ("nightly", "experimental"):
            print(tag)
            break
except Exception:
    pass
' 2>/dev/null)"
        if [[ -n "${stable_tag}" ]]; then
            printf '%s\n' "${stable_tag}"
            return 0
        fi
        return 1
    fi

    # Fallback: first v4+ release without a pre-release hyphen in tag_name
    local fallback_tag=""
    fallback_tag="$(printf '%s\n' "${releases_json}" | grep -o '"tag_name"\s*:\s*"[^"]*"' | cut -d'"' -f4 | grep -E '^v([4-9]|[1-9][0-9]+)\.[0-9]+\.[0-9]+$' | head -1 || true)"
    [[ -n "${fallback_tag}" ]] || return 1
    printf '%s\n' "${fallback_tag}"
}

validate_release_tarball() {
    local archive_path="$1"
    if command -v python3 >/dev/null 2>&1; then
        if ! python3 - "${archive_path}" <<'PY'
import pathlib, sys, tarfile

archive = sys.argv[1]
try:
    with tarfile.open(archive, "r:*") as tf:
        for member in tf.getmembers():
            name = member.name or ""
            if not (member.isfile() or member.isdir()):
                sys.stderr.write(f"Rejected non-regular/non-directory tar entry: {name} (type={member.type!r})\n")
                sys.exit(1)
            if name.startswith("/") or name.startswith("\\"):
                sys.stderr.write(f"Rejected absolute tar entry path: {name}\n")
                sys.exit(1)
            parts = pathlib.PurePosixPath(name).parts
            if ".." in parts:
                sys.stderr.write(f"Rejected path-traversal tar entry: {name}\n")
                sys.exit(1)
except SystemExit:
    raise
except Exception as exc:
    sys.stderr.write(f"Invalid tar archive {archive}: {exc}\n")
    sys.exit(1)
PY
        then
            log_error "Archive security validation failed for ${archive_path} (links, special entries, or path traversal detected)."
            return 1
        fi
        return 0
    fi

    # Fallback inspection using tar -ztvf if python3 is unavailable
    local listing
    listing="$(tar -ztvf "${archive_path}" 2>/dev/null)" || {
        log_error "Failed to inspect archive ${archive_path}."
        return 1
    }
    if printf '%s\n' "${listing}" | awk '
        substr($1, 1, 1) !~ /^[-d]$/ { exit 1 }
        $NF ~ /^\// || $NF ~ /(^|\/)\.\.(\/|$)/ { exit 1 }
    '; then
        return 0
    fi
    log_error "Archive security validation failed for ${archive_path} (links, special entries, or path traversal detected)."
    return 1
}

stage_running_release_manager() {
    if [[ -L "${RELEASE_DIR}" || -L "${RELEASE_DIR}/deploy" ]]; then
        log_error "Refusing to stage release-manager into symlinked deploy path under ${RELEASE_DIR}."
        return 1
    fi
    mkdir -p "${RELEASE_DIR}/deploy"
    if [[ -L "${RELEASE_DIR}/deploy/release-manager.sh" || -L "${RELEASE_DIR}/deploy/release-manager.conf" || -L "${RELEASE_DIR}/deploy/verify-provenance.py" || -L "${RELEASE_DIR}/deploy/log-retention.py" ]]; then
        log_error "Refusing to overwrite symlink inside ${RELEASE_DIR}/deploy."
        return 1
    fi
    if [[ -f "${RELEASE_DIR}/deploy/release-manager.sh" ]]; then
        chmod 0755 "${RELEASE_DIR}/deploy/release-manager.sh"
    elif [[ -f "${SCRIPT_DIR}/release-manager.sh" ]]; then
        cp -f "${SCRIPT_DIR}/release-manager.sh" "${RELEASE_DIR}/deploy/release-manager.sh"
        chmod 0755 "${RELEASE_DIR}/deploy/release-manager.sh"
        log_info "Backfilled missing release-manager.sh into ${RELEASE_DIR}/deploy."
    fi
    if [[ -f "${RELEASE_DIR}/deploy/verify-provenance.py" ]]; then
        chmod 0755 "${RELEASE_DIR}/deploy/verify-provenance.py"
    elif [[ -f "${SCRIPT_DIR}/verify-provenance.py" ]]; then
        cp -f "${SCRIPT_DIR}/verify-provenance.py" "${RELEASE_DIR}/deploy/verify-provenance.py"
        chmod 0755 "${RELEASE_DIR}/deploy/verify-provenance.py"
    fi
    if [[ -f "${RELEASE_DIR}/deploy/log-retention.py" ]]; then
        chmod 0755 "${RELEASE_DIR}/deploy/log-retention.py"
    elif [[ -f "${SCRIPT_DIR}/log-retention.py" ]]; then
        cp -f "${SCRIPT_DIR}/log-retention.py" "${RELEASE_DIR}/deploy/log-retention.py"
        chmod 0755 "${RELEASE_DIR}/deploy/log-retention.py"
    fi
    if [[ -f "${CONF_FILE}" ]]; then
        rm -f "${RELEASE_DIR}/deploy/release-manager.conf"
        cp -f "${CONF_FILE}" "${RELEASE_DIR}/deploy/release-manager.conf"
        chmod 0644 "${RELEASE_DIR}/deploy/release-manager.conf"
    fi
}

pull_prebuilt_artifact() {
    local tag="$1"
    if ! is_v4_or_newer_release_tag "${tag}"; then
        log_error "Refusing unsupported pre-v4 or malformed release tag '${tag}'."
        return 1
    fi
    local base_url="https://github.com/${GITHUB_REPO}/releases/download/${tag}"
    local tmp_dir
    tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/af-release-XXXXXX")" || return 1

    log_info "Downloading pre-built release ${tag} (${ARTIFACT_NAME})..."
    if ! github_https_curl 268435456 -fsSL --max-time 180 -o "${tmp_dir}/${ARTIFACT_NAME}" "${base_url}/${ARTIFACT_NAME}"; then
        rm -rf "${tmp_dir}"
        return 1
    fi

    log_info "Downloading SHA-256 manifest (${CHECKSUM_NAME})..."
    if ! github_https_curl 1048576 -fsSL --max-time 30 -o "${tmp_dir}/${CHECKSUM_NAME}" "${base_url}/${CHECKSUM_NAME}"; then
        log_error "Missing SHA256SUMS manifest for release ${tag}. Refusing unverified binary."
        rm -rf "${tmp_dir}"
        return 1
    fi

    log_info "Verifying cryptographic SHA-256 digest..."
    local expected_hash actual_hash
    expected_hash="$(awk -v f="${ARTIFACT_NAME}" '$2 == f || $2 == "*"f {print tolower($1); exit}' "${tmp_dir}/${CHECKSUM_NAME}")"
    actual_hash="$(sha256sum "${tmp_dir}/${ARTIFACT_NAME}" | awk '{print tolower($1)}')"
    if [[ -z "${expected_hash}" || "${#expected_hash}" -ne 64 || "${actual_hash}" != "${expected_hash}" ]]; then
        log_error "SHA-256 verification FAILED for ${ARTIFACT_NAME} (expected=${expected_hash:-missing}, actual=${actual_hash:-missing}). Aborting deployment."
        rm -rf "${tmp_dir}"
        return 1
    fi
    log_info "SHA-256 OK ${actual_hash}"

    if [[ "${AETHERFLOW_SKIP_PROVENANCE_VERIFY:-0}" != "1" ]]; then
        log_info "Verifying Sigstore + SLSA v1 GitHub Actions build provenance for ${tag}..."
        local -a prov_args=(
            --repo "${GITHUB_REPO}"
            --digest "${actual_hash}"
            --artifact-name "${ARTIFACT_NAME}"
            --tag "${tag}"
            --channel "${CHANNEL}"
        )
        local effective_bundle_file="${AETHERFLOW_PROVENANCE_BUNDLE_FILE:-}"
        if [[ -z "${effective_bundle_file}" ]]; then
            local candidate_bundle="${tmp_dir}/${ARTIFACT_NAME}.sigstore.json"
            if github_https_curl 8388608 -fsSL --max-time 30 -o "${candidate_bundle}" "${base_url}/${ARTIFACT_NAME}.sigstore.json" 2>/dev/null && [[ -s "${candidate_bundle}" ]]; then
                effective_bundle_file="${candidate_bundle}"
                log_info "Using release-attached Sigstore bundle (${ARTIFACT_NAME}.sigstore.json)."
            fi
        fi
        if [[ -n "${effective_bundle_file}" ]]; then
            prov_args+=(--bundle-file "${effective_bundle_file}")
        fi
        local prov_out=""
        if [[ ! -f "${SCRIPT_DIR}/verify-provenance.py" ]] || ! prov_out="$(python3 -I -B "${SCRIPT_DIR}/verify-provenance.py" "${prov_args[@]}" 2>&1)"; then
            [[ -n "${prov_out}" ]] && log_warn "Provenance verifier output: ${prov_out}"
            log_error "Sigstore build provenance verification FAILED for ${ARTIFACT_NAME} (${tag}). Refusing unverified binary."
            rm -rf "${tmp_dir}"
            return 1
        fi
        [[ -n "${prov_out}" ]] && log_info "Provenance verifier: ${prov_out}"
        log_info "Sigstore build provenance OK for ${tag}"
    else
        log_warn "AETHERFLOW_SKIP_PROVENANCE_VERIFY=1 is set; bypassing Sigstore build provenance verification for ${tag}."
    fi

    if ! validate_release_tarball "${tmp_dir}/${ARTIFACT_NAME}"; then
        rm -rf "${tmp_dir}"
        return 1
    fi

    log_info "SHA-256 checksum and archive structure verified. Extracting into ${RELEASE_DIR}..."
    # pull_prebuilt_artifact is called from an if, which disables set -e.
    if ! tar --no-same-owner --no-same-permissions --no-overwrite-dir -xzf "${tmp_dir}/${ARTIFACT_NAME}" -C "${RELEASE_DIR}"; then
        log_error "Failed to extract ${ARTIFACT_NAME}."
        rm -rf "${tmp_dir}"
        return 1
    fi
    if [[ -n "$(find "${RELEASE_DIR}" -type l -print -quit 2>/dev/null)" ]]; then
        log_error "Extracted release directory ${RELEASE_DIR} contains forbidden symbolic links. Aborting."
        rm -rf "${tmp_dir}" "${RELEASE_DIR}"
        return 1
    fi
    if [[ ! -f "${RELEASE_DIR}/aetherflow-api" || -L "${RELEASE_DIR}/aetherflow-api" ]]; then
        log_error "Release archive has no regular ./aetherflow-api binary. Refusing to continue."
        rm -rf "${tmp_dir}"
        return 1
    fi
    if [[ ! -f "${RELEASE_DIR}/web/dist/index.html" || ! -s "${RELEASE_DIR}/web/dist/index.html" ]] || [[ -z "$(find "${RELEASE_DIR}/web/dist" -type f -name '*.wasm' -size +0c -print -quit 2>/dev/null)" ]]; then
        log_error "Release archive is missing external frontend assets (web/dist/index.html and a non-empty .wasm file)."
        rm -rf "${tmp_dir}" "${RELEASE_DIR}"
        return 1
    fi
    if [[ ! -f "${RELEASE_DIR}/.version" || -L "${RELEASE_DIR}/.version" || ! -s "${RELEASE_DIR}/.version" ]]; then
        log_error "Release archive is missing a non-empty regular .version stamp. Refusing to continue."
        rm -rf "${tmp_dir}" "${RELEASE_DIR}"
        return 1
    fi
    local archive_version
    archive_version="$(tr -d '[:space:]' < "${RELEASE_DIR}/.version")"
    if [[ "${archive_version}" != "${tag}" ]]; then
        log_error "Release archive .version mismatch: expected '${tag}', got '${archive_version}'."
        rm -rf "${tmp_dir}" "${RELEASE_DIR}"
        return 1
    fi
    chmod +x "${RELEASE_DIR}/aetherflow-api"
    local companion_bin
    for companion_bin in af speedtest-backend; do
        if [[ -f "${RELEASE_DIR}/${companion_bin}" && ! -L "${RELEASE_DIR}/${companion_bin}" ]]; then
            chmod +x "${RELEASE_DIR}/${companion_bin}"
            mkdir -p "${RELEASE_DIR}/bin"
            if [[ ! -e "${RELEASE_DIR}/bin/${companion_bin}" && ! -L "${RELEASE_DIR}/bin/${companion_bin}" ]]; then
                cp -f "${RELEASE_DIR}/${companion_bin}" "${RELEASE_DIR}/bin/${companion_bin}"
            fi
            chmod +x "${RELEASE_DIR}/bin/${companion_bin}"
        elif [[ -f "${RELEASE_DIR}/bin/${companion_bin}" && ! -L "${RELEASE_DIR}/bin/${companion_bin}" ]]; then
            chmod +x "${RELEASE_DIR}/bin/${companion_bin}"
            rm -f "${RELEASE_DIR}/${companion_bin}"
            cp -f "${RELEASE_DIR}/bin/${companion_bin}" "${RELEASE_DIR}/${companion_bin}"
            chmod +x "${RELEASE_DIR}/${companion_bin}"
        fi
    done
    if ! stage_running_release_manager; then
        rm -rf "${tmp_dir}"
        return 1
    fi
    rm -rf "${tmp_dir}"
    return 0
}

build_from_source() {
    local target_branch="${GIT_BRANCH}"
    if [[ "${CHANNEL}" == "nightly" ]]; then
        target_branch="nightly"
    fi
    log_info "Building release from source (${GIT_REMOTE}/${target_branch})..."
    cd "${REPO_DIR}" || log_fatal "Repository directory not found: ${REPO_DIR}"
    if ! git fetch "${GIT_REMOTE}" "${target_branch}" --tags >> "${LOG_FILE}" 2>&1; then
        if [[ "${CHANNEL}" == "nightly" ]] && git fetch "${GIT_REMOTE}" "Nightly" --tags >> "${LOG_FILE}" 2>&1; then
            target_branch="Nightly"
        else
            log_error "Branch ${target_branch} not found on ${GIT_REMOTE}. Refusing implicit fallback to ${GIT_BRANCH}."
            return 1
        fi
    fi
    if ! git checkout -f "${GIT_REMOTE}/${target_branch}" >> "${LOG_FILE}" 2>&1; then
        log_error "git checkout failed for ${GIT_REMOTE}/${target_branch}."
        return 1
    fi
    local source_sha
    source_sha="$(git rev-parse --short=7 HEAD 2>/dev/null || echo 'unknown')"

    if ! rsync -a --exclude='.git' --exclude='node_modules' --exclude='.next' --exclude='data-snapshot' --exclude='*.sqlite' \
        --exclude='target/' --exclude='__pycache__/' --exclude='*.pyc' --exclude='*.pyo' \
        --exclude='.cache/' --exclude='.pytest_cache/' --exclude='.mypy_cache/' \
        --exclude='.ruff_cache/' --exclude='.tox/' --exclude='.venv/' --exclude='.turbo/' \
        --exclude='*.tsbuildinfo' --exclude='/packages/ui/' --exclude='/packages/plugin/' \
        --exclude='/packages/README.md' --exclude='/web/dist/' --exclude='/frontend-rs/dist/' \
        --exclude='/.github/' --exclude='/apps/' --exclude='/docs/' --exclude='/e2e/' \
        --exclude='/plugins/' --exclude='/setup/' --exclude='/tests/' \
        --exclude='/CHANGELOG.md' --exclude='/README.md' --exclude='/SECURITY.md' \
        --exclude='/package.json' --exclude='/package-lock.json' --exclude='/.gitleaks.toml' \
        --exclude='/.gitignore' --exclude='/.gitattributes' --exclude='/.nvmrc' --exclude='/.env.example' \
        "${REPO_DIR}/" "${RELEASE_DIR}/" >> "${LOG_FILE}" 2>&1; then
        log_error "rsync source tree into ${RELEASE_DIR} failed."
        return 1
    fi
    if [[ ! -s "${RELEASE_DIR}/.version" ]]; then
        echo "${CHANNEL}-${source_sha}" > "${RELEASE_DIR}/.version" || return 1
    fi

    cd "${RELEASE_DIR}" || return 1
    log_info "Building and staging Rust WASM frontend..."
    export PATH="${WASM_TOOL_DIR:-/usr/local/lib/aetherflow-wasm-tools}/bin:${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/aetherflow-wasm-tools/bin:${HOME:-/root}/.cargo/bin:${PATH}"
    if ! bash "${RELEASE_DIR}/scripts/install_wasm_build_tools.sh" --ensure >> "${LOG_FILE}" 2>&1; then
        log_error "Rust WASM frontend tool bootstrap failed."
        return 1
    fi
    if ! FRONTEND_DIST_DIR="${RELEASE_DIR}/web/dist" bash "${RELEASE_DIR}/scripts/build_wasm_frontend.sh" --stage >> "${LOG_FILE}" 2>&1; then
        log_error "Rust WASM frontend build failed."
        return 1
    fi

    if [[ ! -f "${RELEASE_DIR}/web/dist/index.html" || ! -s "${RELEASE_DIR}/web/dist/index.html" ]] || [[ -z "$(find "${RELEASE_DIR}/web/dist" -type f -name '*.wasm' -size +0c -print -quit)" ]]; then
        log_error "Rust WASM frontend staging is missing a non-empty index.html or .wasm file in web/dist."
        return 1
    fi

    cd "${RELEASE_DIR}/backend-rs" || { log_error "Rust backend directory missing."; return 1; }
    if [[ ! -d "${RELEASE_DIR}/backend-rs" ]] || ! command -v cargo &>/dev/null || ! command -v rustc &>/dev/null; then
        log_error "Rust backend source (${RELEASE_DIR}/backend-rs), cargo, and rustc (>= 1.95.0) are required for source builds."
        return 1
    fi
    local rustc_ver
    rustc_ver="$(rustc --version 2>/dev/null | awk '{print $2}' | cut -d- -f1 || true)"
    if [[ "${rustc_ver}" =~ ^([0-9]+)\.([0-9]+) ]]; then
        local r_maj="${BASH_REMATCH[1]}" r_min="${BASH_REMATCH[2]}"
        if (( 10#${r_maj} < 1 || (10#${r_maj} == 1 && 10#${r_min} < 95) )); then
            log_error "Installed rustc ${rustc_ver} is older than required MSRV 1.95.0."
            return 1
        fi
    else
        log_error "Unable to verify rustc version '${rustc_ver}' (requires >= 1.95.0)."
        return 1
    fi

    log_info "Compiling AetherFlow Rust control plane and companions (backend-rs)..."
    local -a cargo_locked_args=(--locked)
    if [[ ! -f Cargo.lock ]]; then
        if [[ "${CARGO_ALLOW_UNLOCKED_DEV:-0}" == "1" ]]; then
            cargo_locked_args=()
        else
            log_error "Missing backend-rs/Cargo.lock. Refusing unlocked source build."
            return 1
        fi
    fi
    local -a companion_bins=(af)
    if [[ -f "${RELEASE_DIR}/backend-rs/crates/af-librespeed/Cargo.toml" ]]; then
        companion_bins+=(speedtest-backend)
    fi
    local -a cargo_bin_args=(--bin aetherflow-api)
    local built_bin
    for built_bin in "${companion_bins[@]}"; do
        cargo_bin_args+=(--bin "${built_bin}")
    done
    local af_src_ver="source-${source_sha}"
    if [[ -s "${RELEASE_DIR}/.version" ]]; then
        af_src_ver="$(tr -d '\r\n' < "${RELEASE_DIR}/.version")"
    fi
    (
        if ! command -v mold &>/dev/null; then
            export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS:--C link-arg=-Wl,--as-needed}"
            export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS:--C link-arg=-Wl,--as-needed}"
        fi
        AF_BUILD_VERSION="${af_src_ver}" AETHERFLOW_VERSION="${af_src_ver}" \
            cargo build --release "${cargo_locked_args[@]}" "${cargo_bin_args[@]}" >> "${LOG_FILE}" 2>&1
    ) || return 1
    local cargo_target_dir="${CARGO_TARGET_DIR:-${RELEASE_DIR}/backend-rs/target}"
    [[ "${cargo_target_dir}" == /* ]] || cargo_target_dir="${RELEASE_DIR}/backend-rs/${cargo_target_dir}"
    install -m 0755 "${cargo_target_dir}/release/aetherflow-api" "${RELEASE_DIR}/aetherflow-api" || return 1
    mkdir -p "${RELEASE_DIR}/bin" || return 1
    for built_bin in "${companion_bins[@]}"; do
        install -m 0755 "${cargo_target_dir}/release/${built_bin}" "${RELEASE_DIR}/${built_bin}" || return 1
        install -m 0755 "${cargo_target_dir}/release/${built_bin}" "${RELEASE_DIR}/bin/${built_bin}" || return 1
    done
    local runtime_script
    for runtime_script in verify-provenance.py log-retention.py; do
        if [[ -f "${RELEASE_DIR}/deploy/${runtime_script}" ]]; then
            chmod 0755 "${RELEASE_DIR}/deploy/${runtime_script}" || return 1
        fi
    done

    # Keep external web/dist beside the binaries after removing build-only files.
    cd "${RELEASE_DIR}" || return 1
    rm -rf "${RELEASE_DIR}/frontend" "${RELEASE_DIR}/frontend-rs" \
        "${RELEASE_DIR}/backend-rs" "${RELEASE_DIR}/scripts" \
        "${RELEASE_DIR}/rust-toolchain.toml" "${RELEASE_DIR}/packages/README.md"
}

simulate_offline_artifact() {
    log_info "[DRY-RUN] Offline mode: simulating artifact verification and extraction."
    mkdir -p "${RELEASE_DIR}/deploy/systemd" "${RELEASE_DIR}/packages" "${RELEASE_DIR}/config" "${RELEASE_DIR}/bin" "${RELEASE_DIR}/web/dist"
    printf '<!doctype html><title>AetherFlow dry run</title>\n' > "${RELEASE_DIR}/web/dist/index.html"
    printf '\000asm\001\000\000\000' > "${RELEASE_DIR}/web/dist/app.wasm"
    echo "#!/bin/bash" > "${RELEASE_DIR}/aetherflow-api"
    echo "#!/bin/bash" > "${RELEASE_DIR}/af"
    cp -f "${RELEASE_DIR}/af" "${RELEASE_DIR}/bin/af"
    echo "#!/bin/bash" > "${RELEASE_DIR}/speedtest-backend"
    cp -f "${RELEASE_DIR}/speedtest-backend" "${RELEASE_DIR}/bin/speedtest-backend"
    chmod +x \
        "${RELEASE_DIR}/aetherflow-api" \
        "${RELEASE_DIR}/af" \
        "${RELEASE_DIR}/bin/af" \
        "${RELEASE_DIR}/speedtest-backend" \
        "${RELEASE_DIR}/bin/speedtest-backend"
    echo "v4.0.0-dryrun" > "${RELEASE_DIR}/.version"
    stage_running_release_manager
}

release_scaffold() {
    log_info "=== STAGE 1: Release Scaffold (Channel: ${CHANNEL}) ==="
    if [[ "${OFFLINE}" == true && "${DRY_RUN}" == false ]]; then
        log_fatal "--offline is only valid with --dry-run. Refusing to deploy a placeholder binary."
    fi

    if [[ "${FROM_SOURCE}" == true && "${DRY_RUN}" == true ]]; then
        log_error "[DRY-RUN] Refusing --from-source. Use a published artifact, or --offline for a placeholder."
        exit 1
    fi

    mkdir -p "${RELEASES_DIR}"
    if [[ -e "${RELEASE_DIR}" ]]; then
        log_error "Release target already exists: ${RELEASE_DIR}"
        exit 1
    fi

    local final_release_dir="${RELEASE_DIR}"
    local stage_dir=""
    stage_dir="$(mktemp -d "${RELEASES_DIR}/.staging.${EPOCH}.XXXXXX")" || log_fatal "Failed to create staging directory under ${RELEASES_DIR}"
    chmod 0750 "${stage_dir}"
    ACTIVE_STAGE_DIR="${stage_dir}"
    RELEASE_DIR="${stage_dir}"

    if [[ "${DRY_RUN}" == true && "${OFFLINE}" == true ]]; then
        if ! simulate_offline_artifact; then
            rm -rf "${stage_dir}"
            ACTIVE_STAGE_DIR=""
            RELEASE_DIR="${final_release_dir}"
            exit 1
        fi
    elif [[ "${FROM_SOURCE}" == false ]]; then
        local target_tag=""
        target_tag="$(resolve_release_tag "${CHANNEL}" || true)"
        if [[ -z "${target_tag}" ]]; then
            log_error "Could not resolve a release tag for channel ${CHANNEL}. Refusing implicit source-build fallback."
            rm -rf "${stage_dir}"
            ACTIVE_STAGE_DIR=""
            RELEASE_DIR="${final_release_dir}"
            exit 1
        fi
        log_info "Resolved release tag ${target_tag} for channel ${CHANNEL}."
        if ! pull_prebuilt_artifact "${target_tag}"; then
            log_error "Pre-built artifact pull or verification failed for ${target_tag}. Refusing implicit source-build fallback."
            rm -rf "${stage_dir}"
            ACTIVE_STAGE_DIR=""
            RELEASE_DIR="${final_release_dir}"
            exit 1
        fi
        if ! mv -T "${stage_dir}" "${final_release_dir}"; then
            rm -rf "${stage_dir}"
            ACTIVE_STAGE_DIR=""
            RELEASE_DIR="${final_release_dir}"
            log_fatal "Failed to atomically promote staged release ${stage_dir} to ${final_release_dir}."
        fi
        ACTIVE_STAGE_DIR=""
        RELEASE_DIR="${final_release_dir}"
        log_info "=== STAGE 1 COMPLETE: Pre-built release ${target_tag} staged at ${RELEASE_DIR} ==="
        return 0
    else
        if ! build_from_source; then
            log_error "Source build failed. Cleaning up ${stage_dir}."
            rm -rf "${stage_dir}"
            ACTIVE_STAGE_DIR=""
            RELEASE_DIR="${final_release_dir}"
            exit 1
        fi
    fi

    if ! mv -T "${stage_dir}" "${final_release_dir}"; then
        rm -rf "${stage_dir}"
        ACTIVE_STAGE_DIR=""
        RELEASE_DIR="${final_release_dir}"
        log_fatal "Failed to atomically promote staged release ${stage_dir} to ${final_release_dir}."
    fi
    ACTIVE_STAGE_DIR=""
    RELEASE_DIR="${final_release_dir}"

    log_info "=== STAGE 1 COMPLETE: Release ${EPOCH} scaffolded ==="
}

###############################################################################
# STAGE 1.5: State Snapshot (Online SQLite Backup + SHA-256 Manifest)
###############################################################################
prepare_release_permissions() {
    local service_user service_group
    service_user="$(systemctl show aetherflow-api.service -p User --value 2>/dev/null || true)"
    service_user="${service_user:-aetherflow}"
    if [[ "${DRY_RUN}" == false ]]; then
        service_group="$(id -gn "${service_user}")" || return 1
        if [[ "${EUID}" -eq 0 ]]; then
            chown -R --no-dereference "root:${service_group}" "${RELEASE_DIR}" || return 1
        fi
    fi
    find "${RELEASE_DIR}" -type d -exec chmod 0755 {} + || return 1
    find "${RELEASE_DIR}" -type f -exec chmod a+r,go-w {} + || return 1
    chmod 0755 "${RELEASE_DIR}/aetherflow-api" || return 1
    local companion_chmod
    for companion_chmod in af speedtest-backend; do
        if [[ -f "${RELEASE_DIR}/${companion_chmod}" ]]; then
            chmod 0755 "${RELEASE_DIR}/${companion_chmod}" || return 1
        fi
        if [[ -f "${RELEASE_DIR}/bin/${companion_chmod}" ]]; then
            chmod 0755 "${RELEASE_DIR}/bin/${companion_chmod}" || return 1
        fi
    done
    if [[ "${DRY_RUN}" == false ]]; then
        if [[ "${EUID}" -eq 0 ]] || [[ "${service_user}" != "$(id -un)" ]]; then
            if ! runuser -u "${service_user}" -- sh -c 'cd "$1" && test -r .version && test -x ./aetherflow-api && { test ! -d web/dist || test -r web/dist/index.html; }' sh "${RELEASE_DIR}"; then
                log_error "Release is inaccessible to service user ${service_user}. Refusing symlink swap."
                return 1
            fi
        else
            if ! sh -c 'cd "$1" && test -r .version && test -x ./aetherflow-api && { test ! -d web/dist || test -r web/dist/index.html; }' sh "${RELEASE_DIR}"; then
                log_error "Release is inaccessible to service user ${service_user}. Refusing symlink swap."
                return 1
            fi
        fi
    fi
    log_info "Release permissions normalized and service access verified."
}

state_snapshot() {
    log_info "=== STAGE 1.5: State Snapshot ==="
    if [[ -z "${RESOLVED_DB_PATH}" ]]; then
        resolve_db_path
    fi

    local snapshot_db="${RESOLVED_DB_PATH}"
    if [[ "${DRY_RUN}" == true ]]; then
        local copy="${DATA_DIR}/${SQLITE_DB}"
        mkdir -p "${DATA_DIR}"
        if [[ -f "${RESOLVED_DB_PATH}" && "${RESOLVED_DB_PATH}" != "${copy}" ]]; then
            if ! command -v sqlite3 >/dev/null 2>&1; then
                log_error "sqlite3 is required to copy the live database without a raw cp of a WAL file."
                return 1
            fi
            log_info "[DRY-RUN] Copying live database with sqlite3 --readonly .backup from ${RESOLVED_DB_PATH} (source: ${RESOLVED_DB_SOURCE}) into ${copy}"
            # state_snapshot runs under `||`, so errexit is off. A failed copy must
            # not fall through into the placeholder database.
            if ! sqlite_online_backup "${RESOLVED_DB_PATH}" "${copy}"; then
                rm -f "${copy}" "${copy}-wal" "${copy}-shm"
                log_error "[DRY-RUN] Failed to copy live database from ${RESOLVED_DB_PATH} (source: ${RESOLVED_DB_SOURCE})."
                return 1
            fi
        fi
        # Never create or snapshot the live path itself during a dry-run.
        snapshot_db="${copy}"
    fi

    if [[ ! -f "${snapshot_db}" ]]; then
        if [[ "${DRY_RUN}" == true ]]; then
            if ! command -v sqlite3 >/dev/null 2>&1; then
                log_error "sqlite3 is required to create the dry-run placeholder database."
                return 1
            fi
            mkdir -p "$(dirname "${snapshot_db}")"
            sqlite3 "${snapshot_db}" "CREATE TABLE IF NOT EXISTS _meta (key TEXT, value TEXT); INSERT INTO _meta VALUES ('version','dryrun');"
            log_info "[DRY-RUN] Created placeholder database at ${snapshot_db} because ${RESOLVED_DB_PATH} is absent."
        else
            log_warn "No database file at ${RESOLVED_DB_PATH}; skipping snapshot."
            log_info "=== STAGE 1.5 COMPLETE: No database to snapshot ==="
            return 0
        fi
    fi

    if ! command -v sqlite3 >/dev/null 2>&1; then
        log_error "sqlite3 is required for a WAL-safe snapshot of ${snapshot_db}."
        return 1
    fi

    local snapshot_dir="${RELEASE_DIR}/data-snapshot"
    mkdir -p "${snapshot_dir}" "${DATA_DIR}"
    local bak_path="${snapshot_dir}/${SQLITE_DB}.bak"
    local lock_file="${snapshot_dir}/.snapshot.lock"

    log_info "Executing SQLite online backup: ${snapshot_db} -> ${bak_path} (resolved ${RESOLVED_DB_PATH}, source: ${RESOLVED_DB_SOURCE})"
    (
        if ! flock -w "${SNAPSHOT_TIMEOUT}" 200; then
            exit 1
        fi
        sqlite_online_backup "${snapshot_db}" "${bak_path}"
    ) 200>"${lock_file}" || {
        log_error "SQLite snapshot failed for ${snapshot_db}."
        return 1
    }

    local integrity
    integrity="$(sqlite_integrity "${bak_path}")"
    if [[ "${integrity}" != "ok" ]]; then
        log_error "Snapshot integrity check FAILED for ${bak_path} (result=${integrity}). Aborting before symlink swap."
        return 1
    fi
    log_info "Snapshot integrity check PASSED: ${bak_path}"

    if ! (
        umask 077
        cd "${snapshot_dir}" &&
        sha256sum -- *.bak > MANIFEST.sha256 &&
        [[ -s MANIFEST.sha256 ]]
    ); then
        log_error "Failed to write snapshot SHA-256 manifest in ${snapshot_dir}. Aborting before symlink swap."
        return 1
    fi

    log_info "=== STAGE 1.5 COMPLETE: State snapshot captured ==="
}

###############################################################################
# STAGE 2: Atomic Symlink Swap
###############################################################################
sync_legacy_package_paths() {
    [[ "${DRY_RUN}" == true ]] && return 0
    [[ -d "${CURRENT_LINK}/packages" ]] || return 0
    if [[ -d "${LEGACY_OPT_ROOT}/packages" && ! "${CURRENT_LINK}/packages" -ef "${LEGACY_OPT_ROOT}/packages" ]]; then
        rsync -a --delete --checksum "${CURRENT_LINK}/packages/" "${LEGACY_OPT_ROOT}/packages/"
    fi
    if [[ -d "${LEGACY_BIN_ROOT}/package" && -d "${CURRENT_LINK}/packages/package" && ! "${CURRENT_LINK}/packages/package" -ef "${LEGACY_BIN_ROOT}/package" ]]; then
        rsync -a --delete --checksum "${CURRENT_LINK}/packages/package/" "${LEGACY_BIN_ROOT}/package/"
    fi
    if [[ -d "${LEGACY_BIN_ROOT}" && -f "${CURRENT_LINK}/packages/common.sh" && ! "${CURRENT_LINK}/packages/common.sh" -ef "${LEGACY_BIN_ROOT}/common.sh" ]]; then
        cp -a "${CURRENT_LINK}/packages/common.sh" "${LEGACY_BIN_ROOT}/common.sh"
    fi
}

sync_cli_entrypoints() {
    local bin_dir="${CLI_BIN_DIR:-}"
    if [[ -z "${bin_dir}" ]]; then
        if [[ "${DRY_RUN}" == true ]]; then
            bin_dir="${DRY_RUN_ROOT}/usr/local/bin"
        elif [[ -n "${EFFECTIVE_RELEASE_ROOT}" ]]; then
            bin_dir="${EFFECTIVE_RELEASE_ROOT%/}/usr/local/bin"
        else
            bin_dir="/usr/local/bin"
        fi
    fi
    validate_path_within_isolated_root "CLI_BIN_DIR" "${bin_dir}"
    if [[ "${DRY_RUN}" == false && -z "${EFFECTIVE_RELEASE_ROOT}" && "${EUID}" -ne 0 && ! -w "${bin_dir}" ]]; then
        return 0
    fi
    mkdir -p "${bin_dir}" 2>/dev/null || return 0
    if [[ -x "${CURRENT_LINK}/af" || -x "${CURRENT_LINK}/bin/af" ]]; then
        if [[ ! -e "${bin_dir}/af" || -L "${bin_dir}/af" ]]; then
            if [[ -x "${CURRENT_LINK}/af" ]]; then
                ln -sfn "${CURRENT_LINK}/af" "${bin_dir}/af" 2>/dev/null || true
            else
                ln -sfn "${CURRENT_LINK}/bin/af" "${bin_dir}/af" 2>/dev/null || true
            fi
        fi
    fi
}

symlink_swap() {
    log_info "=== STAGE 2: Atomic Symlink Swap ==="

    if [[ -L "${CURRENT_LINK}" ]]; then
        local previous_target
        previous_target="$(readlink -f "${CURRENT_LINK}")"
        echo "${previous_target}" > "${RELEASES_DIR}/.previous_release"
        log_info "Previous release recorded: ${previous_target}"
    fi

    local tmp_link="${CURRENT_LINK}.tmp.${EPOCH}"
    ln -s "${RELEASE_DIR}" "${tmp_link}"
    mv -Tf "${tmp_link}" "${CURRENT_LINK}"
    sync_cli_entrypoints
    sync_legacy_package_paths

    log_info "Symlink updated atomically: ${CURRENT_LINK} -> ${RELEASE_DIR}"
}

###############################################################################
# STAGE 3: Systemd Service Restart & Deep Readiness Probe
###############################################################################
install_packaged_unit() {
    local src="$1"
    local unit_name dest tmp_unit=""
    unit_name="$(basename "${src}")"
    dest="${SYSTEMD_UNITS_DST}/${unit_name}"
    if [[ -L "${src}" || -L "${SYSTEMD_UNITS_DST}" || -L "${dest}" ]]; then
        log_fatal "Refusing symlinked systemd unit path: ${dest} (source ${src})."
    fi
    [[ -e "${src}" ]] || return 0
    if [[ ! -f "${src}" ]]; then
        log_fatal "Refusing non-regular packaged systemd unit source: ${src}."
    fi
    mkdir -p "${SYSTEMD_UNITS_DST}"
    if [[ -L "${SYSTEMD_UNITS_DST}" ]]; then
        log_fatal "Refusing symlinked systemd unit directory: ${SYSTEMD_UNITS_DST}."
    fi
    if [[ -e "${dest}" ]]; then
        if [[ ! -f "${dest}" ]]; then
            log_fatal "Refusing non-regular installed systemd unit destination: ${dest}."
        fi
        log_info "Keeping installed systemd unit ${dest}; not replacing it with ${src}."
        return 0
    fi
    tmp_unit="$(mktemp "${SYSTEMD_UNITS_DST}/.${unit_name}.tmp.XXXXXX")" || log_fatal "Failed to create temporary unit file in ${SYSTEMD_UNITS_DST}."
    if ! cp -f "${src}" "${tmp_unit}" || ! chmod 0644 "${tmp_unit}" || ! mv -f "${tmp_unit}" "${dest}"; then
        rm -f "${tmp_unit}"
        log_fatal "Failed to atomically install systemd unit ${dest} from ${src}."
    fi
    log_info "Installed systemd unit ${dest} from ${src}."
}

restart_systemd_units() {
    verify_isolated_systemd_lifecycle_authorized
    if [[ -d "${CURRENT_LINK}/deploy/systemd" ]]; then
        install_packaged_unit "${CURRENT_LINK}/deploy/systemd/aetherflow-runner.service"
        install_packaged_unit "${CURRENT_LINK}/deploy/systemd/aetherflow-api.service"
        local -a dropin_units=(aetherflow-runner.service aetherflow-api.service)
        if [[ -f "${CURRENT_LINK}/deploy/log-retention.py" ]]; then
            install_packaged_unit "${CURRENT_LINK}/deploy/systemd/aetherflow-log-retention.service"
            install_packaged_unit "${CURRENT_LINK}/deploy/systemd/aetherflow-log-retention.timer"
            dropin_units+=(aetherflow-log-retention.service)
        fi
        if [[ -L "${SYSTEMD_UNITS_DST}" ]]; then
            printf 'Refusing symlinked systemd destination: %s\n' "${SYSTEMD_UNITS_DST}" >&2
            return 1
        fi
        mkdir -p "${SYSTEMD_UNITS_DST}"
        local dropin_unit dropin_dir dropin_dest defaults_dest tmp_dropin dropin_payload
        for dropin_unit in "${dropin_units[@]}"; do
            dropin_dir="${SYSTEMD_UNITS_DST}/${dropin_unit}.d"
            defaults_dest="${dropin_dir}/05-aetherflow-unit-defaults.conf"
            dropin_dest="${dropin_dir}/10-aetherflow-hardening.conf"
            if [[ -L "${dropin_dir}" || -L "${defaults_dest}" || -L "${dropin_dest}" ]]; then
                printf 'Refusing symlinked systemd drop-in path: %s\n' "${dropin_dest}" >&2
                return 1
            fi
            # Remove stale 05-aetherflow-unit-defaults.conf (canonical units own RestartSec/TimeoutStopSec)
            rm -f "${defaults_dest}"
            if [[ "${dropin_unit}" == "aetherflow-log-retention.service" ]]; then
                # Remove stale log-retention 10-aetherflow-hardening.conf (canonical unit sets UMask=0027)
                rm -f "${dropin_dest}"
                rmdir "${dropin_dir}" 2>/dev/null || true
                continue
            fi
            mkdir -p "${dropin_dir}"
            chmod 0755 "${dropin_dir}"
            if [[ "${dropin_unit}" == "aetherflow-runner.service" ]]; then
                dropin_payload=$'[Service]\nUMask=0077\nRuntimeDirectory=aetherflow\nRuntimeDirectoryMode=0750\nRuntimeDirectoryPreserve=yes\nLogsDirectory=aetherflow\nLogsDirectoryMode=0750\nPrivateTmp=yes\nProtectClock=yes\nProtectKernelLogs=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nLockPersonality=yes\nRestrictRealtime=yes\nSystemCallArchitectures=native\nSystemCallFilter=~@clock @cpu-emulation @debug @module @obsolete @raw-io @reboot @swap\n'
            else
                dropin_payload=$'[Service]\nUMask=0027\nLogsDirectory=\nProtectClock=yes\nProtectKernelLogs=yes\nProtectKernelModules=yes\nLockPersonality=yes\nRestrictNamespaces=yes\nRestrictRealtime=yes\nSystemCallArchitectures=native\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n'
            fi
            tmp_dropin="$(mktemp "${dropin_dir}/.10-aetherflow-hardening.conf.tmp.XXXXXX")" || return 1
            if ! printf '%s' "${dropin_payload}" > "${tmp_dropin}" || ! chmod 0644 "${tmp_dropin}" || ! mv -f "${tmp_dropin}" "${dropin_dest}"; then
                rm -f "${tmp_dropin}"
                return 1
            fi
        done
    fi

    if [[ "${EUID:-$(id -u)}" -eq 0 && -z "${EFFECTIVE_RELEASE_ROOT:-}" ]] && id -u aetherflow >/dev/null 2>&1; then
        local host_dir
        for host_dir in /var/log/aetherflow /run/aetherflow; do
            if [[ -L "${host_dir}" ]]; then
                printf 'Refusing symlinked host directory: %s\n' "${host_dir}" >&2
                return 1
            fi
            mkdir -p "${host_dir}"
            chown root:aetherflow "${host_dir}"
            chmod 0750 "${host_dir}"
        done
    fi

    systemctl daemon-reload || return 1

    if [[ -f "${CURRENT_LINK}/deploy/log-retention.py" ]]; then
        systemctl start aetherflow-log-retention.service || return 1
        systemctl enable --now aetherflow-log-retention.timer || return 1
    fi

    systemctl stop aetherflow-frontend.service 2>/dev/null || true
    systemctl disable aetherflow-frontend.service 2>/dev/null || true
    if command -v pm2 &>/dev/null; then
        pm2 delete aetherflow-frontend aetherflow-api 2>/dev/null || true
    fi

    systemctl enable aetherflow-runner.service aetherflow-api.service >/dev/null 2>&1 || true
    systemctl restart aetherflow-runner.service || return 1
    systemctl restart aetherflow-api.service || return 1
}

# Top-level "status" from a /health/ready body. Key order and whitespace do not matter.
# v4 Rust returns {"database":"ok","runner":"ok","redis":"disabled","status":"ready","uptime":"0.0s","version":"..."}
# (older supported v4 rollback slots without "runner" or with {"status":"ok"} remain accepted).
parse_health_status() {
    local response="$1"
    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "${response}" | python3 -c '
import json, sys
raw = sys.stdin.read().strip()
if not raw:
    sys.exit(1)
try:
    data = json.loads(raw)
except Exception:
    sys.exit(1)
if not isinstance(data, dict):
    sys.exit(1)
status = data.get("status")
if not isinstance(status, str) or not status:
    sys.exit(1)
sys.stdout.write(status)
' && return 0
    fi

    local flat match
    flat="$(printf '%s' "${response}" | tr -d '[:space:]')"
    match="$(printf '%s' "${flat}" | grep -o '"status":"[^"]*"' | head -1 || true)"
    [[ -n "${match}" ]] || return 1
    match="${match#\"status\":\"}"
    printf '%s' "${match%\"}"
}

health_probe() {
    log_info "=== STAGE 3: Systemd Restart & Deep Readiness Probe ==="

    if [[ "${DRY_RUN}" == true ]]; then
        log_info "[DRY-RUN] Skipping systemctl restart and health probe."
        return 0
    fi

    if ! restart_systemd_units; then
        log_error "Failed to restart required AetherFlow systemd services."
        return 1
    fi

    log_info "Polling ${HEALTH_ENDPOINT} (${HEALTH_RETRIES} attempts, ${HEALTH_INTERVAL}s interval)..."
    local attempt=1
    while [[ ${attempt} -le ${HEALTH_RETRIES} ]]; do
        local raw http_code body status
        raw="$(curl -sS --max-time 5 -w $'\n%{http_code}' "${HEALTH_ENDPOINT}" 2>/dev/null || true)"
        http_code="${raw##*$'\n'}"
        body="${raw%$'\n'*}"
        [[ "${http_code}" =~ ^[0-9]{3}$ ]] || http_code="000"

        if [[ "${http_code}" == "200" ]]; then
            status="$(parse_health_status "${body}" || true)"
            if [[ "${status}" == "ready" || "${status}" == "ok" ]]; then
                if [[ "${EUID:-$(id -u)}" -eq 0 && -z "${EFFECTIVE_RELEASE_ROOT:-}" && -L "${CURRENT_LINK}" ]]; then
                    if [[ -f "${SYSTEMD_UNITS_DST}/aetherflow-runner.service" ]] && ! systemctl is-active --quiet aetherflow-runner.service 2>/dev/null; then
                        log_warn "Health probe HTTP 200 but aetherflow-runner.service is not active; retrying."
                        sleep "${HEALTH_INTERVAL}"
                        attempt=$((attempt + 1))
                        continue
                    fi
                    local expected_release_dir main_pid proc_exe
                    expected_release_dir="$(readlink -f "${CURRENT_LINK}" 2>/dev/null || true)"
                    main_pid="$(systemctl show -p MainPID --value aetherflow-api.service 2>/dev/null | tr -d '[:space:]' || true)"
                    if [[ -n "${expected_release_dir}" && "${main_pid}" =~ ^[1-9][0-9]*$ && -e "/proc/${main_pid}/exe" ]]; then
                        proc_exe="$(readlink -f "/proc/${main_pid}/exe" 2>/dev/null || true)"
                        proc_exe="${proc_exe% (deleted)}"
                        if [[ -n "${proc_exe}" && "${proc_exe}" != "${expected_release_dir}/"* ]]; then
                            log_warn "Health probe HTTP 200 but MainPID ${main_pid} exe=${proc_exe} does not match ${expected_release_dir}; retrying."
                            sleep "${HEALTH_INTERVAL}"
                            attempt=$((attempt + 1))
                            continue
                        fi
                    fi
                fi
                if [[ -L "${CURRENT_LINK}" && -d "${CURRENT_LINK}/web/dist" ]]; then
                    if [[ ! -f "${CURRENT_LINK}/web/dist/index.html" || ! -s "${CURRENT_LINK}/web/dist/index.html" || ! -r "${CURRENT_LINK}/web/dist/index.html" ]]; then
                        log_error "Post-swap readiness check failed: missing, empty, or unreadable ${CURRENT_LINK}/web/dist/index.html."
                        return 1
                    fi
                fi
                log_info "Health probe PASSED on attempt ${attempt}/${HEALTH_RETRIES} (status=${status})"
                return 0
            fi
            log_warn "Health probe HTTP 200 but status=${status:-unknown}; retrying."
        fi

        sleep "${HEALTH_INTERVAL}"
        attempt=$((attempt + 1))
    done

    log_error "Health probe FAILED after ${HEALTH_RETRIES} attempts."
    return 1
}

###############################################################################
# STAGE 4: Rollback & SQLite Integrity Recovery
###############################################################################
stop_database_services() {
    verify_isolated_systemd_lifecycle_authorized
    if ! command -v systemctl >/dev/null 2>&1; then
        log_error "systemctl is absent; cannot stop aetherflow units before restoring ${1}."
        return 1
    fi
    log_info "Stopping aetherflow-api and aetherflow-runner before restoring ${1}."
    systemctl stop aetherflow-api.service aetherflow-runner.service
}

verify_restore_snapshot_digest() {
    python3 - "${1}" "${SQLITE_DB}.bak" <<'PY'
import hashlib
import os
import stat
import sys

snapshot_dir, backup_name = sys.argv[1:3]
directory_fd = os.open(snapshot_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
try:
    manifest_fd = os.open("MANIFEST.sha256", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    with os.fdopen(manifest_fd, "r", encoding="utf-8") as manifest:
        if not stat.S_ISREG(os.fstat(manifest.fileno()).st_mode):
            raise ValueError("snapshot manifest must be regular")
        manifest_text = manifest.read(1024 * 1024 + 1)
        if len(manifest_text) > 1024 * 1024:
            raise ValueError("snapshot manifest is too large")
    matching = []
    for entry in manifest_text.splitlines():
        fields = entry.split(maxsplit=1)
        if len(fields) == 2 and fields[1].lstrip("*") == backup_name:
            matching.append(fields[0].lower())
    if len(matching) != 1 or len(matching[0]) != 64 or any(character not in "0123456789abcdef" for character in matching[0]):
        raise ValueError("snapshot manifest lacks one valid database digest")
    backup_fd = os.open(backup_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    with os.fdopen(backup_fd, "rb") as backup:
        if not stat.S_ISREG(os.fstat(backup.fileno()).st_mode):
            raise ValueError("snapshot backup must be regular")
        backup_digest = hashlib.sha256()
        for chunk in iter(lambda: backup.read(1024 * 1024), b""):
            backup_digest.update(chunk)
        actual_digest = backup_digest.hexdigest()
    if actual_digest != matching[0]:
        raise ValueError("snapshot database digest mismatch")
finally:
    os.close(directory_fd)
PY
}

state_restore() {
    local target_release="${1}"
    if [[ -z "${RESOLVED_DB_PATH}" ]]; then
        resolve_db_path
    fi
    local db_path="${RESOLVED_DB_PATH}"
    local bak_path="${target_release}/data-snapshot/${SQLITE_DB}.bak"

    if [[ "${DRY_RUN}" == true ]]; then
        log_info "[DRY-RUN] Skipping database restore of ${db_path}."
        return 0
    fi

    [[ ! -f "${db_path}" && ! -f "${bak_path}" ]] && return 0

    if ! command -v sqlite3 >/dev/null 2>&1; then
        log_error "sqlite3 is absent; cannot verify integrity for ${db_path}."
        return 1
    fi

    local integrity="missing"
    if [[ -f "${db_path}" ]]; then
        integrity="$(sqlite_integrity "${db_path}")"
    fi
    if [[ "${integrity}" == "ok" ]]; then
        log_info "Database integrity check PASSED (${db_path})."
        return 0
    fi

    log "CRITICAL" "DATABASE CORRUPTION DETECTED (${integrity}) at ${db_path} — Restoring snapshot..."
    if [[ ! -f "${bak_path}" ]]; then
        log_error "No snapshot available at ${bak_path}."
        return 1
    fi
    if ! verify_restore_snapshot_digest "${target_release}/data-snapshot"; then
        log_error "Refusing snapshot with missing or invalid database checksum: ${bak_path}."
        return 1
    fi

    local bak_integrity
    bak_integrity="$(sqlite_integrity "${bak_path}")"
    if [[ "${bak_integrity}" != "ok" ]]; then
        log_error "Refusing to restore snapshot ${bak_path} (integrity=${bak_integrity})."
        return 1
    fi

    stop_database_services "${db_path}" || return 1
    rm -f "${db_path}-wal" "${db_path}-shm" || return 1
    if [[ -f "${db_path}" ]]; then
        mv "${db_path}" "${db_path}.corrupted.$(date +%s)" || return 1
    fi
    cp -pf "${bak_path}" "${db_path}" || return 1
    if [[ "${EUID:-$(id -u)}" -eq 0 ]] && id -u aetherflow >/dev/null 2>&1; then
        chown aetherflow:aetherflow "${db_path}" || return 1
    fi
    chmod 0600 "${db_path}" || return 1
    log "CRITICAL" "Database RESTORED to ${db_path} from verified snapshot: ${bak_path}"
}

rollback() {
    local snapshot_release="${1:-}"
    log_error "=== STAGE 4: ROLLBACK INITIATED ==="
    save_recovery_state "stage4_rollback"
    local prev_file="${RELEASES_DIR}/.previous_release"
    if [[ ! -f "${prev_file}" && -n "${RECOVERY_PREVIOUS_RELEASE}" && -d "${RECOVERY_PREVIOUS_RELEASE}" && ! -L "${prev_file}" ]]; then
        printf '%s\n' "${RECOVERY_PREVIOUS_RELEASE}" > "${prev_file}"
    fi
    if [[ ! -f "${prev_file}" ]]; then
        log_fatal "No previous release record found at ${prev_file}."
    fi

    local previous_target
    previous_target="$(cat "${prev_file}")"
    if [[ ! -d "${previous_target}" ]]; then
        log_fatal "Previous release directory missing: ${previous_target}."
    fi

    local current_before_rollback=""
    if [[ -L "${CURRENT_LINK}" ]]; then
        current_before_rollback="$(readlink -f "${CURRENT_LINK}" 2>/dev/null || true)"
    fi

    local tmp_link="${CURRENT_LINK}.rollback.${EPOCH}"
    ln -s "${previous_target}" "${tmp_link}"
    mv -Tf "${tmp_link}" "${CURRENT_LINK}"
    sync_cli_entrypoints
    sync_legacy_package_paths
    log_info "Symlink reverted: ${CURRENT_LINK} -> ${previous_target}"

    if [[ -z "${snapshot_release}" ]]; then
        local prev_canon
        prev_canon="$(readlink -f "${previous_target}" 2>/dev/null || printf '%s' "${previous_target}")"
        if [[ -n "${INFERRED_POST_SWAP_CANDIDATE}" && -d "${INFERRED_POST_SWAP_CANDIDATE}/data-snapshot" ]]; then
            snapshot_release="${INFERRED_POST_SWAP_CANDIDATE}"
        elif [[ -n "${current_before_rollback}" && "${current_before_rollback}" != "${prev_canon}" && -d "${current_before_rollback}/data-snapshot" ]]; then
            snapshot_release="${current_before_rollback}"
        else
            snapshot_release="${previous_target}"
        fi
    fi
    log_info "Database recovery snapshot release: ${snapshot_release}"

    if ! state_restore "${snapshot_release}"; then
        if ! stop_database_services "${RESOLVED_DB_PATH}"; then
            log_fatal "Database recovery failed; writer quiescence also failed. Refusing to restart services."
        fi
        log_fatal "Database recovery failed; database services remain stopped. Refusing to report rollback completion."
    fi

    if [[ "${DRY_RUN}" == false ]]; then
        if ! health_probe; then
            log_fatal "Health probe failed after rollback to ${previous_target}."
        fi
    fi
    log_error "=== ROLLBACK COMPLETE: Reverted to ${previous_target} ==="
    RECOVERY_PREVIOUS_RELEASE="${previous_target}"
    save_recovery_state "complete"
}

###############################################################################
# STAGE 5: Housekeeping
###############################################################################
cleanup_old_releases() {
    log_info "=== STAGE 5: Pruning Old Releases (retaining ${MAX_RELEASES}) ==="

    if [[ -d "${RELEASES_DIR}" && ! -L "${RELEASES_DIR}" ]]; then
        find "${RELEASES_DIR}" -mindepth 1 -maxdepth 1 -type d \( -name '.staging.*' -o -name '.staging-*' \) -mmin +120 -exec rm -rf {} + 2>/dev/null || true
    fi

    local current_target=""
    [[ -L "${CURRENT_LINK}" ]] && current_target="$(readlink -f "${CURRENT_LINK}")"

    local previous_target=""
    [[ -f "${RELEASES_DIR}/.previous_release" ]] && previous_target="$(cat "${RELEASES_DIR}/.previous_release")"

    local release_dirs
    if ! release_dirs="$(find "${RELEASES_DIR}" -mindepth 1 -maxdepth 1 -type d -not -name '.*' | sort -n)"; then
        LAST_LOG_ERROR="Could not list releases for retention cleanup."
        log_warn "${LAST_LOG_ERROR}"
        return 1
    fi
    [[ -n "${release_dirs}" ]] || return 0
    local releases=()
    while IFS= read -r dir; do
        releases+=("${dir}")
    done <<< "${release_dirs}"

    local count=${#releases[@]}
    [[ ${count} -le ${MAX_RELEASES} ]] && return 0

    local to_prune=$((count - MAX_RELEASES))
    local pruned=0
    for dir in "${releases[@]}"; do
        [[ ${pruned} -ge ${to_prune} ]] && break
        if [[ "${dir}" == "${current_target}" ]] || [[ "${dir}" == "${previous_target}" ]]; then
            continue
        fi
        if ! rm -rf -- "${dir}"; then
            LAST_LOG_ERROR="Could not prune ${dir} after pruning ${pruned} old release(s)."
            log_warn "${LAST_LOG_ERROR}"
            return 1
        fi
        pruned=$((pruned + 1))
    done
    log_info "Pruned ${pruned} old release(s)."
}

###############################################################################
# STAGE 6: One-Shot PM2 -> Systemd Migration
###############################################################################
migrate_systemd() {
    log_info "=== STAGE 6: PM2 -> Systemd Migration ==="
    ensure_fhs_layout
    if [[ "${DRY_RUN}" == true ]]; then
        log_info "[DRY-RUN] Would install aetherflow-runner.service and aetherflow-api.service and stop PM2."
        return 0
    fi
    if command -v pm2 &>/dev/null; then
        pm2 kill >> "${LOG_FILE}" 2>&1 || true
        pm2 unstartup >> "${LOG_FILE}" 2>&1 || true
        sleep 2
    fi
    if ! health_probe; then
        log_fatal "Health probe failed after systemd migration."
    fi
    log_info "MIGRATION COMPLETE: AetherFlow is running under hardened systemd units."
}

check_package_lifecycle_reservations() {
    [[ "${DRY_RUN}" != true ]] || return 0
    resolve_db_path_quiet
    if ! python3 - "${RESOLVED_DB_PATH}" "${COMMAND}" <<'PY'
import datetime, fcntl, os, pathlib, sqlite3, stat, sys, uuid
database, command = pathlib.Path(sys.argv[1]), sys.argv[2]
if not database.exists():
    sys.exit(0)
with database.open("rb") as source:
    header = source.read(16)
if not header:
    sys.exit(0)
if header != b"SQLite format 3\0":
    sys.exit(0 if command == "rollback" else "Cannot verify application lifecycle journal: invalid SQLite header")
try:
    connection = sqlite3.connect(database.as_uri() + "?mode=ro", uri=True, timeout=5)
    try:
        table = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='package_lifecycle_jobs'").fetchone()
        if not table:
            sys.exit(0)
        columns = {row[1] for row in connection.execute("PRAGMA table_info(package_lifecycle_jobs)")}
        stale = []
        held_leases = []
        try:
            if "owner_id" in columns:
                for package, job, owner in connection.execute("SELECT package_id,job_id,owner_id FROM package_lifecycle_jobs WHERE status IN ('installing','updating','uninstalling')").fetchall():
                    lease = None
                    try:
                        uuid.UUID(owner)
                        lease_path = database.with_suffix(".lifecycle-owners") / owner
                        descriptor = os.open(lease_path, os.O_RDONLY | os.O_NOFOLLOW)
                        lease = os.fdopen(descriptor, "rb")
                        if not stat.S_ISREG(os.fstat(lease.fileno()).st_mode):
                            lease.close()
                            continue
                        fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                        held_leases.append(lease)
                        stale.append((package, job, owner))
                    except (OSError, ValueError):
                        if lease is not None:
                            lease.close()
                        continue
            if stale:
                rw = sqlite3.connect(database.as_uri() + "?mode=rw", uri=True, timeout=5)
                try:
                    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                    for package, job, owner in stale:
                        rw.execute(
                            "UPDATE package_lifecycle_jobs SET status='interrupted',finished_at=? WHERE package_id=? AND job_id=? AND owner_id=? AND status IN ('installing','updating','uninstalling')",
                            (now, package, job, owner),
                        )
                    rw.commit()
                    active = rw.execute("SELECT 1 FROM package_lifecycle_jobs WHERE status NOT IN ('completed','failed','interrupted') LIMIT 1").fetchone()
                finally:
                    rw.close()
            else:
                active = connection.execute("SELECT 1 FROM package_lifecycle_jobs WHERE status NOT IN ('completed','failed','interrupted') LIMIT 1").fetchone()
        finally:
            for held in held_leases:
                try:
                    held.close()
                except OSError:
                    pass
        if active:
            sys.exit("Application lifecycle orchestration is active or its owner is unknown")
    finally:
        connection.close()
except sqlite3.DatabaseError as error:
    code = getattr(error, "sqlite_errorcode", None)
    # Python 3.10 has neither sqlite_errorcode nor the SQLITE_* constants.
    corrupt = (code is not None and (code & 255) in (11, 26)) or (
        code is None and str(error) in ("database disk image is malformed", "file is not a database")
    )
    if command == "rollback" and corrupt:
        sys.exit(0)
    sys.exit(f"Cannot verify application lifecycle journal: {error}")
PY
    then
        log_fatal "Application lifecycle admission is unavailable; release was not started."
    fi
}

guard_and_init_recovery_state() {
    local parsed=""
    if ! parsed="$(python3 - "${RELEASES_DIR}" "${CURRENT_LINK}" "${COMMAND}" "${CHANNEL:-stable}" "${DRY_RUN:-false}" "${AETHERFLOW_UPDATE_OPERATION_ID:-}" <<'PY'
import datetime, json, os, pathlib, shutil, stat, sys, uuid

releases_dir_s, current_link_s, cmd, channel, dry_run_s, env_op_id = sys.argv[1:]
releases_dir = pathlib.Path(releases_dir_s)
current_link = pathlib.Path(current_link_s)
state_file = releases_dir / ".recovery_state.json"
prev_file = releases_dir / ".previous_release"

if state_file.is_symlink():
    sys.stderr.write(f"Refusing symlinked recovery journal: {state_file}\n")
    raise SystemExit(1)

now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
valid_env_op = ""
if env_op_id:
    try:
        valid_env_op = str(uuid.UUID(env_op_id))
    except ValueError:
        valid_env_op = ""

op_id = valid_env_op or str(uuid.uuid4())
started_at = now
rec_cmd = cmd
rec_channel = "nightly" if channel == "experimental" else (channel or "stable")
rec_cand = ""
rec_prev = ""
rec_snap = ""
inferred_cand = ""
from_post_swap = "false"

if state_file.exists():
    st = state_file.lstat()
    if not stat.S_ISREG(st.st_mode):
        sys.stderr.write(f"Refusing non-regular recovery journal: {state_file}\n")
        raise SystemExit(1)
    try:
        existing = json.loads(state_file.read_text(encoding="utf-8"))
        if not isinstance(existing, dict):
            raise ValueError("not a JSON object")
    except Exception as exc:
        sys.stderr.write(f"Corrupted recovery journal {state_file}: {exc}\n")
        raise SystemExit(1)

    phase = str(existing.get("phase") or "")
    ex_cmd = str(existing.get("command") or "")
    ex_dry = bool(existing.get("dry_run", False))
    is_unfinished = phase not in ("complete", "completed", "failed")
    post_swap_deploy = (
        is_unfinished
        and ex_cmd in ("", "deploy")
        and not ex_dry
        and phase in ("stage2_symlink_swap", "stage3_health_probe", "stage4_rollback")
    )

    if post_swap_deploy:
        if cmd != "rollback":
            sys.stderr.write(
                f"Refusing to run '{cmd}' while an interrupted deployment "
                f"(operation_id={existing.get('operation_id')}, phase={phase}, "
                f"candidate={existing.get('candidate_release')}, previous_release={existing.get('previous_release')}) "
                f"is unfinished after symlink swap; run 'rollback' first so '.previous_release' is not overwritten.\n"
            )
            raise SystemExit(2)
        ex_prev = existing.get("previous_release")
        if isinstance(ex_prev, str) and ex_prev and pathlib.Path(ex_prev).is_dir():
            if prev_file.is_symlink():
                sys.stderr.write(f"Refusing symlinked .previous_release: {prev_file}\n")
                raise SystemExit(1)
            tmp_prev = releases_dir / f".previous_release.tmp.{os.getpid()}.{uuid.uuid4().hex}"
            tmp_prev.write_text(ex_prev + "\n", encoding="utf-8")
            os.replace(str(tmp_prev), str(prev_file))
            rec_prev = ex_prev
        ex_cand = existing.get("candidate_release")
        if isinstance(ex_cand, str) and ex_cand:
            rec_cand = ex_cand
            if (pathlib.Path(ex_cand) / "data-snapshot").is_dir():
                inferred_cand = ex_cand
        ex_snap = existing.get("snapshot_path")
        if isinstance(ex_snap, str) and ex_snap:
            rec_snap = ex_snap
        op_id = valid_env_op or str(existing.get("operation_id") or op_id)
        started_at = str(existing.get("started_at") or now)
        rec_cmd = ex_cmd or "rollback"
        rec_channel = str(existing.get("channel") or rec_channel)
        from_post_swap = "true"
    elif is_unfinished and phase in ("stage0_fhs_layout", "stage1_scaffold", "stage1_5_snapshot") and cmd != "rollback":
        ex_cand = existing.get("candidate_release")
        if isinstance(ex_cand, str) and ex_cand:
            cand_p = pathlib.Path(ex_cand)
            try:
                cand_res = cand_p.resolve(strict=False)
                rel_res = releases_dir.resolve(strict=False)
                cur_res = current_link.resolve(strict=False) if current_link.is_symlink() else None
                prev_res = pathlib.Path(prev_file.read_text(encoding="utf-8").strip()).resolve(strict=False) if prev_file.is_file() else None
                if (
                    cand_p.is_dir()
                    and not cand_p.is_symlink()
                    and str(cand_res).startswith(str(rel_res) + "/")
                    and cand_res != cur_res
                    and cand_res != prev_res
                ):
                    shutil.rmtree(cand_p, ignore_errors=True)
            except OSError:
                pass
    elif cmd == "rollback":
        ex_prev = existing.get("previous_release")
        if isinstance(ex_prev, str) and ex_prev:
            rec_prev = ex_prev

for val in (op_id, started_at, rec_cmd, rec_channel, rec_cand, rec_prev, rec_snap, inferred_cand, from_post_swap):
    sys.stdout.write(val.replace("\n", "") + "\n")
PY
    )"; then
        log_fatal "Recovery state admission refused command '${COMMAND}'; run 'rollback' first or inspect ${RELEASES_DIR}/.recovery_state.json."
    fi
    {
        IFS= read -r RECOVERY_OPERATION_ID
        IFS= read -r RECOVERY_STARTED_AT
        IFS= read -r RECOVERY_COMMAND
        IFS= read -r RECOVERY_CHANNEL
        IFS= read -r RECOVERY_CANDIDATE_RELEASE
        IFS= read -r RECOVERY_PREVIOUS_RELEASE
        IFS= read -r RECOVERY_SNAPSHOT_PATH
        IFS= read -r INFERRED_POST_SWAP_CANDIDATE
        IFS= read -r RECOVERY_FROM_UNFINISHED_POST_SWAP
    } <<< "${parsed}"
}

acquire_release_lock() {
    local shared_db_lock="${AETHERFLOW_MAINTENANCE_LOCK_PATH:-}"
    if [[ -z "${shared_db_lock}" ]]; then
        if [[ "${DRY_RUN}" == true ]]; then
            shared_db_lock="${DATA_DIR}/.snapshot.lock"
        else
            resolve_db_path_quiet
            local db_parent
            db_parent="$(dirname "${RESOLVED_DB_PATH}")"
            if [[ -z "${EFFECTIVE_RELEASE_ROOT}" && "${db_parent%/}" == "/var/lib/aetherflow" ]]; then
                shared_db_lock="/run/aetherflow/.snapshot.lock"
            elif [[ -n "${EFFECTIVE_RELEASE_ROOT}" && "${db_parent%/}" == "${EFFECTIVE_RELEASE_ROOT}/var/lib/aetherflow" && -d "${EFFECTIVE_RELEASE_ROOT}/run/aetherflow" ]]; then
                shared_db_lock="${EFFECTIVE_RELEASE_ROOT}/run/aetherflow/.snapshot.lock"
            else
                shared_db_lock="${db_parent}/.snapshot.lock"
            fi
        fi
    else
        resolve_db_path_quiet
    fi
    if [[ "${shared_db_lock}" == *".."* ]]; then
        log_fatal "Maintenance lock path must not contain '..': ${shared_db_lock}"
    fi
    validate_path_within_isolated_root "AETHERFLOW_MAINTENANCE_LOCK_PATH" "${shared_db_lock}"

    local shared_lock_dir
    shared_lock_dir="$(dirname "${shared_db_lock}")"
    if [[ -L "${shared_lock_dir}" ]]; then
        log_fatal "Maintenance lock parent directory is a symbolic link: ${shared_lock_dir}"
    fi
    mkdir -p "${shared_lock_dir}"
    if [[ "${EUID}" -eq 0 && ( "${shared_lock_dir%/}" == "/run/aetherflow" || ( -n "${EFFECTIVE_RELEASE_ROOT}" && "${shared_lock_dir%/}" == "${EFFECTIVE_RELEASE_ROOT}/run/aetherflow" ) ) ]]; then
        local runtime_svc_user="${AETHERFLOW_SERVICE_USER:-aetherflow}"
        if [[ -n "${AETHERFLOW_SERVICE_GID:-}" ]]; then
            chown --no-dereference "0:${AETHERFLOW_SERVICE_GID}" "${shared_lock_dir}" 2>/dev/null || true
        elif id -u "${runtime_svc_user}" >/dev/null 2>&1; then
            local runtime_svc_gid
            runtime_svc_gid="$(id -gn "${runtime_svc_user}" 2>/dev/null || echo "${runtime_svc_user}")"
            chown --no-dereference "root:${runtime_svc_gid}" "${shared_lock_dir}" 2>/dev/null || true
        fi
        chmod 0750 "${shared_lock_dir}" 2>/dev/null || true
    fi
    if [[ -L "${shared_db_lock}" ]]; then
        log_fatal "Maintenance lockfile is a symbolic link: ${shared_db_lock}"
    fi
    if [[ -e "${shared_db_lock}" && ! -f "${shared_db_lock}" ]]; then
        log_fatal "Maintenance lockfile exists and is not a regular file: ${shared_db_lock}"
    fi

    if [[ ! -e "${shared_db_lock}" ]]; then
        (
            umask 0007
            set -o noclobber
            : > "${shared_db_lock}"
        ) || log_fatal "Could not initialize maintenance lockfile: ${shared_db_lock}"
    fi

    if [[ -L "${shared_db_lock}" || ! -f "${shared_db_lock}" ]]; then
        log_fatal "Maintenance lockfile failed post-create regular-file check: ${shared_db_lock}"
    fi

    if [[ "${EUID}" -eq 0 ]]; then
        local dir_uid dir_gid dir_mode svc_user="${AETHERFLOW_SERVICE_USER:-aetherflow}"
        dir_uid="$(stat -c '%u' "${shared_lock_dir}" 2>/dev/null || echo 0)"
        dir_gid="$(stat -c '%g' "${shared_lock_dir}" 2>/dev/null || echo 0)"
        dir_mode="$(stat -c '%a' "${shared_lock_dir}" 2>/dev/null || echo 0755)"
        if [[ "${dir_uid}" != "0" && "${#dir_mode}" -lt 4 ]]; then
            chown --no-dereference "${dir_uid}:${dir_gid}" "${shared_db_lock}" 2>/dev/null || true
        elif [[ -n "${AETHERFLOW_SERVICE_UID:-}" && -n "${AETHERFLOW_SERVICE_GID:-}" ]]; then
            chown --no-dereference "0:${AETHERFLOW_SERVICE_GID}" "${shared_db_lock}" 2>/dev/null || true
        elif id -u "${svc_user}" >/dev/null 2>&1; then
            local svc_gid
            svc_gid="$(id -gn "${svc_user}" 2>/dev/null || echo "${svc_user}")"
            chown --no-dereference "root:${svc_gid}" "${shared_db_lock}" 2>/dev/null || true
        fi
        chmod 0660 "${shared_db_lock}" 2>/dev/null || true
    else
        chmod 0660 "${shared_db_lock}" 2>/dev/null || true
    fi

    exec 199<"${shared_db_lock}"
    if ! flock -w "${SNAPSHOT_TIMEOUT}" 199; then
        log_fatal "Could not acquire maintenance lock ${shared_db_lock} within ${SNAPSHOT_TIMEOUT}s."
    fi
    check_package_lifecycle_reservations
    mkdir -p "${RELEASES_DIR}"
    local release_lock="${RELEASES_DIR}/.release.lock"
    if [[ -L "${release_lock}" ]]; then
        log_fatal "Release lockfile is a symbolic link: ${release_lock}"
    fi
    exec 201>"${release_lock}"
    if ! flock -w "${SNAPSHOT_TIMEOUT}" 201; then
        log_fatal "Could not acquire release lock ${release_lock} within ${SNAPSHOT_TIMEOUT}s."
    fi
    guard_and_init_recovery_state
}

case "${COMMAND}" in
    deploy)
        acquire_release_lock
        save_recovery_state "stage0_fhs_layout"
        ensure_fhs_layout
        RECOVERY_CANDIDATE_RELEASE="${RELEASE_DIR}"
        save_recovery_state "stage1_scaffold"
        release_scaffold
        prepare_release_permissions || exit 1
        save_recovery_state "stage1_5_snapshot"
        state_snapshot || exit 1
        if [[ -f "${RELEASE_DIR}/data-snapshot/${SQLITE_DB}.bak" ]]; then
            RECOVERY_SNAPSHOT_PATH="${RELEASE_DIR}/data-snapshot/${SQLITE_DB}.bak"
        fi
        PRIOR_PREVIOUS_RELEASE=""
        if [[ -f "${RELEASES_DIR}/.previous_release" ]]; then
            PRIOR_PREVIOUS_RELEASE="$(cat "${RELEASES_DIR}/.previous_release")"
        fi
        if [[ -L "${CURRENT_LINK}" ]]; then
            RECOVERY_PREVIOUS_RELEASE="$(readlink -f "${CURRENT_LINK}" 2>/dev/null || true)"
        else
            RECOVERY_PREVIOUS_RELEASE="${PRIOR_PREVIOUS_RELEASE}"
        fi
        save_recovery_state "stage2_symlink_swap"
        symlink_swap
        if [[ -f "${RELEASES_DIR}/.previous_release" ]]; then
            RECOVERY_PREVIOUS_RELEASE="$(cat "${RELEASES_DIR}/.previous_release")"
        fi
        save_recovery_state "stage3_health_probe"
        if ! health_probe; then
            RECOVERY_FROM_UNFINISHED_POST_SWAP=true
            save_recovery_state "stage4_rollback" "${LAST_LOG_ERROR:-Health probe failed}"
            rollback "${RELEASE_DIR}"
            if [[ -n "${PRIOR_PREVIOUS_RELEASE}" && -d "${PRIOR_PREVIOUS_RELEASE}" ]]; then
                REVERTED_CANON="$(readlink -f "${CURRENT_LINK}" 2>/dev/null || true)"
                PRIOR_CANON="$(readlink -f "${PRIOR_PREVIOUS_RELEASE}" 2>/dev/null || printf '%s' "${PRIOR_PREVIOUS_RELEASE}")"
                if [[ "${PRIOR_CANON}" != "${REVERTED_CANON}" && ! -L "${RELEASES_DIR}/.previous_release" ]]; then
                    printf '%s\n' "${PRIOR_PREVIOUS_RELEASE}" > "${RELEASES_DIR}/.previous_release"
                fi
            fi
            exit 2
        fi
        save_recovery_state "complete"
        if ! cleanup_old_releases; then
            log_warn "Release retention cleanup can be retried."
        fi
        if [[ "${DRY_RUN}" == true ]]; then
            log_info "DRY-RUN SUCCESSFUL: Release ${EPOCH} (${CHANNEL}) staged at ${CURRENT_LINK}. Systemd was not restarted."
        else
            log_info "DEPLOYMENT SUCCESSFUL: Release ${EPOCH} (${CHANNEL}) is now live."
        fi
        ;;
    rollback)
        acquire_release_lock
        rollback
        ;;
    cleanup)
        acquire_release_lock
        save_recovery_state "stage5_cleanup"
        cleanup_old_releases
        save_recovery_state "complete"
        ;;
    migrate-systemd)
        acquire_release_lock
        save_recovery_state "stage6_migrate_systemd"
        migrate_systemd
        save_recovery_state "complete"
        ;;
    *)
        echo "Usage: $0 {deploy|rollback|cleanup|migrate-systemd} [--channel stable|nightly] [--from-source] [--dry-run] [--offline]"
        exit 4
        ;;
esac
