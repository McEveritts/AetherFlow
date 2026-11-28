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
        python3 -I - "${SELF_UPDATE_STATUS_FILE}" "${status_str}" "${completed_bool}" "${success_bool}" "${SELF_UPDATE_JOB_UNIT}" "${exit_code_val}" "${err_msg}" "${AETHERFLOW_SELF_UPDATE_DIRECTORY_DEV:-}" "${AETHERFLOW_SELF_UPDATE_DIRECTORY_INO:-}" <<'PY'
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
            # Keep self-update receipts private (root-only 0600).
            os.fchmod(output.fileno(), 0o600)
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
    python3 -I - "${RELEASES_DIR}" "${RECOVERY_OPERATION_ID}" "${RECOVERY_COMMAND}" "${RECOVERY_CHANNEL}" "${DRY_RUN:-false}" "${phase}" "${RECOVERY_CANDIDATE_RELEASE}" "${RECOVERY_PREVIOUS_RELEASE}" "${RESOLVED_DB_PATH:-}" "${RESOLVED_DB_SOURCE:-}" "${RECOVERY_SNAPSHOT_PATH}" "${RECOVERY_STARTED_AT}" "${err_msg}" <<'PY'
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
            if [[ "${RECOVERY_FROM_UNFINISHED_POST_SWAP}" == true || "${ROLLBACK_POST_SWAP_ACTIVE:-false}" == true ]]; then
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

release_fd_lock_coproc() {
    if [[ -n "${AF_LOCK_COPROC_IN_FD:-}" ]]; then
        eval "exec ${AF_LOCK_COPROC_IN_FD}>&-" 2>/dev/null || true
        AF_LOCK_COPROC_IN_FD=""
    fi
    if [[ -n "${AF_LOCK_COPROC_OUT_FD:-}" ]]; then
        eval "exec ${AF_LOCK_COPROC_OUT_FD}<&-" 2>/dev/null || true
        AF_LOCK_COPROC_OUT_FD=""
    fi
    if [[ -n "${AF_LOCK_COPROC_PID:-}" ]]; then
        kill "${AF_LOCK_COPROC_PID}" 2>/dev/null || true
        wait "${AF_LOCK_COPROC_PID}" 2>/dev/null || true
        AF_LOCK_COPROC_PID=""
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
    release_fd_lock_coproc
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
    : "${SYS_BIN_DIR:=${EFFECTIVE_RELEASE_ROOT}/usr/bin}"
    : "${TRANSCODE_SHIM_PATH:=${EFFECTIVE_RELEASE_ROOT}/usr/lib/aetherflow/transcode/ffmpeg}"
fi

load_conf_file_safely() {
    local conf_path="$1"
    if command -v python3 >/dev/null 2>&1; then
        local parsed_records=""
        if ! parsed_records="$(python3 -I - "${conf_path}" "${SCRIPT_DIR}" "${EFFECTIVE_RELEASE_ROOT:-}" <<'PY'
import base64, errno, os, pathlib, re, stat, sys

conf_path = sys.argv[1]
script_dir = sys.argv[2]
confine_root_raw = sys.argv[3]
MAX_CONF_BYTES = 65536
allowed_keys = {
    "RELEASES_DIR", "CURRENT_LINK", "REPO_DIR", "LEGACY_OPT_ROOT", "DRY_RUN_ROOT",
    "GITHUB_REPO", "RELEASE_CHANNEL", "ARTIFACT_NAME", "RELEASE_ASSET_NAME", "CHECKSUM_NAME", "GIT_BRANCH",
    "GIT_REMOTE", "NODE_HEAP_MB", "HEALTH_ENDPOINT", "HEALTH_RETRIES",
    "HEALTH_INTERVAL", "MAX_RELEASES", "LOG_FILE", "DATA_DIR", "ENV_DIR", "ENV_FILE",
    "SQLITE_DB", "SNAPSHOT_TIMEOUT", "SYSTEMD_UNITS_SRC", "SYSTEMD_UNITS_DST",
    "CLI_BIN_DIR", "TRANSCODE_SHIM_PATH", "AETHERFLOW_RELEASE_ROOT", "AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH",
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

def open_conf_file_via_openat(path_str):
    p = pathlib.PurePosixPath(path_str)
    if ".." in p.parts:
        raise ValueError(f"refusing parent traversal in configuration path: {path_str}")
    abs_p = pathlib.PurePosixPath(os.path.abspath(path_str))
    leaf_name = abs_p.name
    if not leaf_name or leaf_name in (".", ".."):
        raise ValueError(f"invalid configuration path: {path_str}")
    confine = pathlib.PurePosixPath(confine_root_raw.rstrip("/") or "/") if confine_root_raw else None
    if confine is not None:
        try:
            rel_parents = abs_p.parent.relative_to(confine).parts
            anchor = pathlib.Path(str(confine))
        except ValueError:
            rel_parents = abs_p.parent.parts[1:]
            anchor = pathlib.Path("/")
    else:
        rel_parents = abs_p.parent.parts[1:]
        anchor = pathlib.Path("/")

    O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
    O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
    O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
    O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
    cur_fd = os.open(str(anchor), os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    cur = anchor
    try:
        for part in rel_parents:
            nxt = cur / part
            st = os.stat(part, dir_fd=cur_fd, follow_symlinks=False)
            if stat.S_ISLNK(st.st_mode):
                if part == "current" and cur.name == "AetherFlow" and cur.parent.name == "opt":
                    if os.geteuid() == 0 and st.st_uid != 0:
                        raise ValueError(f"refusing non-root-owned current release symlink: {nxt}")
                    raw_target = pathlib.PurePosixPath(os.readlink(part, dir_fd=cur_fd))
                    if ".." in raw_target.parts:
                        raise ValueError(f"refusing traversal in current release symlink: {nxt}")
                    resolved_target = raw_target if raw_target.is_absolute() else pathlib.PurePosixPath(str(cur)) / raw_target
                    expected_releases = pathlib.PurePosixPath(str(cur / "releases"))
                    if resolved_target.parent != expected_releases:
                        raise ValueError(f"refusing current release symlink outside releases/: {nxt}")
                    rel_fd = os.open("releases", os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
                    try:
                        epoch_fd = os.open(resolved_target.name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=rel_fd)
                    except Exception:
                        os.close(rel_fd)
                        raise
                    try:
                        if os.geteuid() == 0:
                            for hfd, hpath in ((rel_fd, expected_releases), (epoch_fd, resolved_target)):
                                hst = os.fstat(hfd)
                                if hst.st_uid != 0 or (hst.st_mode & 0o022) != 0:
                                    raise ValueError(f"refusing untrusted release directory ownership/mode: {hpath}")
                    except Exception:
                        os.close(epoch_fd)
                        os.close(rel_fd)
                        raise
                    os.close(rel_fd)
                    os.close(cur_fd)
                    cur_fd = epoch_fd
                    cur = pathlib.Path(str(resolved_target))
                    continue
                raise ValueError(f"refusing symlinked configuration ancestor directory: {nxt}")
            if not stat.S_ISDIR(st.st_mode):
                raise ValueError(f"configuration ancestor is not a directory: {nxt}")
            nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
            os.close(cur_fd)
            cur_fd = nxt_fd
            cur = nxt
        return os.open(leaf_name, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=cur_fd)
    finally:
        os.close(cur_fd)

try:
    fd = open_conf_file_via_openat(conf_path)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise ValueError(f"configuration path is not a regular file: {conf_path}")
        if (st.st_mode & 0o002) != 0:
            raise ValueError(f"refusing world-writable configuration file (mode {st.st_mode & 0o777:04o}): {conf_path}")
        if os.geteuid() == 0:
            if st.st_uid != 0:
                raise ValueError(f"refusing non-root-owned configuration file (uid={st.st_uid}) while running as root: {conf_path}")
            if (st.st_mode & 0o022) != 0:
                raise ValueError(f"refusing group/world-writable configuration file (mode {st.st_mode & 0o777:04o}) while running as root: {conf_path}")
        if st.st_size > MAX_CONF_BYTES:
            raise ValueError(f"configuration file exceeds maximum size ({MAX_CONF_BYTES} bytes): {conf_path}")
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, 8192)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_CONF_BYTES:
                raise ValueError(f"configuration file exceeds maximum size ({MAX_CONF_BYTES} bytes): {conf_path}")
            chunks.append(chunk)
        lines = b"".join(chunks).decode("utf-8").splitlines()
    finally:
        os.close(fd)
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
            val="$(python3 -I -c 'import base64, sys; sys.stdout.write(base64.b64decode(sys.argv[1]).decode("utf-8"))' "${encoded_val}")"
            if [[ "${mode}" == "DEFAULT" ]]; then
                if [[ -z "${!key:-}" ]]; then
                    printf -v "${key}" '%s' "${val}"
                fi
            else
                printf -v "${key}" '%s' "${val}"
                if [[ "${key}" == "HEALTH_ENDPOINT" && -n "${val}" ]]; then
                    HEALTH_ENDPOINT_EXPLICIT=true
                fi
            fi
        done <<< "${parsed_records}"
        return 0
    fi

    LAST_LOG_ERROR="python3 is required to safely parse ${conf_path}"
    echo "[FATAL] ${LAST_LOG_ERROR}"
    exit 4
}

# Track whether HEALTH_ENDPOINT was explicitly supplied via process env or non-default conf.
HEALTH_ENDPOINT_EXPLICIT=false
if [[ -n "${HEALTH_ENDPOINT:-}" ]]; then
    HEALTH_ENDPOINT_EXPLICIT=true
fi

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
: "${SNAPSHOT_TIMEOUT:=30}"
: "${MAX_RELEASES:=3}"
: "${HEALTH_RETRIES:=10}"
: "${HEALTH_INTERVAL:=3}"
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
    : "${LEGACY_BIN_ROOT:=${CLI_BIN_DIR%/}/AetherFlow}"
    : "${SYS_BIN_DIR:=${EFFECTIVE_RELEASE_ROOT}/usr/bin}"
    : "${TRANSCODE_SHIM_PATH:=${EFFECTIVE_RELEASE_ROOT}/usr/lib/aetherflow/transcode/ffmpeg}"
    for _root_check_var in RELEASES_DIR CURRENT_LINK REPO_DIR LEGACY_OPT_ROOT DRY_RUN_ROOT LOG_FILE DATA_DIR ENV_DIR ENV_FILE SYSTEMD_UNITS_DST CLI_BIN_DIR LEGACY_BIN_ROOT SYS_BIN_DIR TRANSCODE_SHIM_PATH; do
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
CONFIG_REPO_DIR="${REPO_DIR:-}"
CONFIG_ENV_FILE="${ENV_FILE}"
CONFIG_DATA_DIR="${DATA_DIR}"
LEGACY_OPT_ROOT="${LEGACY_OPT_ROOT:-/opt/AetherFlow}"
LEGACY_BIN_ROOT="${LEGACY_BIN_ROOT:-${CLI_BIN_DIR:-/usr/local/bin}/AetherFlow}"
SYS_BIN_DIR="${SYS_BIN_DIR:-/usr/bin}"
DRY_RUN_ROOT="${DRY_RUN_ROOT:-/tmp/aetherflow-dryrun}"
RESOLVED_DB_PATH=""
RESOLVED_DB_SOURCE=""
ENV_FILE_GITHUB_TOKEN=""
EFFECTIVE_SKIP_PROVENANCE_VERIFY="${AETHERFLOW_SKIP_PROVENANCE_VERIFY:-}"

is_trusted_root_env_file() {
    local target="$1"
    [[ -n "${target}" && -f "${target}" && ! -L "${target}" ]] || return 1
    command -v python3 >/dev/null 2>&1 || return 1
    python3 -I - "${target}" "${EFFECTIVE_RELEASE_ROOT:-}" <<'PY' >/dev/null 2>&1
import os, pathlib, stat, sys
target, isolated_root = sys.argv[1], sys.argv[2]
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)

p = pathlib.PurePosixPath(os.path.abspath(target))
if not p.is_absolute() or ".." in p.parts or len(p.parts) < 2:
    sys.exit(1)

confine = pathlib.PurePosixPath(isolated_root.rstrip("/") or "/") if isolated_root else None
if confine is not None:
    try:
        rel_parent = p.parent.relative_to(confine).parts
        anchor = pathlib.Path(str(confine))
    except ValueError:
        sys.exit(1)
else:
    rel_parent = p.parent.parts[1:]
    anchor = pathlib.Path("/")

cur_fd = os.open(str(anchor), os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
try:
    for part in rel_parent:
        nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
        os.close(cur_fd)
        cur_fd = nxt_fd
        if confine is None:
            dst = os.fstat(cur_fd)
            if not stat.S_ISDIR(dst.st_mode) or dst.st_uid != 0 or (dst.st_mode & 0o022) != 0:
                sys.exit(1)
    fd = os.open(p.parts[-1], os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=cur_fd)
finally:
    os.close(cur_fd)
try:
    st = os.fstat(fd)
finally:
    os.close(fd)
if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or (st.st_mode & 0o022) != 0:
    sys.exit(1)
if st.st_uid == 0:
    sys.exit(0)
if isolated_root and st.st_uid == os.geteuid():
    sys.exit(0)
sys.exit(1)
PY
}

write_atomic_private_file() {
    local dest_path="$1"
    local file_mode="$2"
    local content="$3"
    python3 -I - "${dest_path}" "${file_mode}" "${content}" "${EFFECTIVE_RELEASE_ROOT:-}" <<'PY'
import errno, os, pathlib, stat, sys, uuid

dest_path, mode_s, content, confine_raw = sys.argv[1:5]
mode = int(mode_s, 8) & 0o777
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)

p = pathlib.PurePosixPath(os.path.abspath(dest_path))
if not p.is_absolute() or ".." in p.parts or len(p.parts) < 2:
    raise SystemExit(f"Invalid destination file path: {dest_path}")
leaf = p.parts[-1]
if not leaf or leaf in (".", ".."):
    raise SystemExit(f"Invalid destination leaf name: {dest_path}")

confine = pathlib.PurePosixPath(confine_raw.rstrip("/") or "/") if confine_raw else None
if confine is not None:
    try:
        rel_parent = p.parent.relative_to(confine).parts
        anchor = pathlib.Path(str(confine))
    except ValueError:
        raise SystemExit(f"Path {dest_path} escapes isolated root {confine}")
else:
    rel_parent = p.parent.parts[1:]
    anchor = pathlib.Path("/")

cur_fd = os.open(str(anchor), os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
try:
    for part in rel_parent:
        nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
        os.close(cur_fd)
        cur_fd = nxt_fd
    try:
        existing = os.stat(leaf, dir_fd=cur_fd, follow_symlinks=False)
    except FileNotFoundError:
        existing = None
    if existing is not None and not stat.S_ISREG(existing.st_mode):
        raise SystemExit(f"Refusing non-regular or symlinked target file: {dest_path}")
    tmp_name = f".{leaf}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
    fd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode, dir_fd=cur_fd)
    try:
        data = content.encode("utf-8")
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError(f"short write to {dest_path}")
            view = view[written:]
        os.fchmod(fd, mode)
        os.fsync(fd)
    except Exception:
        os.close(fd)
        try:
            os.unlink(tmp_name, dir_fd=cur_fd)
        except OSError as rm_err:
            _ = rm_err
        raise
    os.close(fd)
    os.replace(tmp_name, leaf, src_dir_fd=cur_fd, dst_dir_fd=cur_fd)
    try:
        os.fsync(cur_fd)
    except OSError as exc:
        if exc.errno not in (errno.EINVAL, errno.EBADF, errno.EROFS):
            raise
finally:
    os.close(cur_fd)
PY
}

ensure_trusted_dry_run_tree() {
    local dry_root="$1"
    shift
    python3 -I - "${dry_root}" "${EFFECTIVE_RELEASE_ROOT:-}" "$@" <<'PY'
import os, pathlib, stat, sys

dry_root = sys.argv[1]
confine_raw = sys.argv[2]
subdirs = sys.argv[3:]
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
is_root = os.geteuid() == 0

p_root = pathlib.PurePosixPath(os.path.abspath(dry_root))
if not p_root.is_absolute() or ".." in p_root.parts or len(p_root.parts) < 2:
    raise SystemExit(f"Refusing invalid DRY_RUN_ROOT: {dry_root}")

confine = pathlib.PurePosixPath(confine_raw.rstrip("/") or "/") if confine_raw else None
if confine is not None:
    try:
        rel_root = p_root.relative_to(confine).parts
        anchor = pathlib.Path(str(confine))
    except ValueError:
        raise SystemExit(f"DRY_RUN_ROOT {dry_root} escapes isolated root {confine}")
else:
    rel_root = p_root.parts[1:]
    anchor = pathlib.Path("/")

def verify_root_dir_fd(fd, label):
    st = os.fstat(fd)
    if not stat.S_ISDIR(st.st_mode):
        raise SystemExit(f"Refusing non-directory dry-run path: {label}")
    if is_root:
        if st.st_uid != 0:
            raise SystemExit(f"Refusing non-root-owned dry-run directory (uid={st.st_uid}): {label}")
        if (st.st_mode & 0o022) != 0:
            raise SystemExit(f"Refusing group/world-writable root dry-run directory (mode={stat.S_IMODE(st.st_mode):o}): {label}")

cur_fd = os.open(str(anchor), os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
try:
    cur_path = anchor
    # Walk ancestors up to DRY_RUN_ROOT parent (root-owned, allowing sticky /tmp or /var/tmp when non-isolated).
    for part in rel_root[:-1]:
        cur_path = cur_path / part
        try:
            nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
        except FileNotFoundError:
            try:
                os.mkdir(part, 0o755, dir_fd=cur_fd)
            except FileExistsError as exists_err:
                _ = exists_err
            nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
        os.close(cur_fd)
        cur_fd = nxt_fd
        if is_root and confine is None:
            st = os.fstat(cur_fd)
            if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0:
                raise SystemExit(f"Refusing untrusted DRY_RUN_ROOT ancestor: {cur_path}")
            if (st.st_mode & 0o022) != 0 and (st.st_mode & stat.S_ISVTX) == 0:
                raise SystemExit(f"Refusing non-sticky writable DRY_RUN_ROOT ancestor: {cur_path}")

    root_leaf = rel_root[-1]
    cur_path = cur_path / root_leaf
    try:
        root_fd = os.open(root_leaf, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
    except FileNotFoundError:
        created_root = False
        try:
            os.mkdir(root_leaf, 0o700, dir_fd=cur_fd)
            created_root = True
        except FileExistsError as exists_err:
            _ = exists_err
        root_fd = os.open(root_leaf, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
        if created_root:
            os.fchmod(root_fd, 0o700)
    os.close(cur_fd)
    cur_fd = root_fd
    verify_root_dir_fd(cur_fd, str(cur_path))

    for spec in subdirs:
        rel_sub, mode_s = spec.split(":", 1)
        sub_mode = int(mode_s, 8) & 0o755
        sub_fd = os.dup(cur_fd)
        sub_path = cur_path
        try:
            for part in pathlib.PurePosixPath(rel_sub).parts:
                if part in ("", ".", "..", "/"):
                    raise SystemExit(f"Invalid dry-run subdir component: {rel_sub}")
                sub_path = sub_path / part
                try:
                    nxt = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=sub_fd)
                except FileNotFoundError:
                    created_sub = False
                    try:
                        os.mkdir(part, sub_mode, dir_fd=sub_fd)
                        created_sub = True
                    except FileExistsError as exists_err:
                        _ = exists_err
                    nxt = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=sub_fd)
                    if created_sub:
                        os.fchmod(nxt, sub_mode)
                os.close(sub_fd)
                sub_fd = nxt
                verify_root_dir_fd(sub_fd, str(sub_path))
        finally:
            os.close(sub_fd)
finally:
    os.close(cur_fd)
PY
}

# ── Dry-Run Override ─────────────────────────────────────────────────────────
# Writes stay under DRY_RUN_ROOT. CONFIG_ENV_FILE / CONFIG_DATA_DIR stay put
# so the live database can be resolved and copied with sqlite3 .backup.
if [[ "${DRY_RUN}" == true ]]; then
    RELEASES_DIR="${DRY_RUN_ROOT}/releases"
    CURRENT_LINK="${DRY_RUN_ROOT}/current"
    REPO_DIR="${DRY_RUN_ROOT}/repo"
    LEGACY_OPT_ROOT="${DRY_RUN_ROOT}/opt/AetherFlow"
    DATA_DIR="${DRY_RUN_ROOT}/data"
    ENV_DIR="${DRY_RUN_ROOT}/etc"
    ENV_FILE="${DRY_RUN_ROOT}/etc/aetherflow.env"
    LOG_FILE="${DRY_RUN_ROOT}/deploy.log"
    CLI_BIN_DIR="${DRY_RUN_ROOT}/usr/local/bin"
    LEGACY_BIN_ROOT="${CLI_BIN_DIR}/AetherFlow"
    SYS_BIN_DIR="${DRY_RUN_ROOT}/usr/bin"
    if ! ensure_trusted_dry_run_tree "${DRY_RUN_ROOT}" \
        "releases:0755" "repo:0755" "opt/AetherFlow:0755" "data:0700" "etc:0750" "usr/local/bin:0755" "usr/bin:0755"; then
        echo "[FATAL] Refusing untrusted or symlinked DRY_RUN_ROOT: ${DRY_RUN_ROOT}" >&2
        exit 4
    fi
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
        python3 -I - "${LOG_FILE}" "${line}" <<'PY' || return 1
import fcntl, os, stat, sys

target, line = sys.argv[1], sys.argv[2]
parent = os.path.dirname(target) or "."
pst = os.lstat(parent)
if stat.S_ISLNK(pst.st_mode) or not stat.S_ISDIR(pst.st_mode):
    raise SystemExit(1)
flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
fd = os.open(target, flags, 0o640)
try:
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
        raise SystemExit(1)
    if hasattr(os, "O_NONBLOCK"):
        cur_fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, cur_fl & ~os.O_NONBLOCK)
    fcntl.flock(fd, fcntl.LOCK_SH)
    try:
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
    [[ -f "${file}" && ! -L "${file}" ]] || return 1

    if command -v python3 >/dev/null 2>&1; then
        python3 -I - "${file}" "${key}" "${EFFECTIVE_RELEASE_ROOT:-}" <<'PY'
import os, pathlib, stat, sys

path, target_key = sys.argv[1], sys.argv[2]
confine_root_raw = sys.argv[3] if len(sys.argv) > 3 else ""
prefix = target_key + "="
MAX_ENV_BYTES = 262144
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
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
    p = pathlib.PurePosixPath(os.path.abspath(path))
    if ".." in p.parts or len(p.parts) < 2:
        sys.exit(1)
    confine = pathlib.PurePosixPath(confine_root_raw.rstrip("/") or "/") if confine_root_raw else None
    if confine is not None:
        try:
            rel_parent = p.parent.relative_to(confine).parts
            anchor = pathlib.Path(str(confine))
        except ValueError:
            rel_parent = p.parent.parts[1:]
            anchor = pathlib.Path("/")
    else:
        rel_parent = p.parent.parts[1:]
        anchor = pathlib.Path("/")
    cur_fd = os.open(str(anchor), os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    try:
        for part in rel_parent:
            nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
            os.close(cur_fd)
            cur_fd = nxt_fd
        fd = os.open(p.parts[-1], os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=cur_fd)
    finally:
        os.close(cur_fd)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_size > MAX_ENV_BYTES:
            sys.exit(1)
        chunks = []
        total = 0
        while True:
            chunk = os.read(fd, 8192)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ENV_BYTES:
                sys.exit(1)
            chunks.append(chunk)
        content = b"".join(chunks).decode("utf-8")
    finally:
        os.close(fd)
    for raw_line in content.splitlines():
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

# Unified loading of HEALTH_ENDPOINT, GitHub tokens, and root-only provenance bypass
# from CONFIG_ENV_FILE (/etc/aetherflow/aetherflow.env) when AETHERFLOW_SKIP_ENV_FILES!=1:
# process env > explicit --config > CONFIG_ENV_FILE > default-fallback --config > compiled default.
apply_unified_env_file_overrides() {
    [[ "${AETHERFLOW_SKIP_ENV_FILES:-0}" != "1" ]] || return 0
    [[ -n "${CONFIG_ENV_FILE:-}" && -f "${CONFIG_ENV_FILE}" && ! -L "${CONFIG_ENV_FILE}" ]] || return 0

    if [[ "${HEALTH_ENDPOINT_EXPLICIT:-false}" != "true" ]]; then
        local env_health=""
        env_health="$(read_env_file_value "${CONFIG_ENV_FILE}" "HEALTH_ENDPOINT" || true)"
        if [[ -n "${env_health}" ]]; then
            HEALTH_ENDPOINT="${env_health}"
        fi
    fi

    local tok_key="" tok_val=""
    for tok_key in AF_GITHUB_TOKEN GITHUB_TOKEN GH_TOKEN; do
        tok_val="$(read_env_file_value "${CONFIG_ENV_FILE}" "${tok_key}" || true)"
        if [[ -n "${tok_val}" ]]; then
            ENV_FILE_GITHUB_TOKEN="${tok_val}"
            break
        fi
    done

    if [[ -z "${EFFECTIVE_SKIP_PROVENANCE_VERIFY}" ]] && is_trusted_root_env_file "${CONFIG_ENV_FILE}"; then
        local env_skip=""
        env_skip="$(read_env_file_value "${CONFIG_ENV_FILE}" "AETHERFLOW_SKIP_PROVENANCE_VERIFY" || true)"
        if [[ -n "${env_skip}" ]]; then
            EFFECTIVE_SKIP_PROVENANCE_VERIFY="${env_skip}"
        fi
    fi
}
apply_unified_env_file_overrides

# `systemctl show -p Environment` prints one or more `Environment=K=V K2=V2`
# lines. Values may be quoted. Missing systemctl or a missing unit yields nothing.
read_systemd_environment_value() {
    local key="$1"
    local blob="$2"
    [[ -n "${blob}" ]] || return 1

    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "${blob}" | python3 -I -c '
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
        if [[ "${AETHERFLOW_SKIP_ENV_FILES:-0}" != "1" || "${CONFIG_ENV_FILE}" != "/etc/aetherflow/aetherflow.env" ]]; then
            file_af="$(read_env_file_value "${CONFIG_ENV_FILE}" "AF_DB_PATH" || true)"
            file_db="$(read_env_file_value "${CONFIG_ENV_FILE}" "DB_PATH" || true)"
            file_alias="$(read_env_file_value "${CONFIG_ENV_FILE}" "AETHERFLOW_DB_PATH" || true)"
        fi

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
            if [[ -n "${unit_blob}" ]] && val="$(read_systemd_environment_value "AF_DB_PATH" "${unit_blob}")"; then
                RESOLVED_DB_PATH="${val}"
                RESOLVED_DB_SOURCE="systemd:aetherflow-api:AF_DB_PATH"
            elif [[ -n "${unit_blob}" ]] && val="$(read_systemd_environment_value "DB_PATH" "${unit_blob}")"; then
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

atomic_publish_db_file() {
    local mode="$1"      # "backup" (service-owned 0600), "snapshot" (root-owned 0600), or "restore" (service-owned 0600 + quarantine)
    local src_path="$2"
    local dest_path="$3"
    local lock_leaf="${4:-}"
    local lock_timeout="${5:-30}"
    python3 -I - "${mode}" "${src_path}" "${dest_path}" "${EFFECTIVE_RELEASE_ROOT:-}" "${lock_leaf}" "${lock_timeout}" <<'PY'
import errno, fcntl, os, pathlib, pwd, shutil, sqlite3, stat, subprocess, sys, time, uuid

mode, src_path, dest_path, confine_root_raw, lock_leaf, lock_timeout_raw = sys.argv[1:7]
lock_timeout = max(1, int(lock_timeout_raw or "30"))
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
is_root = os.geteuid() == 0

def open_dir_nofollow(dir_str, create=False):
    p = pathlib.PurePosixPath(os.path.abspath(dir_str))
    if ".." in p.parts:
        raise SystemExit(f"Refusing parent traversal in DB directory: {dir_str}")
    confine = pathlib.PurePosixPath(confine_root_raw.rstrip("/") or "/") if confine_root_raw else None
    if confine is not None:
        try:
            rel_parts = p.relative_to(confine).parts
            anchor = pathlib.Path(str(confine))
        except ValueError:
            raise SystemExit(f"DB directory {dir_str} escapes isolated root {confine}")
        if create and not os.path.lexists(anchor):
            os.makedirs(anchor, mode=0o755, exist_ok=True)
    else:
        rel_parts = p.parts[1:]
        anchor = pathlib.Path("/")
    cur_fd = os.open(str(anchor), os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    cur = anchor
    try:
        for part in rel_parts:
            cur = cur / part
            try:
                nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
            except FileNotFoundError:
                if not create:
                    raise SystemExit(f"DB directory does not exist: {cur}")
                created_dir = False
                try:
                    os.mkdir(part, 0o700, dir_fd=cur_fd)
                    created_dir = True
                except FileExistsError as exists_err:
                    _ = exists_err
                nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
                if created_dir:
                    os.fchmod(nxt_fd, 0o700)
            except OSError as exc:
                raise SystemExit(f"Refusing symlinked or non-directory DB parent path {cur}: {exc}")
            os.close(cur_fd)
            cur_fd = nxt_fd
        return cur_fd
    except Exception:
        os.close(cur_fd)
        raise

dest_abs = os.path.abspath(dest_path)
parent_str = os.path.dirname(dest_abs)
leaf_name = os.path.basename(dest_abs)
if not leaf_name or leaf_name in (".", ".."):
    raise SystemExit(f"Invalid DB destination path: {dest_path}")

parent_fd = open_dir_nofollow(parent_str, create=True)
lock_fd = -1
stage_base_fd = -1
stage_fd = -1
stage_name = f".af-db-stage.{os.getpid()}.{uuid.uuid4().hex}"
stage_path = None
try:
    parent_st = os.fstat(parent_fd)
    if not stat.S_ISDIR(parent_st.st_mode):
        raise SystemExit(f"DB parent is not a directory: {parent_str}")
    if lock_leaf:
        if "/" in lock_leaf or lock_leaf in (".", ".."):
            raise SystemExit(f"Invalid snapshot lock filename: {lock_leaf}")
        lock_fd = os.open(lock_leaf, os.O_RDWR | os.O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0o600, dir_fd=parent_fd)
        lst = os.fstat(lock_fd)
        if not stat.S_ISREG(lst.st_mode) or lst.st_nlink != 1:
            raise SystemExit(f"Refusing non-regular or hardlinked snapshot lock file: {lock_leaf}")
        os.fchmod(lock_fd, 0o600)
        deadline = time.monotonic() + float(lock_timeout)
        while True:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise SystemExit(f"Timed out acquiring snapshot lock {lock_leaf} after {lock_timeout}s")
                time.sleep(0.05)

    # Prefer nearest same-FS root-owned non-group/world-writable ancestor when root writes into
    # an unprivileged service directory (matching PrivateStagingDir in af-release/src/fs_security.rs).
    chosen_base = None
    if is_root and parent_st.st_uid != 0:
        cur_anc = pathlib.Path(parent_str).parent
        while str(cur_anc) != str(cur_anc.parent) or str(cur_anc) == "/":
            anc_fd = -1
            try:
                anc_fd = open_dir_nofollow(str(cur_anc), create=False)
                anc_st = os.fstat(anc_fd)
                if anc_st.st_dev != parent_st.st_dev:
                    os.close(anc_fd)
                    anc_fd = -1
                    break
                if anc_st.st_uid == 0 and (anc_st.st_mode & 0o022) == 0:
                    os.mkdir(stage_name, 0o700, dir_fd=anc_fd)
                    chosen_base = (anc_fd, str(cur_anc))
                    anc_fd = -1
                    break
            except OSError:
                if anc_fd >= 0:
                    os.close(anc_fd)
                    anc_fd = -1
                break
            if anc_fd >= 0:
                os.close(anc_fd)
            if str(cur_anc) == "/":
                break
            cur_anc = cur_anc.parent

    if chosen_base is not None:
        stage_base_fd, base_str = chosen_base
    else:
        os.mkdir(stage_name, 0o700, dir_fd=parent_fd)
        stage_base_fd = os.dup(parent_fd)
        base_str = parent_str

    stage_path = os.path.join(base_str, stage_name)
    stage_fd = os.open(stage_name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=stage_base_fd)
    stage_st = os.fstat(stage_fd)
    expected_uid = 0 if is_root else os.geteuid()
    if not stat.S_ISDIR(stage_st.st_mode) or stage_st.st_dev != parent_st.st_dev or stage_st.st_uid != expected_uid:
        raise SystemExit(f"Private staging directory failed same-FS/owner invariants: {stage_path}")
    os.fchmod(stage_fd, 0o700)

    def is_trusted_root_path_dir(dir_str, allow_sticky):
        dp = pathlib.PurePosixPath(os.path.abspath(dir_str))
        if not dp.is_absolute() or ".." in dp.parts:
            return False
        cur_p = pathlib.Path("/")
        for part in dp.parts:
            cur_p = pathlib.Path("/") if part == "/" else cur_p / part
            try:
                cst = os.lstat(cur_p)
            except OSError:
                return False
            if stat.S_ISLNK(cst.st_mode) or not stat.S_ISDIR(cst.st_mode) or cst.st_uid != 0:
                return False
            writable = (cst.st_mode & 0o022) != 0
            sticky = (cst.st_mode & getattr(stat, "S_ISVTX", 0o1000)) != 0
            if writable and not (allow_sticky and sticky):
                return False
        return True

    MAX_SCRATCH_BYTES = 2 * 1024 * 1024 * 1024

    def create_trusted_root_scratch(min_free=16 * 1024 * 1024):
        sc_name = f".af-root-db-stage.{os.getpid()}.{uuid.uuid4().hex}"
        candidates = ("/var/tmp", "/tmp", "/run") if is_root else (os.environ.get("TMPDIR", "/tmp"),)
        for cand in candidates:
            if is_root and not is_trusted_root_path_dir(cand, allow_sticky=True):
                continue
            cand_fd = -1
            try:
                cand_fd = os.open(cand, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                vfs = os.fstatvfs(cand_fd)
                avail = vfs.f_bavail * (vfs.f_frsize or vfs.f_bsize)
                if avail < min_free:
                    os.close(cand_fd)
                    continue
                os.mkdir(sc_name, 0o700, dir_fd=cand_fd)
                sc_fd = os.open(sc_name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cand_fd)
                sc_st = os.fstat(sc_fd)
                if not stat.S_ISDIR(sc_st.st_mode) or sc_st.st_uid != expected_uid:
                    os.close(sc_fd)
                    os.rmdir(sc_name, dir_fd=cand_fd)
                    os.close(cand_fd)
                    continue
                os.fchmod(sc_fd, 0o700)
                return cand_fd, sc_fd, sc_name, os.path.join(cand, sc_name)
            except OSError:
                if cand_fd >= 0:
                    os.close(cand_fd)
        raise SystemExit("Failed to create trusted root-owned 0700 scratch directory for SQLite backup")

    SQLITE_JOURNAL_MAGIC = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"

    def reject_super_journal_fd(fd, label_path):
        st = os.fstat(fd)
        if st.st_size >= 16:
            os.lseek(fd, -8, os.SEEK_END)
            tail = os.read(fd, 8)
            os.lseek(fd, 0, os.SEEK_SET)
            if tail == SQLITE_JOURNAL_MAGIC:
                raise SystemExit(f"Refusing SQLite rollback journal with super-journal trailer: {label_path}")

    def copy_fd_to_dirfd(in_fd, out_dir_fd, out_name, remaining_cap=None):
        out_fd = os.open(out_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600, dir_fd=out_dir_fd)
        copied = 0
        tail8 = b""
        try:
            while True:
                chunk = os.read(in_fd, 65536)
                if not chunk:
                    break
                copied += len(chunk)
                if remaining_cap is not None and copied > remaining_cap:
                    raise SystemExit(f"SQLite scratch copy exceeded {MAX_SCRATCH_BYTES} byte limit")
                tail8 = (tail8 + chunk)[-8:]
                view = memoryview(chunk)
                while view:
                    written = os.write(out_fd, view)
                    if written <= 0:
                        raise OSError(f"short write staging {out_name}")
                    view = view[written:]
            if out_name.endswith("-journal") and copied >= 16 and tail8 == SQLITE_JOURNAL_MAGIC:
                raise SystemExit(f"Refusing SQLite rollback journal with super-journal trailer: {out_name}")
            return None if remaining_cap is None else (remaining_cap - copied)
        finally:
            os.close(out_fd)

    staged_ext = ".bak" if leaf_name.endswith(".bak") else ".sqlite"
    staged_name = f"staged.{uuid.uuid4().hex}{staged_ext}"
    staged_full = os.path.join(stage_path, staged_name)
    stage_path_safe_for_root = (not is_root) or is_trusted_root_path_dir(base_str, allow_sticky=True)

    def py_sqlite_backup_and_check(src_file, dst_file, readonly_src=False):
        src_uri = pathlib.Path(src_file).as_uri() + ("?mode=ro" if readonly_src else "")
        src_conn = sqlite3.connect(src_uri, uri=True, timeout=5)
        try:
            src_conn.execute("PRAGMA trusted_schema = OFF;")
            dst_conn = sqlite3.connect(dst_file, timeout=5)
            try:
                dst_conn.execute("PRAGMA trusted_schema = OFF;")
                src_conn.backup(dst_conn)
                dst_conn.commit()
            finally:
                dst_conn.close()
        finally:
            src_conn.close()

    def py_sqlite_integrity_ok(target_file):
        conn = sqlite3.connect(pathlib.Path(target_file).as_uri() + "?mode=ro", uri=True, timeout=5)
        try:
            conn.execute("PRAGMA trusted_schema = OFF;")
            row = conn.execute("PRAGMA integrity_check;").fetchone()
            return "".join((row[0] if row and row[0] else "").split())
        finally:
            conn.close()

    if mode == "placeholder":
        placeholder_sql = "CREATE TABLE IF NOT EXISTS _meta (key TEXT, value TEXT); INSERT INTO _meta VALUES ('version','dryrun');"
        if stage_path_safe_for_root:
            init_fd = os.open(staged_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600, dir_fd=stage_fd)
            os.close(init_fd)
            pconn = sqlite3.connect(staged_full, timeout=5)
            try:
                pconn.execute("PRAGMA trusted_schema = OFF;")
                pconn.executescript(placeholder_sql)
                pconn.commit()
            finally:
                pconn.close()
        else:
            sc_base_fd, sc_fd, sc_name, sc_path = create_trusted_root_scratch(16 * 1024 * 1024)
            try:
                sc_init = os.open(staged_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600, dir_fd=sc_fd)
                os.close(sc_init)
                pconn = sqlite3.connect(os.path.join(sc_path, staged_name), timeout=5)
                try:
                    pconn.execute("PRAGMA trusted_schema = OFF;")
                    pconn.executescript(placeholder_sql)
                    pconn.commit()
                finally:
                    pconn.close()
                sc_vfd = os.open(staged_name, os.O_RDONLY | O_NOFOLLOW | O_CLOEXEC, dir_fd=sc_fd)
                try:
                    sc_vst = os.fstat(sc_vfd)
                    if not stat.S_ISREG(sc_vst.st_mode) or sc_vst.st_nlink != 1 or sc_vst.st_size < 100:
                        raise SystemExit("Staged SQLite placeholder failed size/exclusivity invariant")
                    if os.read(sc_vfd, 16) != b"SQLite format 3\x00":
                        raise SystemExit("Staged SQLite placeholder failed SQLite header verification")
                    os.lseek(sc_vfd, 0, os.SEEK_SET)
                    copy_fd_to_dirfd(sc_vfd, stage_fd, staged_name)
                finally:
                    os.close(sc_vfd)
            finally:
                for sc_left in (staged_name, staged_name + "-wal", staged_name + "-shm", staged_name + "-journal"):
                    try:
                        os.unlink(sc_left, dir_fd=sc_fd)
                    except FileNotFoundError:
                        _ = sc_left
                os.close(sc_fd)
                try:
                    os.rmdir(sc_name, dir_fd=sc_base_fd)
                except OSError:
                    _ = sc_name
                os.close(sc_base_fd)
    else:
        src_abs = os.path.abspath(src_path)
        src_parent_str = os.path.dirname(src_abs)
        src_leaf_name = os.path.basename(src_abs)

        def db_files_root_owned_safe(pfd, lname):
            for sfx in ("", "-wal", "-shm", "-journal"):
                try:
                    fst = os.stat(lname + sfx, dir_fd=pfd, follow_symlinks=False)
                except FileNotFoundError:
                    fst = None
                if fst is not None and (fst.st_uid != 0 or (fst.st_mode & 0o022) != 0):
                    return False
            return True

        # Validate source is a regular non-symlink file before reading/backing up (create=False!).
        src_parent_fd = open_dir_nofollow(src_parent_str, create=False)
        src_path_safe_for_root = (not is_root) or (
            is_trusted_root_path_dir(src_parent_str, allow_sticky=False)
            and db_files_root_owned_safe(src_parent_fd, src_leaf_name)
        )
        src_fd = -1
        try:
            src_fd = os.open(src_leaf_name, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=src_parent_fd)
            src_st = os.fstat(src_fd)
            if not stat.S_ISREG(src_st.st_mode) or src_st.st_nlink != 1:
                raise SystemExit(f"Refusing non-regular or hardlinked source DB file: {src_path}")
            if mode in ("backup", "snapshot") and (is_root or shutil.which("sqlite3")):
                if stage_path_safe_for_root and src_path_safe_for_root:
                    try:
                        jcheck_fd = os.open(src_leaf_name + "-journal", os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=src_parent_fd)
                    except FileNotFoundError:
                        jcheck_fd = -1
                    if jcheck_fd >= 0:
                        try:
                            jst = os.fstat(jcheck_fd)
                            if not stat.S_ISREG(jst.st_mode) or jst.st_nlink != 1:
                                raise SystemExit(f"Refusing non-regular or hardlinked source -journal sidecar for {src_path}")
                            reject_super_journal_fd(jcheck_fd, src_path)
                        finally:
                            os.close(jcheck_fd)
                    init_fd = os.open(staged_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600, dir_fd=stage_fd)
                    os.close(init_fd)
                    os.close(src_fd)
                    src_fd = -1
                    if is_root:
                        # Never invoke the sqlite3 CLI binary as root (shell.c registers edit() without DIRECTONLY).
                        py_sqlite_backup_and_check(src_abs, staged_full, readonly_src=True)
                    else:
                        res = subprocess.run(
                            ["sqlite3", "--readonly", src_abs, f".backup '{staged_name}'"],
                            cwd=stage_path,
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        if res.returncode != 0:
                            raise SystemExit(f"sqlite3 backup failed: {res.stderr.strip()}")
                else:
                    # Never pass an unprivileged-writable staging path or swappable source path to
                    # root SQLite: run via libsqlite3 (Python sqlite3, PRAGMA trusted_schema = OFF)
                    # inside a guaranteed root-owned 0700 scratch directory and stream-copy strictly
                    # via open FDs into `stage_fd`.
                    last_err = "sqlite3 isolated backup failed"
                    copied_to_stage = False
                    for attempt in range(3):
                        wal_fd = -1
                        jrn_fd = -1
                        req_bytes = src_st.st_size
                        if not src_path_safe_for_root:
                            if attempt > 0:
                                if src_fd >= 0:
                                    os.close(src_fd)
                                    src_fd = -1
                                src_fd = os.open(src_leaf_name, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=src_parent_fd)
                                src_st = os.fstat(src_fd)
                                if not stat.S_ISREG(src_st.st_mode) or src_st.st_nlink != 1:
                                    raise SystemExit(f"Refusing non-regular or hardlinked source DB file: {src_path}")
                                req_bytes = src_st.st_size
                            else:
                                os.lseek(src_fd, 0, os.SEEK_SET)
                            for suffix in ("-wal", "-shm", "-journal"):
                                try:
                                    sfd = os.open(src_leaf_name + suffix, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=src_parent_fd)
                                except FileNotFoundError:
                                    continue
                                except OSError as werr:
                                    raise SystemExit(f"Refusing untrusted source {suffix} sidecar for {src_path}: {werr}")
                                sst = os.fstat(sfd)
                                if not stat.S_ISREG(sst.st_mode) or sst.st_nlink != 1:
                                    os.close(sfd)
                                    raise SystemExit(f"Refusing non-regular or hardlinked source {suffix} sidecar for {src_path}")
                                if suffix == "-wal":
                                    wal_fd = sfd
                                    req_bytes += sst.st_size
                                elif suffix == "-journal":
                                    jrn_fd = sfd
                                    req_bytes += sst.st_size
                                else:
                                    os.close(sfd)
                            if req_bytes > MAX_SCRATCH_BYTES:
                                for fd_c in (wal_fd, jrn_fd):
                                    if fd_c >= 0:
                                        os.close(fd_c)
                                raise SystemExit(f"Source SQLite database exceeds {MAX_SCRATCH_BYTES} byte scratch cap")
                        sc_base_fd, sc_fd, sc_name, sc_path = create_trusted_root_scratch(req_bytes * 2 + 16 * 1024 * 1024)
                        try:
                            sc_staged = os.path.join(sc_path, staged_name)
                            sc_init = os.open(staged_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600, dir_fd=sc_fd)
                            os.close(sc_init)
                            backup_ok = False
                            if src_path_safe_for_root:
                                try:
                                    jcheck_fd = os.open(src_leaf_name + "-journal", os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=src_parent_fd)
                                except FileNotFoundError:
                                    jcheck_fd = -1
                                if jcheck_fd >= 0:
                                    try:
                                        jst = os.fstat(jcheck_fd)
                                        if not stat.S_ISREG(jst.st_mode) or jst.st_nlink != 1:
                                            raise SystemExit(f"Refusing non-regular or hardlinked source -journal sidecar for {src_path}")
                                        reject_super_journal_fd(jcheck_fd, src_path)
                                    finally:
                                        os.close(jcheck_fd)
                                try:
                                    py_sqlite_backup_and_check(src_abs, sc_staged, readonly_src=True)
                                    backup_ok = True
                                except Exception as b_err:
                                    last_err = f"sqlite3 backup failed: {b_err}"
                            else:
                                rem_cap = copy_fd_to_dirfd(src_fd, sc_fd, "src.sqlite", MAX_SCRATCH_BYTES)
                                if wal_fd >= 0:
                                    rem_cap = copy_fd_to_dirfd(wal_fd, sc_fd, "src.sqlite-wal", rem_cap)
                                if jrn_fd >= 0:
                                    copy_fd_to_dirfd(jrn_fd, sc_fd, "src.sqlite-journal", rem_cap)
                                try:
                                    py_sqlite_backup_and_check(os.path.join(sc_path, "src.sqlite"), sc_staged, readonly_src=False)
                                    backup_ok = True
                                except Exception as b_err:
                                    last_err = f"sqlite3 backup failed: {b_err}"
                            if backup_ok:
                                try:
                                    ic_line = py_sqlite_integrity_ok(sc_staged)
                                except Exception as ic_err:
                                    ic_line = f"error: {ic_err}"
                                if ic_line == "ok":
                                    sc_vfd = os.open(staged_name, os.O_RDONLY | O_NOFOLLOW | O_CLOEXEC, dir_fd=sc_fd)
                                    try:
                                        sc_vst = os.fstat(sc_vfd)
                                        if not stat.S_ISREG(sc_vst.st_mode) or sc_vst.st_nlink != 1 or sc_vst.st_size < 100:
                                            raise SystemExit("Staged SQLite backup failed size/exclusivity invariant")
                                        hdr = os.read(sc_vfd, 16)
                                        if hdr != b"SQLite format 3\x00":
                                            raise SystemExit("Staged SQLite backup failed SQLite header verification")
                                        os.lseek(sc_vfd, 0, os.SEEK_SET)
                                        copy_fd_to_dirfd(sc_vfd, stage_fd, staged_name)
                                        copied_to_stage = True
                                        break
                                    finally:
                                        os.close(sc_vfd)
                                else:
                                    last_err = f"sqlite3 integrity check failed on isolated backup: {ic_line}"
                        finally:
                            for fd_c in (wal_fd, jrn_fd):
                                if fd_c >= 0:
                                    os.close(fd_c)
                            for sc_left in ("src.sqlite", "src.sqlite-wal", "src.sqlite-shm", "src.sqlite-journal", staged_name, staged_name + "-wal", staged_name + "-shm", staged_name + "-journal"):
                                try:
                                    os.unlink(sc_left, dir_fd=sc_fd)
                                except FileNotFoundError:
                                    _ = sc_left
                            os.close(sc_fd)
                            try:
                                os.rmdir(sc_name, dir_fd=sc_base_fd)
                            except OSError:
                                _ = sc_name
                            os.close(sc_base_fd)
                        if attempt < 2:
                            time.sleep(0.025)
                    if not copied_to_stage:
                        raise SystemExit(last_err)
            else:
                copy_fd_to_dirfd(src_fd, stage_fd, staged_name)
        finally:
            if src_fd >= 0:
                os.close(src_fd)
            os.close(src_parent_fd)

    # Remove any SQLite sidecars inside stage dir so cleanup rmdir succeeds.
    for suffix in ("-wal", "-shm", "-journal"):
        try:
            os.unlink(staged_name + suffix, dir_fd=stage_fd)
        except FileNotFoundError:
            _ = suffix

    # Apply target ownership + 0600 + fsync directly on the open staged FD BEFORE publishing.
    verify_fd = os.open(staged_name, os.O_RDONLY | O_NOFOLLOW | O_CLOEXEC, dir_fd=stage_fd)
    try:
        vst = os.fstat(verify_fd)
        if not stat.S_ISREG(vst.st_mode) or vst.st_nlink != 1:
            raise SystemExit(f"Staged DB file is not an exclusive regular file: {staged_full}")
        if mode in ("backup", "snapshot", "placeholder"):
            if vst.st_size < 100 or os.read(verify_fd, 16) != b"SQLite format 3\x00":
                raise SystemExit(f"Staged DB backup failed SQLite format 3 header/size check: {staged_full}")
        if is_root:
            if mode in ("snapshot", "placeholder"):
                os.fchown(verify_fd, 0, 0)
            else:
                try:
                    af_pw = pwd.getpwnam("aetherflow")
                except KeyError:
                    af_pw = None
                if af_pw is not None:
                    os.fchown(verify_fd, af_pw.pw_uid, af_pw.pw_gid)
        os.fchmod(verify_fd, 0o600)
        os.fsync(verify_fd)
    finally:
        os.close(verify_fd)

    # Handle existing leaf safely on parent_fd without ever following symlinks.
    try:
        leaf_st = os.stat(leaf_name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        leaf_st = None
    quarantine_name = None
    if leaf_st is not None:
        if stat.S_ISDIR(leaf_st.st_mode) and not stat.S_ISLNK(leaf_st.st_mode):
            raise SystemExit(f"Refusing to overwrite directory at DB path: {dest_path}")
        elif stat.S_ISREG(leaf_st.st_mode) and mode == "restore":
            quarantine_name = f"{leaf_name}.corrupted.{int(time.time())}.{uuid.uuid4()}"
            os.replace(leaf_name, quarantine_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        elif not stat.S_ISREG(leaf_st.st_mode):
            # Symlink (including symlink to root directory or dangling symlink) or special file.
            os.unlink(leaf_name, dir_fd=parent_fd)

    try:
        os.replace(staged_name, leaf_name, src_dir_fd=stage_fd, dst_dir_fd=parent_fd)
    except OSError:
        if quarantine_name is not None:
            try:
                os.replace(quarantine_name, leaf_name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            except OSError as rev_err:
                _ = rev_err
        raise
    # Remove stale WAL/SHM/journal sidecars in parent_fd ONLY after atomic replace succeeds.
    for suffix in ("-wal", "-shm", "-journal"):
        try:
            os.unlink(leaf_name + suffix, dir_fd=parent_fd)
        except (FileNotFoundError, IsADirectoryError):
            _ = suffix
    try:
        os.fsync(parent_fd)
    except OSError as exc:
        if exc.errno not in (errno.EINVAL, errno.EBADF, errno.EROFS):
            raise
finally:
    if stage_fd >= 0:
        for leftover in (staged_name, staged_name + "-wal", staged_name + "-shm", staged_name + "-journal"):
            try:
                os.unlink(leftover, dir_fd=stage_fd)
            except FileNotFoundError:
                _ = leftover
        os.close(stage_fd)
    if stage_base_fd >= 0:
        try:
            os.rmdir(stage_name, dir_fd=stage_base_fd)
        except OSError as rm_err:
            if rm_err.errno != errno.ENOENT:
                sys.stderr.write(f"warning: failed to remove staging dir {stage_path}: {rm_err}\n")
        os.close(stage_base_fd)
    if lock_fd >= 0:
        os.close(lock_fd)
    os.close(parent_fd)
PY
}

sqlite_online_backup() {
    local src="$1"
    local dest="$2"
    atomic_publish_db_file "snapshot" "${src}" "${dest}"
}

sqlite_integrity() {
    local db="$1"
    local result=""
    result="$(python3 -I - "${db}" "${EFFECTIVE_RELEASE_ROOT:-}" <<'PY'
import os, pathlib, shutil, sqlite3, stat, subprocess, sys, time, uuid

db_path, confine_root_raw = sys.argv[1:3]
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
is_root = os.geteuid() == 0

def open_dir_nofollow(dir_str):
    p = pathlib.PurePosixPath(os.path.abspath(dir_str))
    if ".." in p.parts:
        return -1
    confine = pathlib.PurePosixPath(confine_root_raw.rstrip("/") or "/") if confine_root_raw else None
    if confine is not None:
        try:
            rel_parts = p.relative_to(confine).parts
            anchor = pathlib.Path(str(confine))
        except ValueError:
            rel_parts = p.parts[1:]
            anchor = pathlib.Path("/")
    else:
        rel_parts = p.parts[1:]
        anchor = pathlib.Path("/")
    try:
        cur_fd = os.open(str(anchor), os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    except OSError:
        return -1
    try:
        for part in rel_parts:
            nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
            os.close(cur_fd)
            cur_fd = nxt_fd
        return cur_fd
    except OSError:
        os.close(cur_fd)
        return -1

def is_trusted_root_path_dir(dir_str, allow_sticky):
    dp = pathlib.PurePosixPath(os.path.abspath(dir_str))
    if not dp.is_absolute() or ".." in dp.parts:
        return False
    cur_p = pathlib.Path("/")
    for part in dp.parts:
        cur_p = pathlib.Path("/") if part == "/" else cur_p / part
        try:
            cst = os.lstat(cur_p)
        except OSError:
            return False
        if stat.S_ISLNK(cst.st_mode) or not stat.S_ISDIR(cst.st_mode) or cst.st_uid != 0:
            return False
        writable = (cst.st_mode & 0o022) != 0
        sticky = (cst.st_mode & getattr(stat, "S_ISVTX", 0o1000)) != 0
        if writable and not (allow_sticky and sticky):
            return False
    return True

MAX_SCRATCH_BYTES = 2 * 1024 * 1024 * 1024
SQLITE_JOURNAL_MAGIC = b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7"

def has_super_journal_trailer(fd):
    st = os.fstat(fd)
    if st.st_size < 16:
        return False
    os.lseek(fd, -8, os.SEEK_END)
    tail = os.read(fd, 8)
    os.lseek(fd, 0, os.SEEK_SET)
    return tail == SQLITE_JOURNAL_MAGIC

def copy_fd(in_fd, out_dir_fd, out_name, remaining_cap):
    out_fd = os.open(out_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600, dir_fd=out_dir_fd)
    copied = 0
    tail8 = b""
    try:
        while True:
            chunk = os.read(in_fd, 65536)
            if not chunk:
                break
            copied += len(chunk)
            if copied > remaining_cap:
                raise OSError("scratch copy cap exceeded")
            tail8 = (tail8 + chunk)[-8:]
            view = memoryview(chunk)
            while view:
                w = os.write(out_fd, view)
                if w <= 0:
                    raise OSError("short write")
                view = view[w:]
        if out_name.endswith("-journal") and copied >= 16 and tail8 == SQLITE_JOURNAL_MAGIC:
            raise OSError("forbidden SQLite super-journal trailer")
        return remaining_cap - copied
    finally:
        os.close(out_fd)

def create_root_scratch(min_free=16 * 1024 * 1024):
    sc_name = f".af-root-ic.{os.getpid()}.{uuid.uuid4().hex}"
    for cand in ("/var/tmp", "/tmp", "/run"):
        if not is_trusted_root_path_dir(cand, allow_sticky=True):
            continue
        cand_fd = -1
        try:
            cand_fd = os.open(cand, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            vfs = os.fstatvfs(cand_fd)
            avail = vfs.f_bavail * (vfs.f_frsize or vfs.f_bsize)
            if avail < min_free:
                os.close(cand_fd)
                continue
            os.mkdir(sc_name, 0o700, dir_fd=cand_fd)
            sc_fd = os.open(sc_name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cand_fd)
            if not stat.S_ISDIR(os.fstat(sc_fd).st_mode) or os.fstat(sc_fd).st_uid != 0:
                os.close(sc_fd)
                os.rmdir(sc_name, dir_fd=cand_fd)
                os.close(cand_fd)
                continue
            os.fchmod(sc_fd, 0o700)
            return cand_fd, sc_fd, sc_name, os.path.join(cand, sc_name)
        except OSError:
            if cand_fd >= 0:
                os.close(cand_fd)
    return None

db_abs = os.path.abspath(db_path)
parent_str = os.path.dirname(db_abs)
leaf_name = os.path.basename(db_abs)
parent_fd = open_dir_nofollow(parent_str)
if parent_fd < 0:
    sys.stdout.write("error")
    sys.exit(0)

try:
    try:
        db_fd = os.open(leaf_name, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=parent_fd)
    except FileNotFoundError:
        sys.stdout.write("missing")
        sys.exit(0)
    except OSError:
        sys.stdout.write("error")
        sys.exit(0)
    try:
        st = os.fstat(db_fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            sys.stdout.write("error")
            sys.exit(0)
        if os.read(db_fd, 16) != b"SQLite format 3\x00":
            sys.stdout.write("error")
            sys.exit(0)
        # Validate any present sidecars are exclusive regular files (reject symlinks/FIFOs).
        for suffix in ("-wal", "-shm", "-journal"):
            try:
                sc_fd = os.open(leaf_name + suffix, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=parent_fd)
            except FileNotFoundError:
                continue
            except OSError:
                sys.stdout.write("error")
                sys.exit(0)
            try:
                sc_st = os.fstat(sc_fd)
                if not stat.S_ISREG(sc_st.st_mode) or sc_st.st_nlink != 1:
                    sys.stdout.write("error")
                    sys.exit(0)
                if suffix == "-journal" and has_super_journal_trailer(sc_fd):
                    sys.stdout.write("error")
                    sys.exit(0)
            finally:
                os.close(sc_fd)

        def db_files_root_owned_safe(pfd, lname):
            for sfx in ("", "-wal", "-shm", "-journal"):
                try:
                    fst = os.stat(lname + sfx, dir_fd=pfd, follow_symlinks=False)
                except FileNotFoundError:
                    fst = None
                if fst is not None and (fst.st_uid != 0 or (fst.st_mode & 0o022) != 0):
                    return False
            return True

        if is_root and (
            not is_trusted_root_path_dir(parent_str, allow_sticky=False)
            or not db_files_root_owned_safe(parent_fd, leaf_name)
        ):
            last_res = "error"
            for attempt in range(3):
                wal_fd = -1
                jrn_fd = -1
                try:
                    if attempt > 0:
                        if db_fd >= 0:
                            os.close(db_fd)
                            db_fd = -1
                        try:
                            db_fd = os.open(leaf_name, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=parent_fd)
                        except OSError:
                            sys.stdout.write("error")
                            sys.exit(0)
                        st = os.fstat(db_fd)
                        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                            sys.stdout.write("error")
                            sys.exit(0)
                    else:
                        os.lseek(db_fd, 0, os.SEEK_SET)
                    req_bytes = st.st_size
                    for suffix in ("-wal", "-shm", "-journal"):
                        try:
                            sfd = os.open(leaf_name + suffix, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=parent_fd)
                        except FileNotFoundError:
                            continue
                        except OSError:
                            sys.stdout.write("error")
                            sys.exit(0)
                        sst = os.fstat(sfd)
                        if not stat.S_ISREG(sst.st_mode) or sst.st_nlink != 1:
                            os.close(sfd)
                            sys.stdout.write("error")
                            sys.exit(0)
                        if suffix == "-wal":
                            wal_fd = sfd
                            req_bytes += sst.st_size
                        elif suffix == "-journal":
                            jrn_fd = sfd
                            req_bytes += sst.st_size
                        else:
                            os.close(sfd)
                    if req_bytes > MAX_SCRATCH_BYTES:
                        sys.stdout.write("error")
                        sys.exit(0)
                    sc = create_root_scratch(req_bytes * 2 + 16 * 1024 * 1024)
                    if sc is None:
                        break
                    sc_base_fd, sc_fd, sc_name, sc_path = sc
                    try:
                        rem_cap = copy_fd(db_fd, sc_fd, "check.sqlite", MAX_SCRATCH_BYTES)
                        if wal_fd >= 0:
                            rem_cap = copy_fd(wal_fd, sc_fd, "check.sqlite-wal", rem_cap)
                        if jrn_fd >= 0:
                            copy_fd(jrn_fd, sc_fd, "check.sqlite-journal", rem_cap)
                        target = os.path.join(sc_path, "check.sqlite")
                        # Always use Python stdlib sqlite3 (libsqlite3 directly, PRAGMA trusted_schema = OFF)
                        # instead of /usr/bin/sqlite3 CLI (shell.c registers edit() without SQLITE_DIRECTONLY).
                        conn = sqlite3.connect(target, timeout=5)
                        try:
                            conn.execute("PRAGMA trusted_schema = OFF;")
                            row = conn.execute("PRAGMA integrity_check;").fetchone()
                            cleaned = "".join((row[0] if row and row[0] else "").split())
                        finally:
                            conn.close()
                        if cleaned == "ok":
                            sys.stdout.write("ok")
                            sys.exit(0)
                        last_res = cleaned or "error"
                    except Exception:
                        last_res = "error"
                    finally:
                        for leftover in ("check.sqlite", "check.sqlite-wal", "check.sqlite-shm", "check.sqlite-journal"):
                            try:
                                os.unlink(leftover, dir_fd=sc_fd)
                            except FileNotFoundError:
                                _ = leftover
                        os.close(sc_fd)
                        try:
                            os.rmdir(sc_name, dir_fd=sc_base_fd)
                        except OSError:
                            _ = sc_name
                        os.close(sc_base_fd)
                finally:
                    for fd_c in (wal_fd, jrn_fd):
                        if fd_c >= 0:
                            os.close(fd_c)
                if attempt < 2:
                    time.sleep(0.025)
            sys.stdout.write(last_res or "error")
            sys.exit(0)
    finally:
        if db_fd >= 0:
            os.close(db_fd)
finally:
    os.close(parent_fd)

try:
    # Always use libsqlite3 via Python stdlib sqlite3 (PRAGMA trusted_schema = OFF), never /usr/bin/sqlite3 CLI.
    conn = sqlite3.connect(pathlib.Path(db_abs).as_uri() + "?mode=ro", uri=True, timeout=5)
    try:
        conn.execute("PRAGMA trusted_schema = OFF;")
        row = conn.execute("PRAGMA integrity_check;").fetchone()
        cleaned = "".join((row[0] if row and row[0] else "").split())
    finally:
        conn.close()
    sys.stdout.write(cleaned or "error")
except Exception:
    sys.stdout.write("error")
PY
    )"
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
            # Non-recursive FD-based ownership/mode on DATA_DIR itself (matching Rust
            # apply_data_dir_ownership_and_mode in af-release/src/fs_security.rs) so root-owned
            # security state under DATA_DIR (e.g. .self-update-jobs/, *.conf, *.json) is NEVER chowned.
            python3 -I - "${DATA_DIR}" "${EFFECTIVE_RELEASE_ROOT:-}" <<'PY' || log_fatal "Failed to secure DATA_DIR: ${DATA_DIR}"
import os, pathlib, pwd, sys
data_dir, confine_raw = sys.argv[1:3]
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
p = pathlib.PurePosixPath(os.path.abspath(data_dir))
if ".." in p.parts:
    raise SystemExit(f"Refusing traversal in DATA_DIR: {data_dir}")
confine = pathlib.PurePosixPath(confine_raw.rstrip("/") or "/") if confine_raw else None
if confine is not None:
    rel_parts = p.relative_to(confine).parts
    anchor = pathlib.Path(str(confine))
else:
    rel_parts = p.parts[1:]
    anchor = pathlib.Path("/")
cur_fd = os.open(str(anchor), os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
try:
    for part in rel_parts:
        try:
            nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
        except FileNotFoundError:
            os.mkdir(part, 0o700, dir_fd=cur_fd)
            nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
        os.close(cur_fd)
        cur_fd = nxt_fd
    if os.geteuid() == 0:
        af_pw = pwd.getpwnam("aetherflow")
        os.fchown(cur_fd, af_pw.pw_uid, af_pw.pw_gid)
    os.fchmod(cur_fd, 0o700)
finally:
    os.close(cur_fd)
PY
            if [[ ! -L "${ENV_DIR}" ]]; then
                if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
                    chown root:aetherflow "${ENV_DIR}"
                fi
                chmod 0750 "${ENV_DIR}"
            fi
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
    if [[ "${RESOLVED_DB_PATH}" == "${fhs_db}" && ( ! -f "${fhs_db}" || -L "${fhs_db}" ) ]]; then
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
                atomic_publish_db_file "backup" "${legacy_db}" "${fhs_db}" || log_fatal "Failed to atomically migrate legacy SQLite database to ${fhs_db}"
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
                if ! python3 -I - "${legacy_env}" "${CONFIG_ENV_FILE}" "${EFFECTIVE_RELEASE_ROOT:-}" <<'PY'
import errno, os, pathlib, pwd, stat, sys, uuid

src_path, dst_path, confine_raw = sys.argv[1:4]
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
is_root = os.geteuid() == 0

def walk_dir_nofollow(dir_str, create=False, mode=0o750):
    p = pathlib.PurePosixPath(os.path.abspath(dir_str))
    if not p.is_absolute() or ".." in p.parts:
        raise SystemExit(f"Refusing invalid directory path: {dir_str}")
    confine = pathlib.PurePosixPath(confine_raw.rstrip("/") or "/") if confine_raw else None
    if confine is not None:
        try:
            rel_parts = p.relative_to(confine).parts
            anchor = pathlib.Path(str(confine))
        except ValueError:
            raise SystemExit(f"Path {dir_str} escapes isolated root {confine}")
        if create and not os.path.lexists(anchor):
            os.makedirs(anchor, mode=0o755, exist_ok=True)
    else:
        rel_parts = p.parts[1:]
        anchor = pathlib.Path("/")
    cur_fd = os.open(str(anchor), os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    cur = anchor
    try:
        for part in rel_parts:
            cur = cur / part
            try:
                nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
            except FileNotFoundError:
                if not create:
                    raise SystemExit(f"Missing directory: {cur}")
                created = False
                try:
                    os.mkdir(part, mode, dir_fd=cur_fd)
                    created = True
                except FileExistsError as exists_err:
                    _ = exists_err
                nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
                if created:
                    os.fchmod(nxt_fd, mode)
            os.close(cur_fd)
            cur_fd = nxt_fd
        return cur_fd
    except BaseException:
        os.close(cur_fd)
        raise

src_p = pathlib.PurePosixPath(os.path.abspath(src_path))
dst_p = pathlib.PurePosixPath(os.path.abspath(dst_path))
if len(src_p.parts) < 2 or len(dst_p.parts) < 2 or ".." in src_p.parts or ".." in dst_p.parts:
    raise SystemExit("Invalid legacy env migration path")

src_dir_fd = walk_dir_nofollow(str(src_p.parent), create=False)
try:
    src_fd = os.open(src_p.parts[-1], os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=src_dir_fd)
finally:
    os.close(src_dir_fd)

try:
    sst = os.fstat(src_fd)
    if not stat.S_ISREG(sst.st_mode) or sst.st_nlink != 1:
        raise SystemExit(f"Refusing non-regular or hardlinked legacy env source: {src_path}")
    if sst.st_size > 2 * 1024 * 1024:
        raise SystemExit(f"Refusing oversized legacy env source: {src_path}")
    payload = bytearray()
    while True:
        chunk = os.read(src_fd, 65536)
        if not chunk:
            break
        payload.extend(chunk)
        if len(payload) > 2 * 1024 * 1024:
            raise SystemExit(f"Refusing oversized legacy env source: {src_path}")
finally:
    os.close(src_fd)

af_gid = None
if is_root:
    try:
        af_gid = pwd.getpwnam("aetherflow").pw_gid
    except KeyError:
        af_gid = None

dst_dir_fd = walk_dir_nofollow(str(dst_p.parent), create=True, mode=0o750)
try:
    os.fchmod(dst_dir_fd, 0o750)
    if is_root and af_gid is not None:
        os.fchown(dst_dir_fd, 0, af_gid)
    leaf = dst_p.parts[-1]
    try:
        dst_existing = os.stat(leaf, dir_fd=dst_dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        dst_existing = None
    if dst_existing is not None and not stat.S_ISREG(dst_existing.st_mode):
        raise SystemExit(f"Refusing symlinked or non-regular destination: {dst_path}")
    tmp_name = f".{leaf}.tmp.{os.getpid()}.{uuid.uuid4().hex}"
    tmp_fd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600, dir_fd=dst_dir_fd)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(tmp_fd, view)
            if written <= 0:
                raise OSError("short write migrating legacy env")
            view = view[written:]
        if is_root and af_gid is not None:
            os.fchown(tmp_fd, 0, af_gid)
            os.fchmod(tmp_fd, 0o640)
        else:
            os.fchmod(tmp_fd, 0o600)
        os.fsync(tmp_fd)
    except BaseException:
        os.close(tmp_fd)
        try:
            os.unlink(tmp_name, dir_fd=dst_dir_fd)
        except OSError as rm_err:
            _ = rm_err
        raise
    os.close(tmp_fd)
    os.replace(tmp_name, leaf, src_dir_fd=dst_dir_fd, dst_dir_fd=dst_dir_fd)
    try:
        os.fsync(dst_dir_fd)
    except OSError as exc:
        if exc.errno not in (errno.EINVAL, errno.EBADF, errno.EROFS):
            raise
finally:
    os.close(dst_dir_fd)
PY
                then
                    log_fatal "Failed to safely migrate legacy environment file ${legacy_env} to ${CONFIG_ENV_FILE}"
                fi
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
    local tok="${AF_GITHUB_TOKEN:-${GITHUB_TOKEN:-${GH_TOKEN:-${ENV_FILE_GITHUB_TOKEN:-}}}}"
    [[ -n "${tok}" ]] || return 1
    printf '%s' "${tok}"
}

github_https_curl() {
    local max_bytes="$1"
    local url="${!#}"
    shift
    local -a extra_args=("$@")
    local hdr_fd=""
    local gh_tok=""
    if gh_tok="$(resolve_github_token_for_url "${url}" 2>/dev/null)"; then
        if [[ "${gh_tok}" != *$'\n'* && "${gh_tok}" != *$'\r'* ]]; then
            local esc_tok="${gh_tok//\\/\\\\}"
            esc_tok="${esc_tok//\"/\\\"}"
            exec {hdr_fd}< <(printf 'header = "Authorization: Bearer %s"\n' "${esc_tok}")
            extra_args=(-K "/dev/fd/${hdr_fd}" "${extra_args[@]}")
        fi
    fi
    local rc=0
    curl --proto '=https' --proto-redir '=https' --max-filesize "${max_bytes}" "${extra_args[@]}" || rc=$?
    if [[ -n "${hdr_fd}" ]]; then
        exec {hdr_fd}<&- 2>/dev/null || true
    fi
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
        if ! python3 -I - "${archive_path}" <<'PY'
import gzip, pathlib, sys, tarfile

archive = sys.argv[1]
MAX_ENTRY_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 2 * 1024 * 1024 * 1024
MAX_STREAM_BYTES = MAX_TOTAL_BYTES + 64 * 1024 * 1024
MAX_ENTRIES = 20000

class BoundedReader:
    def __init__(self, inner, limit):
        self.inner = inner
        self.limit = limit
        self.read_bytes = 0

    def read(self, size=-1):
        data = self.inner.read(size)
        self.read_bytes += len(data)
        if self.read_bytes > self.limit:
            raise ValueError(f"decompressed archive stream exceeded {self.limit} byte cap")
        return data

try:
    with open(archive, "rb") as raw_fh:
        magic = raw_fh.read(2)
        raw_fh.seek(0)
        if magic == b"\x1f\x8b":
            gz_fh = gzip.GzipFile(fileobj=raw_fh, mode="rb")
            stream = BoundedReader(gz_fh, MAX_STREAM_BYTES)
        else:
            gz_fh = None
            stream = BoundedReader(raw_fh, MAX_STREAM_BYTES)
        try:
            entry_count = 0
            total_bytes = 0
            with tarfile.open(fileobj=stream, mode="r|") as tf:
                for member in tf:
                    entry_count += 1
                    if entry_count > MAX_ENTRIES:
                        sys.stderr.write(f"Rejected archive exceeding {MAX_ENTRIES} entries\n")
                        sys.exit(1)
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
                    norm_parts = [part for part in parts if part not in ("", ".")]
                    if norm_parts and norm_parts[0] == "data-snapshot":
                        sys.stderr.write(f"Rejected reserved data-snapshot tar entry: {name}\n")
                        sys.exit(1)
                    if member.isfile():
                        if member.size < 0 or member.size > MAX_ENTRY_BYTES:
                            sys.stderr.write(f"Rejected oversized tar entry {name} ({member.size} bytes)\n")
                            sys.exit(1)
                        total_bytes += member.size
                        if total_bytes > MAX_TOTAL_BYTES:
                            sys.stderr.write(f"Rejected archive exceeding {MAX_TOTAL_BYTES} byte cumulative cap\n")
                            sys.exit(1)
        finally:
            if gz_fh is not None:
                gz_fh.close()
except SystemExit:
    raise
except Exception as exc:
    sys.stderr.write(f"Invalid tar archive {archive}: {exc}\n")
    sys.exit(1)
PY
        then
            log_error "Archive security validation failed for ${archive_path} (links, special entries, size caps, or path traversal detected)."
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
    if ! github_https_curl 536870912 -fsSL --max-time 180 -o "${tmp_dir}/${ARTIFACT_NAME}" "${base_url}/${ARTIFACT_NAME}"; then
        rm -rf "${tmp_dir}"
        return 1
    fi

    log_info "Downloading SHA-256 manifest (${CHECKSUM_NAME})..."
    if ! github_https_curl 4194304 -fsSL --max-time 30 -o "${tmp_dir}/${CHECKSUM_NAME}" "${base_url}/${CHECKSUM_NAME}"; then
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

    if [[ "${EFFECTIVE_SKIP_PROVENANCE_VERIFY:-0}" != "1" ]]; then
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
        local prov_gh_token="${AF_GITHUB_TOKEN:-${GITHUB_TOKEN:-${GH_TOKEN:-${ENV_FILE_GITHUB_TOKEN:-}}}}"
        if [[ ! -f "${SCRIPT_DIR}/verify-provenance.py" ]] || ! prov_out="$(AF_GITHUB_TOKEN="${prov_gh_token}" python3 -I -B -c '
import os, signal, subprocess, sys
script = sys.argv[1]
args = sys.argv[2:]
clean_env = {
    "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
    "HOME": os.environ.get("HOME", "/root"),
    "LANG": os.environ.get("LANG", "C.UTF-8"),
}
for k in ("SSL_CERT_FILE", "SSL_CERT_DIR", "AF_GITHUB_TOKEN", "AETHERFLOW_GITHUB_API_BASE"):
    v = os.environ.get(k, "")
    if v:
        clean_env[k] = v
proc = subprocess.Popen(
    [sys.executable, "-I", "-B", script, *args],
    env=clean_env,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    start_new_session=True,
)
try:
    out, _ = proc.communicate(timeout=60)
except subprocess.TimeoutExpired:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError as exc:
        _ = exc
    out, _ = proc.communicate()
    if out:
        sys.stdout.buffer.write(out)
    sys.stdout.write("\nProvenance verification timed out after 60s\n")
    raise SystemExit(124)
if out:
    sys.stdout.buffer.write(out)
raise SystemExit(proc.returncode)
' "${SCRIPT_DIR}/verify-provenance.py" "${prov_args[@]}" 2>&1)"; then
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
    for companion_bin in af speedtest-backend af-transcode; do
        if [[ -f "${RELEASE_DIR}/bin/${companion_bin}" && ! -L "${RELEASE_DIR}/bin/${companion_bin}" ]]; then
            chmod +x "${RELEASE_DIR}/bin/${companion_bin}"
        fi
        if [[ -f "${RELEASE_DIR}/${companion_bin}" && ! -L "${RELEASE_DIR}/${companion_bin}" ]]; then
            chmod +x "${RELEASE_DIR}/${companion_bin}"
        fi
    done
    if [[ -f "${RELEASE_DIR}/plugins/telemetry-inspector/backend/hooks/start.sh" && ! -L "${RELEASE_DIR}/plugins/telemetry-inspector/backend/hooks/start.sh" ]]; then
        chmod 0755 "${RELEASE_DIR}/plugins/telemetry-inspector/backend/hooks/start.sh"
    fi
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
        --exclude='*.tsbuildinfo' \
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
    if [[ -f "${RELEASE_DIR}/backend-rs/crates/af-transcode/Cargo.toml" ]]; then
        companion_bins+=(af-transcode)
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
        install -m 0755 "${cargo_target_dir}/release/${built_bin}" "${RELEASE_DIR}/bin/${built_bin}" || return 1
    done
    if [[ -d "${REPO_DIR}/plugins/telemetry-inspector" && ! -L "${REPO_DIR}/plugins/telemetry-inspector" ]]; then
        mkdir -p "${RELEASE_DIR}/plugins/telemetry-inspector" || return 1
        if ! rsync -a --exclude='__pycache__/' --exclude='*.pyc' --exclude='*.pyo' \
            --exclude='.cache/' --exclude='.pytest_cache/' --exclude='.mypy_cache/' \
            --exclude='.ruff_cache/' --exclude='target/' --exclude='node_modules/' \
            "${REPO_DIR}/plugins/telemetry-inspector/" "${RELEASE_DIR}/plugins/telemetry-inspector/" >> "${LOG_FILE}" 2>&1; then
            log_error "Failed to stage managed plugin plugins/telemetry-inspector into ${RELEASE_DIR}."
            return 1
        fi
        if [[ -f "${RELEASE_DIR}/plugins/telemetry-inspector/backend/hooks/start.sh" && ! -L "${RELEASE_DIR}/plugins/telemetry-inspector/backend/hooks/start.sh" ]]; then
            chmod 0755 "${RELEASE_DIR}/plugins/telemetry-inspector/backend/hooks/start.sh" || return 1
        fi
    fi
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

resolve_dry_run_version_stamp() {
    local candidate raw="" normalized=""
    for candidate in \
        "${CONFIG_REPO_DIR:-}/.version" \
        "${SCRIPT_DIR}/../.version" \
        "${SCRIPT_DIR}/.version" \
        "${CURRENT_LINK:-}/.version" \
        "${LEGACY_OPT_ROOT:-}/current/.version"; do
        [[ -n "${candidate}" && -f "${candidate}" && ! -L "${candidate}" && -s "${candidate}" ]] || continue
        raw="$(tr -d '[:space:]' < "${candidate}" 2>/dev/null || true)"
        raw="${raw%-dryrun}"
        if [[ "${raw}" =~ ^[vV]?[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9._-]+)?$ ]]; then
            normalized="${raw#V}"
            normalized="${normalized#v}"
            printf 'v%s-dryrun' "${normalized}"
            return 0
        fi
    done
    printf 'v4.0.1-dryrun'
}

simulate_offline_artifact() {
    log_info "[DRY-RUN] Offline mode: simulating artifact verification and extraction."
    mkdir -p "${RELEASE_DIR}/deploy/systemd" "${RELEASE_DIR}/packages/system" "${RELEASE_DIR}/config" "${RELEASE_DIR}/bin" "${RELEASE_DIR}/web/dist" \
        "${RELEASE_DIR}/plugins/telemetry-inspector/backend/hooks" "${RELEASE_DIR}/plugins/telemetry-inspector/frontend/dist"
    printf '<!-- Offline dry-run placeholder; not a frontend. -->\n' > "${RELEASE_DIR}/web/dist/index.html"
    : > "${RELEASE_DIR}/web/dist/dry-run-placeholder.wasm"
    printf '#!/bin/bash\n# Offline dry-run placeholder; not a release binary.\n' > "${RELEASE_DIR}/aetherflow-api"
    printf '#!/bin/bash\n# Offline dry-run placeholder; not a release binary.\n' > "${RELEASE_DIR}/bin/af"
    printf '#!/bin/bash\n# Offline dry-run placeholder; not a release binary.\n' > "${RELEASE_DIR}/bin/speedtest-backend"
    printf '#!/bin/bash\n# Offline dry-run placeholder; not a release binary.\n' > "${RELEASE_DIR}/bin/af-transcode"
    printf '#!/bin/bash\n# Offline dry-run placeholder; not a package helper.\n' > "${RELEASE_DIR}/packages/common.sh"
    printf '#!/bin/bash\n# Offline dry-run placeholder; not a certbot helper.\n' > "${RELEASE_DIR}/packages/system/af-certbot-sync"
    printf '#!/bin/bash\n# Offline dry-run placeholder; not a sandbox helper.\n' > "${RELEASE_DIR}/packages/system/af-systemd-sandbox"
    printf '{"id":"telemetry-inspector","name":"Telemetry Inspector","version":"1.0.0","runtime_status":"managed"}\n' > "${RELEASE_DIR}/plugins/telemetry-inspector/plugin.manifest.json"
    printf '#!/usr/bin/env bash\n# Offline dry-run placeholder; not a release binary.\n' > "${RELEASE_DIR}/plugins/telemetry-inspector/backend/hooks/start.sh"
    echo "# Offline dry-run placeholder" > "${RELEASE_DIR}/plugins/telemetry-inspector/backend/runtime.py"
    printf '<!-- Offline dry-run placeholder; not a plugin UI. -->\n' > "${RELEASE_DIR}/plugins/telemetry-inspector/frontend/dist/index.html"
    chmod +x \
        "${RELEASE_DIR}/aetherflow-api" \
        "${RELEASE_DIR}/bin/af" \
        "${RELEASE_DIR}/bin/speedtest-backend" \
        "${RELEASE_DIR}/bin/af-transcode" \
        "${RELEASE_DIR}/packages/common.sh" \
        "${RELEASE_DIR}/packages/system/af-certbot-sync" \
        "${RELEASE_DIR}/packages/system/af-systemd-sandbox" \
        "${RELEASE_DIR}/plugins/telemetry-inspector/backend/hooks/start.sh"
    printf '%s\n' "$(resolve_dry_run_version_stamp)" > "${RELEASE_DIR}/.version"
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
    for companion_chmod in af speedtest-backend af-transcode; do
        if [[ -f "${RELEASE_DIR}/${companion_chmod}" && ! -L "${RELEASE_DIR}/${companion_chmod}" ]]; then
            chmod 0755 "${RELEASE_DIR}/${companion_chmod}" || return 1
        fi
        if [[ -f "${RELEASE_DIR}/bin/${companion_chmod}" && ! -L "${RELEASE_DIR}/bin/${companion_chmod}" ]]; then
            chmod 0755 "${RELEASE_DIR}/bin/${companion_chmod}" || return 1
        fi
    done
    if [[ -f "${RELEASE_DIR}/plugins/telemetry-inspector/backend/hooks/start.sh" && ! -L "${RELEASE_DIR}/plugins/telemetry-inspector/backend/hooks/start.sh" ]]; then
        chmod 0755 "${RELEASE_DIR}/plugins/telemetry-inspector/backend/hooks/start.sh" || return 1
    fi
    local pkg_exec_dir
    for pkg_exec_dir in \
        "${RELEASE_DIR}/packages/system" \
        "${RELEASE_DIR}/packages/package/install" \
        "${RELEASE_DIR}/packages/package/remove"; do
        if [[ -d "${pkg_exec_dir}" && ! -L "${pkg_exec_dir}" ]]; then
            find "${pkg_exec_dir}" -type f -exec chmod 0755 {} + || return 1
        fi
    done
    if [[ "${DRY_RUN}" == false ]]; then
        if [[ "${EUID}" -eq 0 ]] || [[ "${service_user}" != "$(id -un)" ]]; then
            if ! runuser -u "${service_user}" -- /usr/bin/env -i PATH="/usr/local/bin:/usr/bin:/bin" LANG="C.UTF-8" /bin/sh -c 'cd "$1" && test -r .version && test -x ./aetherflow-api && { test ! -d web/dist || test -r web/dist/index.html; }' sh "${RELEASE_DIR}"; then
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

has_python_sqlite3() {
    python3 -I -c "import sqlite3" >/dev/null 2>&1
}

has_sqlite_snapshot_backend() {
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        has_python_sqlite3
    else
        command -v sqlite3 >/dev/null 2>&1
    fi
}

state_snapshot() {
    log_info "=== STAGE 1.5: State Snapshot ==="
    if [[ -z "${RESOLVED_DB_PATH}" ]]; then
        resolve_db_path
    fi

    if [[ -L "${DATA_DIR}" || -L "${RESOLVED_DB_PATH}" ]]; then
        log_error "Refusing symlinked database or data directory path during snapshot."
        return 1
    fi

    local snapshot_db="${RESOLVED_DB_PATH}"
    if [[ "${DRY_RUN}" == true ]]; then
        local copy="${DATA_DIR}/${SQLITE_DB}"
        install -d -m 0700 "${DATA_DIR}"
        if [[ -f "${RESOLVED_DB_PATH}" && ! -L "${RESOLVED_DB_PATH}" && "${RESOLVED_DB_PATH}" != "${copy}" ]]; then
            if ! has_sqlite_snapshot_backend; then
                log_error "sqlite3 is required to copy the live database without a raw cp of a WAL file."
                return 1
            fi
            log_info "[DRY-RUN] Copying live database with FD-isolated sqlite3 backup from ${RESOLVED_DB_PATH} (source: ${RESOLVED_DB_SOURCE}) into ${copy}"
            # state_snapshot runs under `||`, so errexit is off. A failed copy must
            # not fall through into the placeholder database.
            if ! atomic_publish_db_file "snapshot" "${RESOLVED_DB_PATH}" "${copy}"; then
                rm -f "${copy}" "${copy}-wal" "${copy}-shm" "${copy}-journal"
                log_error "[DRY-RUN] Failed to copy live database from ${RESOLVED_DB_PATH} (source: ${RESOLVED_DB_SOURCE})."
                return 1
            fi
        fi
        # Never create or snapshot the live path itself during a dry-run.
        snapshot_db="${copy}"
    fi

    if [[ -L "${snapshot_db}" ]]; then
        log_error "Refusing symlinked database file during snapshot: ${snapshot_db}"
        return 1
    fi

    if [[ ! -f "${snapshot_db}" ]]; then
        if [[ "${DRY_RUN}" == true ]]; then
            if ! has_python_sqlite3; then
                log_error "python3 sqlite3 is required to create the dry-run placeholder database."
                return 1
            fi
            if ! atomic_publish_db_file "placeholder" "" "${snapshot_db}"; then
                log_error "[DRY-RUN] Failed to stage and publish placeholder database at ${snapshot_db}."
                return 1
            fi
            log_info "[DRY-RUN] Created placeholder database at ${snapshot_db} because ${RESOLVED_DB_PATH} is absent."
        else
            log_warn "No database file at ${RESOLVED_DB_PATH}; skipping snapshot."
            log_info "=== STAGE 1.5 COMPLETE: No database to snapshot ==="
            return 0
        fi
    fi

    if ! has_sqlite_snapshot_backend; then
        log_error "sqlite3 is required for a WAL-safe snapshot of ${snapshot_db}."
        return 1
    fi

    local snapshot_dir="${RELEASE_DIR}/data-snapshot"
    if [[ -L "${snapshot_dir}" ]]; then
        log_error "Refusing symlinked snapshot directory: ${snapshot_dir}"
        return 1
    fi
    install -d -m 0700 "${snapshot_dir}"
    if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
        chown root:root "${snapshot_dir}"
    fi
    chmod 0700 "${snapshot_dir}"
    local bak_path="${snapshot_dir}/${SQLITE_DB}.bak"

    log_info "Executing SQLite online backup: ${snapshot_db} -> ${bak_path} (resolved ${RESOLVED_DB_PATH}, source: ${RESOLVED_DB_SOURCE})"
    if ! atomic_publish_db_file "snapshot" "${snapshot_db}" "${bak_path}" ".snapshot.lock" "${SNAPSHOT_TIMEOUT}"; then
        log_error "Snapshot integrity check FAILED for ${bak_path} (SQLite snapshot failed for ${snapshot_db}). Aborting before symlink swap."
        return 1
    fi

    local integrity
    integrity="$(sqlite_integrity "${bak_path}")"
    if [[ "${integrity}" != "ok" ]]; then
        log_error "Snapshot integrity check FAILED for ${bak_path} (result=${integrity}). Aborting before symlink swap."
        return 1
    fi
    log_info "Snapshot integrity check PASSED: ${bak_path}"

    local manifest_lines=""
    if ! manifest_lines="$(cd "${snapshot_dir}" && sha256sum -- *.bak)" || [[ -z "${manifest_lines}" ]]; then
        log_error "Failed to compute snapshot SHA-256 manifest in ${snapshot_dir}. Aborting before symlink swap."
        return 1
    fi
    if ! write_atomic_private_file "${snapshot_dir}/MANIFEST.sha256" "0600" "${manifest_lines}"$'\n'; then
        log_error "Failed to write snapshot SHA-256 manifest in ${snapshot_dir}. Aborting before symlink swap."
        return 1
    fi

    log_info "=== STAGE 1.5 COMPLETE: State snapshot captured ==="
}

###############################################################################
# STAGE 2: Atomic Symlink Swap
###############################################################################
sync_legacy_package_paths() {
    local mode="sync"
    if [[ "${1:-}" == "--preflight-only" ]]; then
        mode="preflight"
        shift
    fi
    local src_root="${1:-${CURRENT_LINK:-}}"
    [[ -n "${src_root}" && ( -d "${src_root}/packages" || -L "${src_root}/packages" ) ]] || return 0

    local opt_packages_dir=""
    local legacy_bin_root=""
    local local_bin_dir=""
    local sys_bin_dir=""
    local confine_root=""

    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        local dry_root="${DRY_RUN_ROOT:-/tmp/aetherflow-dryrun}"
        dry_root="${dry_root%/}"
        opt_packages_dir="${dry_root}/opt/AetherFlow/packages"
        local_bin_dir="${dry_root}/usr/local/bin"
        legacy_bin_root="${local_bin_dir}/AetherFlow"
        sys_bin_dir="${dry_root}/usr/bin"
        confine_root="${EFFECTIVE_RELEASE_ROOT:-${dry_root}}"
    else
        local opt_root="${LEGACY_OPT_ROOT:-}"
        if [[ -z "${opt_root}" ]]; then
            if [[ -n "${EFFECTIVE_RELEASE_ROOT:-}" ]]; then
                opt_root="${EFFECTIVE_RELEASE_ROOT%/}/opt/AetherFlow"
            else
                opt_root="/opt/AetherFlow"
            fi
        fi
        opt_packages_dir="${opt_root%/}/packages"

        local_bin_dir="${CLI_BIN_DIR:-}"
        if [[ -z "${local_bin_dir}" ]]; then
            if [[ -n "${EFFECTIVE_RELEASE_ROOT:-}" ]]; then
                local_bin_dir="${EFFECTIVE_RELEASE_ROOT%/}/usr/local/bin"
            else
                local_bin_dir="/usr/local/bin"
            fi
        fi
        local_bin_dir="${local_bin_dir%/}"

        legacy_bin_root="${LEGACY_BIN_ROOT:-}"
        if [[ -z "${legacy_bin_root}" ]]; then
            legacy_bin_root="${local_bin_dir}/AetherFlow"
        fi
        legacy_bin_root="${legacy_bin_root%/}"

        sys_bin_dir="${SYS_BIN_DIR:-}"
        if [[ -z "${sys_bin_dir}" ]]; then
            if [[ -n "${EFFECTIVE_RELEASE_ROOT:-}" ]]; then
                sys_bin_dir="${EFFECTIVE_RELEASE_ROOT%/}/usr/bin"
            elif [[ "${local_bin_dir}" == */usr/local/bin && "${local_bin_dir}" != "/usr/local/bin" ]]; then
                sys_bin_dir="${local_bin_dir%/usr/local/bin}/usr/bin"
            else
                sys_bin_dir="/usr/bin"
            fi
        fi
        sys_bin_dir="${sys_bin_dir%/}"
        confine_root="${EFFECTIVE_RELEASE_ROOT:-}"
    fi

    validate_path_within_isolated_root "LEGACY_OPT_ROOT/packages" "${opt_packages_dir}"
    validate_path_within_isolated_root "LEGACY_BIN_ROOT" "${legacy_bin_root}"
    validate_path_within_isolated_root "CLI_BIN_DIR" "${local_bin_dir}"
    validate_path_within_isolated_root "SYS_BIN_DIR" "${sys_bin_dir}"

    local sync_err=""
    if ! sync_err="$(python3 -I - "${mode}" "${src_root}" "${opt_packages_dir}" "${legacy_bin_root}" "${local_bin_dir}" "${sys_bin_dir}" "${DRY_RUN:-false}" "${confine_root}" <<'PY' 2>&1
import errno
import os
import pathlib
import stat
import sys
import uuid

(
    mode,
    src_root_raw,
    opt_packages_raw,
    legacy_bin_raw,
    local_bin_raw,
    sys_bin_raw,
    dry_run_s,
    confine_root_raw,
) = sys.argv[1:]

dry_run = dry_run_s == "true"
is_root = os.geteuid() == 0
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)

# Resolve CURRENT_LINK (the release slot symlink itself), then require packages/ inside
# that slot to be a real directory with zero symlinks or special entries.
resolved_slot = pathlib.Path(os.path.realpath(src_root_raw))
src_packages = resolved_slot / "packages"
try:
    src_st = os.lstat(src_packages)
except FileNotFoundError:
    sys.exit(0)
if stat.S_ISLNK(src_st.st_mode) or not stat.S_ISDIR(src_st.st_mode):
    raise SystemExit(f"Refusing symlinked or non-directory release packages path: {src_packages}")

# Collect relative directory and file inventory from src_packages without following symlinks.
rel_dirs = []
rel_files = {}

def scan_source_dir(dir_fd, rel_prefix):
    names = sorted(os.listdir(dir_fd))
    for name in names:
        if name in (".", "..") or name == "EGM.md":
            continue
        rel = f"{rel_prefix}/{name}" if rel_prefix else name
        if rel in ("README.md", "system/af-heal"):
            continue
        st = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
        if stat.S_ISLNK(st.st_mode):
            raise SystemExit(f"Refusing symbolic link inside release packages tree: {src_packages / rel}")
        if stat.S_ISDIR(st.st_mode):
            rel_dirs.append(rel)
            child_fd = os.open(name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=dir_fd)
            try:
                scan_source_dir(child_fd, rel)
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(st.st_mode):
            file_fd = os.open(name, os.O_RDONLY | O_NOFOLLOW | O_CLOEXEC, dir_fd=dir_fd)
            try:
                fst = os.fstat(file_fd)
                if not stat.S_ISREG(fst.st_mode):
                    raise SystemExit(f"Refusing non-regular package file: {src_packages / rel}")
                with os.fdopen(file_fd, "rb") as fh:
                    file_fd = -1
                    rel_files[rel] = fh.read()
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
        else:
            raise SystemExit(f"Refusing non-regular entry inside release packages tree: {src_packages / rel}")

src_fd = os.open(str(src_packages), os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
try:
    scan_source_dir(src_fd, "")
finally:
    os.close(src_fd)

if not rel_files and not rel_dirs:
    sys.exit(0)

confine_root = pathlib.PurePosixPath(confine_root_raw.rstrip("/") or "/") if confine_root_raw else None

def verify_no_symlink_ancestors(target_str, expect_regular_leaf=False):
    p = pathlib.PurePosixPath(target_str)
    if not p.is_absolute() or ".." in p.parts:
        raise SystemExit(f"Refusing non-normalized helper sync target: {target_str}")
    if confine_root is not None:
        try:
            rel_parts = p.relative_to(confine_root).parts
        except ValueError:
            raise SystemExit(f"Target {target_str} escapes isolated root {confine_root}")
        cur = pathlib.Path(str(confine_root))
        try:
            rst = os.lstat(cur)
        except FileNotFoundError:
            rst = None
        if rst is not None and stat.S_ISLNK(rst.st_mode):
            raise SystemExit(f"Refusing symlinked isolated root directory: {cur}")
        for idx, part in enumerate(rel_parts):
            cur = cur / part
            is_leaf = idx == len(rel_parts) - 1
            try:
                st = os.lstat(cur)
            except FileNotFoundError:
                break
            if is_leaf and expect_regular_leaf:
                if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
                    raise SystemExit(f"Refusing directory at helper binary path: {cur}")
            else:
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                    raise SystemExit(f"Refusing symlinked or non-directory helper path: {cur}")
    else:
        cur = pathlib.Path("/")
        for idx, part in enumerate(p.parts[1:]):
            cur = cur / part
            is_leaf = idx == len(p.parts) - 2
            try:
                st = os.lstat(cur)
            except FileNotFoundError:
                break
            if is_leaf and expect_regular_leaf:
                if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
                    raise SystemExit(f"Refusing directory at helper binary path: {cur}")
            else:
                if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
                    raise SystemExit(f"Refusing symlinked or non-directory helper path: {cur}")

def can_manage_target(target_str):
    if dry_run or confine_root is not None or is_root:
        return True
    probe = pathlib.Path(target_str)
    while not os.path.exists(probe) and probe.parent != probe:
        probe = probe.parent
    return os.access(probe, os.W_OK | os.X_OK)

def check_existing_subtree_no_symlink_dirs(root_str):
    if not os.path.lexists(root_str):
        return
    st = os.lstat(root_str)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise SystemExit(f"Refusing symlinked or non-directory package sync root: {root_str}")
    dir_fd = os.open(root_str, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    try:
        for rel_d in rel_dirs:
            cur_fd = os.dup(dir_fd)
            try:
                for comp in rel_d.split("/"):
                    try:
                        cst = os.stat(comp, dir_fd=cur_fd, follow_symlinks=False)
                    except FileNotFoundError:
                        break
                    if stat.S_ISLNK(cst.st_mode):
                        raise SystemExit(f"Refusing symlinked package subdirectory: {root_str}/{rel_d}")
                    if not stat.S_ISDIR(cst.st_mode):
                        break
                    nxt_fd = os.open(comp, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
                    os.close(cur_fd)
                    cur_fd = nxt_fd
            finally:
                os.close(cur_fd)
    finally:
        os.close(dir_fd)

manage_opt = can_manage_target(opt_packages_raw)
manage_legacy_bin = can_manage_target(legacy_bin_raw)
manage_local_bin = can_manage_target(local_bin_raw)
manage_sys_bin = can_manage_target(sys_bin_raw)

if manage_opt:
    verify_no_symlink_ancestors(opt_packages_raw, expect_regular_leaf=False)
    check_existing_subtree_no_symlink_dirs(opt_packages_raw)
if manage_legacy_bin:
    verify_no_symlink_ancestors(legacy_bin_raw, expect_regular_leaf=False)
    check_existing_subtree_no_symlink_dirs(legacy_bin_raw)
if manage_local_bin and "system/af-certbot-sync" in rel_files:
    verify_no_symlink_ancestors(local_bin_raw, expect_regular_leaf=False)
    verify_no_symlink_ancestors(f"{local_bin_raw}/af-certbot-sync", expect_regular_leaf=True)
if manage_sys_bin and ("system/af-certbot-sync" in rel_files or "system/af-systemd-sandbox" in rel_files):
    verify_no_symlink_ancestors(sys_bin_raw, expect_regular_leaf=False)
    if "system/af-certbot-sync" in rel_files:
        verify_no_symlink_ancestors(f"{sys_bin_raw}/af-certbot-sync", expect_regular_leaf=True)
    if "system/af-systemd-sandbox" in rel_files:
        verify_no_symlink_ancestors(f"{sys_bin_raw}/af-systemd-sandbox", expect_regular_leaf=True)

if mode == "preflight":
    sys.exit(0)

def fsync_dir_best_effort(dir_fd):
    try:
        os.fsync(dir_fd)
    except OSError as exc:
        if exc.errno not in (errno.EINVAL, errno.EBADF, errno.EROFS):
            raise

def ensure_dir_nofollow(target_str, set_managed_perms):
    verify_no_symlink_ancestors(target_str, expect_regular_leaf=False)
    p = pathlib.PurePosixPath(target_str)
    if confine_root is not None:
        anchor = pathlib.Path(str(confine_root))
        rel_parts = p.relative_to(confine_root).parts
        if not os.path.lexists(anchor):
            os.makedirs(anchor, mode=0o755, exist_ok=True)
    else:
        anchor = pathlib.Path("/")
        rel_parts = p.parts[1:]
    cur_fd = os.open(str(anchor), os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    cur = anchor
    try:
        for part in rel_parts:
            cur = cur / part
            try:
                nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(part, 0o755, dir_fd=cur_fd)
                except FileExistsError as exists_err:
                    _ = exists_err
                nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
            except OSError as exc:
                raise SystemExit(f"Refusing symlinked or non-directory helper path {cur}: {exc}")
            os.close(cur_fd)
            cur_fd = nxt_fd
        fst = os.fstat(cur_fd)
        if not stat.S_ISDIR(fst.st_mode):
            raise SystemExit(f"Opened helper directory is not a directory: {target_str}")
        if set_managed_perms:
            if is_root:
                os.fchown(cur_fd, 0, 0)
            os.fchmod(cur_fd, 0o755)
        return cur_fd
    except BaseException:
        os.close(cur_fd)
        raise

def remove_tree_at(parent_fd, name):
    st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if stat.S_ISDIR(st.st_mode) and not stat.S_ISLNK(st.st_mode):
        child_fd = os.open(name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=parent_fd)
        try:
            for child in os.listdir(child_fd):
                if child not in (".", ".."):
                    remove_tree_at(child_fd, child)
        finally:
            os.close(child_fd)
        os.rmdir(name, dir_fd=parent_fd)
    else:
        os.unlink(name, dir_fd=parent_fd)

def atomic_write_regular_in_dir(dir_fd, entry_name, payload, allow_dir_replace=False):
    try:
        existing = os.stat(entry_name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        existing = None
    if existing is not None and stat.S_ISDIR(existing.st_mode) and not stat.S_ISLNK(existing.st_mode):
        if allow_dir_replace:
            remove_tree_at(dir_fd, entry_name)
        else:
            raise SystemExit(f"Refusing to overwrite directory at helper binary path: {entry_name}")

    tmp_name = f".af-sync.{entry_name}.{os.getpid()}.{uuid.uuid4().hex}"
    tmp_fd = os.open(
        tmp_name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        0o600,
        dir_fd=dir_fd,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(tmp_fd, view)
            if written <= 0:
                raise OSError("short write during atomic helper sync")
            view = view[written:]
        if is_root:
            os.fchown(tmp_fd, 0, 0)
        os.fchmod(tmp_fd, 0o755)
        os.fsync(tmp_fd)
    except BaseException:
        os.close(tmp_fd)
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except OSError as cleanup_err:
            if cleanup_err.errno != errno.ENOENT:
                sys.stderr.write(f"warning: failed to clean up temp helper {tmp_name}: {cleanup_err}\n")
        raise
    os.close(tmp_fd)
    try:
        os.replace(tmp_name, entry_name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
    except BaseException:
        try:
            os.unlink(tmp_name, dir_fd=dir_fd)
        except OSError as cleanup_err:
            if cleanup_err.errno != errno.ENOENT:
                sys.stderr.write(f"warning: failed to clean up temp helper {tmp_name}: {cleanup_err}\n")
        raise
    verify_st = os.stat(entry_name, dir_fd=dir_fd, follow_symlinks=False)
    if stat.S_ISLNK(verify_st.st_mode) or not stat.S_ISREG(verify_st.st_mode):
        raise SystemExit(f"Post-sync verification failed for regular file {entry_name}")
    fsync_dir_best_effort(dir_fd)

def sync_managed_packages_tree(dest_root_str):
    if os.path.lexists(dest_root_str):
        dst_st = os.lstat(dest_root_str)
        if os.path.samestat(src_st, dst_st):
            return
    root_fd = ensure_dir_nofollow(dest_root_str, set_managed_perms=True)
    dir_fds = {"": root_fd}
    try:
        for rel_d in rel_dirs:
            parent_rel, _, leaf = rel_d.rpartition("/")
            parent_fd = dir_fds[parent_rel]
            try:
                est = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
                if stat.S_ISLNK(est.st_mode):
                    raise SystemExit(f"Refusing symlinked package directory: {dest_root_str}/{rel_d}")
                if not stat.S_ISDIR(est.st_mode):
                    os.unlink(leaf, dir_fd=parent_fd)
                    os.mkdir(leaf, 0o755, dir_fd=parent_fd)
            except FileNotFoundError:
                os.mkdir(leaf, 0o755, dir_fd=parent_fd)
            child_fd = os.open(leaf, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=parent_fd)
            if is_root:
                os.fchown(child_fd, 0, 0)
            os.fchmod(child_fd, 0o755)
            dir_fds[rel_d] = child_fd

        for rel_f, payload in rel_files.items():
            parent_rel, _, leaf = rel_f.rpartition("/")
            parent_fd = dir_fds[parent_rel]
            atomic_write_regular_in_dir(parent_fd, leaf, payload, allow_dir_replace=True)

        expected_children = {rel_d: set() for rel_d in ["", *rel_dirs]}
        for rel_d in rel_dirs:
            parent_rel, _, leaf = rel_d.rpartition("/")
            expected_children[parent_rel].add(leaf)
        for rel_f in rel_files:
            parent_rel, _, leaf = rel_f.rpartition("/")
            expected_children[parent_rel].add(leaf)

        for rel_d in reversed(["", *rel_dirs]):
            dfd = dir_fds[rel_d]
            keep = expected_children[rel_d]
            for existing_name in os.listdir(dfd):
                if existing_name in (".", "..") or existing_name in keep:
                    continue
                remove_tree_at(dfd, existing_name)
            fsync_dir_best_effort(dfd)
    finally:
        for dfd in reversed(list(dir_fds.values())):
            os.close(dfd)

if manage_opt:
    sync_managed_packages_tree(opt_packages_raw)
if manage_legacy_bin:
    sync_managed_packages_tree(legacy_bin_raw)

if manage_local_bin and "system/af-certbot-sync" in rel_files:
    lbin_fd = ensure_dir_nofollow(local_bin_raw, set_managed_perms=False)
    try:
        atomic_write_regular_in_dir(
            lbin_fd,
            "af-certbot-sync",
            rel_files["system/af-certbot-sync"],
            allow_dir_replace=False,
        )
    finally:
        os.close(lbin_fd)

if manage_sys_bin:
    if "system/af-certbot-sync" in rel_files or "system/af-systemd-sandbox" in rel_files or os.path.lexists(f"{sys_bin_raw}/af-heal"):
        if os.path.lexists(sys_bin_raw) or "system/af-certbot-sync" in rel_files or "system/af-systemd-sandbox" in rel_files:
            sbin_fd = ensure_dir_nofollow(sys_bin_raw, set_managed_perms=False)
            try:
                if "system/af-certbot-sync" in rel_files:
                    atomic_write_regular_in_dir(
                        sbin_fd,
                        "af-certbot-sync",
                        rel_files["system/af-certbot-sync"],
                        allow_dir_replace=False,
                    )
                if "system/af-systemd-sandbox" in rel_files:
                    atomic_write_regular_in_dir(
                        sbin_fd,
                        "af-systemd-sandbox",
                        rel_files["system/af-systemd-sandbox"],
                        allow_dir_replace=False,
                    )
                try:
                    heal_st = os.stat("af-heal", dir_fd=sbin_fd, follow_symlinks=False)
                except FileNotFoundError:
                    heal_st = None
                if heal_st is not None and (not stat.S_ISDIR(heal_st.st_mode) or stat.S_ISLNK(heal_st.st_mode)):
                    os.unlink("af-heal", dir_fd=sbin_fd)
                    fsync_dir_best_effort(sbin_fd)
            finally:
                os.close(sbin_fd)
PY
)"; then
        if declare -F log_error >/dev/null 2>&1; then
            log_error "Failed to atomically sync package and system helpers: ${sync_err}"
        else
            printf '[ERROR] Failed to atomically sync package and system helpers: %s\n' "${sync_err}" >&2
        fi
        return 1
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
    if [[ -L "${bin_dir}" ]]; then
        log_error "Refusing symlinked CLI bin directory: ${bin_dir}"
        return 1
    fi
    if ! mkdir -p "${bin_dir}"; then
        log_error "Failed to create CLI bin directory: ${bin_dir}"
        return 1
    fi
    local af_target=""
    if [[ -x "${CURRENT_LINK}/bin/af" ]]; then
        af_target="${CURRENT_LINK}/bin/af"
    elif [[ -x "${CURRENT_LINK}/af" ]]; then
        af_target="${CURRENT_LINK}/af"
    fi
    if [[ -n "${af_target}" ]]; then
        if [[ ! -e "${bin_dir}/af" || -L "${bin_dir}/af" ]]; then
            local tmp_af_link="${bin_dir}/.af.tmp.$$.${RANDOM}"
            if ! ln -s "${af_target}" "${tmp_af_link}"; then
                log_error "Failed to stage CLI symlink at ${tmp_af_link}"
                return 1
            fi
            if ! mv -Tf "${tmp_af_link}" "${bin_dir}/af"; then
                rm -f "${tmp_af_link}" 2>/dev/null || true
                log_error "Failed to atomically install CLI symlink at ${bin_dir}/af"
                return 1
            fi
        fi
    fi
}

symlink_swap() {
    log_info "=== STAGE 2: Atomic Symlink Swap ==="

    sync_legacy_package_paths --preflight-only "${RELEASE_DIR}" || return 1

    if [[ -L "${CURRENT_LINK}" ]]; then
        local previous_target
        previous_target="$(readlink -f "${CURRENT_LINK}")"
        write_atomic_private_file "${RELEASES_DIR}/.previous_release" "0644" "${previous_target}"$'\n' || return 1
        log_info "Previous release recorded: ${previous_target}"
    fi

    local tmp_link="${CURRENT_LINK}.tmp.${EPOCH}.$$.${RANDOM}"
    ln -s "${RELEASE_DIR}" "${tmp_link}"
    mv -Tf "${tmp_link}" "${CURRENT_LINK}"
    sync_cli_entrypoints || return 1
    sync_legacy_package_paths || return 1

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
        if [[ -L /run/aetherflow ]]; then
            printf 'Refusing symlinked host directory: /run/aetherflow\n' >&2
            return 1
        fi
        mkdir -p /run/aetherflow
        chown root:aetherflow /run/aetherflow
        chmod 0750 /run/aetherflow
    fi

    local transcode_src="${CURRENT_LINK}/bin/af-transcode"
    local shim_path="${TRANSCODE_SHIM_PATH:-}"
    if [[ -z "${shim_path}" ]]; then
        if [[ -n "${EFFECTIVE_RELEASE_ROOT:-}" ]]; then
            shim_path="${EFFECTIVE_RELEASE_ROOT%/}/usr/lib/aetherflow/transcode/ffmpeg"
        else
            shim_path="/usr/lib/aetherflow/transcode/ffmpeg"
        fi
    fi
    if [[ -n "${EFFECTIVE_RELEASE_ROOT:-}" ]]; then
        if [[ "${shim_path}" != /* || "${shim_path}" == *".."* || ( "${shim_path}" != "${EFFECTIVE_RELEASE_ROOT%/}" && "${shim_path}" != "${EFFECTIVE_RELEASE_ROOT%/}/"* ) ]]; then
            printf 'Configured TRANSCODE_SHIM_PATH=%s escapes isolated release root %s\n' "${shim_path}" "${EFFECTIVE_RELEASE_ROOT}" >&2
            return 1
        fi
    fi
    local shim_dir shim_parent
    shim_dir="$(dirname "${shim_path}")"
    shim_parent="$(dirname "${shim_dir}")"
    if [[ -L "${shim_parent}" || -L "${shim_dir}" || -L "${shim_path}" ]]; then
        printf 'Refusing symlinked transcode shim path: %s\n' "${shim_path}" >&2
        return 1
    fi
    if [[ -e "${shim_path}" && ! -f "${shim_path}" ]]; then
        printf 'Refusing non-regular transcode shim path: %s\n' "${shim_path}" >&2
        return 1
    fi
    if [[ ! -L "${shim_path}" && -f "${shim_path}" ]]; then
        if [[ -L "${CURRENT_LINK}/bin" || -L "${transcode_src}" ]]; then
            printf 'Refusing symlinked transcode binary source: %s\n' "${transcode_src}" >&2
            return 1
        fi
        if [[ -f "${transcode_src}" && -x "${transcode_src}" ]]; then
            local tmp_shim=""
            tmp_shim="$(mktemp "${shim_dir}/.ffmpeg.tmp.XXXXXX")" || return 1
            if ! install -m 0755 -- "${transcode_src}" "${tmp_shim}" || ! mv -Tf -- "${tmp_shim}" "${shim_path}"; then
                rm -f -- "${tmp_shim}"
                return 1
            fi
            log_info "Refreshed transcode shim ${shim_path} from ${transcode_src}."
        fi
    fi

    systemctl daemon-reload || return 1

    systemctl stop aetherflow-frontend.service 2>/dev/null || true
    systemctl disable aetherflow-frontend.service 2>/dev/null || true
    if command -v pm2 &>/dev/null; then
        pm2 delete aetherflow-frontend aetherflow-api 2>/dev/null || true
    fi

    systemctl enable aetherflow-runner.service aetherflow-api.service >/dev/null 2>&1 || true
    systemctl restart aetherflow-runner.service || return 1
    systemctl restart aetherflow-api.service || return 1
    if systemctl is-active --quiet af-transcode-worker.service 2>/dev/null; then
        systemctl restart af-transcode-worker.service || return 1
    fi

    # Best-effort post-restart log retention housekeeping: never block Stage 3/4 recovery.
    if [[ "${EUID:-$(id -u)}" -eq 0 && -z "${EFFECTIVE_RELEASE_ROOT:-}" ]] && id -u aetherflow >/dev/null 2>&1; then
        if [[ -L /var/log/aetherflow ]]; then
            log_warn "Skipping /var/log/aetherflow ownership setup because path is a symlink."
        elif ! mkdir -p /var/log/aetherflow || ! chown root:aetherflow /var/log/aetherflow || ! chmod 0750 /var/log/aetherflow; then
            log_warn "Best-effort /var/log/aetherflow ownership setup failed; continuing."
        fi
    fi
    if [[ -f "${CURRENT_LINK}/deploy/log-retention.py" ]]; then
        if ! systemctl enable --now aetherflow-log-retention.timer; then
            log_warn "Best-effort systemctl enable --now aetherflow-log-retention.timer failed; continuing."
        fi
        if ! systemctl start aetherflow-log-retention.service; then
            log_warn "Best-effort systemctl start aetherflow-log-retention.service failed; continuing."
        fi
    fi
}

# Top-level "status" from a /health/ready body. Key order and whitespace do not matter.
# v4 Rust returns {"database":"ok","runner":"ok","redis":"disabled","status":"ready","uptime":"0.0s","version":"..."}
# (older supported v4 rollback slots without "runner" or with {"status":"ok"} remain accepted).
parse_health_status() {
    local response="$1"
    if command -v python3 >/dev/null 2>&1; then
        printf '%s' "${response}" | python3 -I -c '
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
    python3 -I - "${1}" "${SQLITE_DB}.bak" <<'PY'
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

    [[ ! -e "${db_path}" && ! -L "${db_path}" && ! -f "${bak_path}" ]] && return 0

    if ! has_python_sqlite3; then
        log_error "python3 sqlite3 is absent; cannot verify integrity for ${db_path}."
        return 1
    fi

    local integrity="missing"
    if [[ -L "${db_path}" ]]; then
        integrity="error"
    elif [[ -f "${db_path}" ]]; then
        integrity="$(sqlite_integrity "${db_path}")"
    elif [[ -e "${db_path}" ]]; then
        integrity="error"
    fi
    if [[ "${integrity}" == "ok" ]]; then
        log_info "Database integrity check PASSED (${db_path})."
        return 0
    fi

    log "CRITICAL" "DATABASE CORRUPTION DETECTED (${integrity}) at ${db_path} — Restoring snapshot..."
    if [[ ! -f "${bak_path}" || -L "${bak_path}" ]]; then
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
    if [[ -f "${db_path}" && ! -L "${db_path}" ]]; then
        local post_stop_integrity
        post_stop_integrity="$(sqlite_integrity "${db_path}")"
        if [[ "${post_stop_integrity}" == "ok" ]]; then
            log_info "Quiesced database integrity check PASSED (${db_path}); skipping snapshot overwrite."
            return 0
        fi
    fi
    atomic_publish_db_file "restore" "${bak_path}" "${db_path}" || return 1
    log "CRITICAL" "Database RESTORED to ${db_path} from verified snapshot: ${bak_path}"
}

rollback() {
    local snapshot_release="${1:-}"
    log_error "=== STAGE 4: ROLLBACK INITIATED ==="
    local prev_file="${RELEASES_DIR}/.previous_release"
    if [[ ! -f "${prev_file}" && -n "${RECOVERY_PREVIOUS_RELEASE}" && -d "${RECOVERY_PREVIOUS_RELEASE}" && ! -L "${prev_file}" ]]; then
        write_atomic_private_file "${prev_file}" "0644" "${RECOVERY_PREVIOUS_RELEASE}"$'\n' || log_fatal "Failed to persist ${prev_file}."
    fi
    if [[ -L "${prev_file}" ]]; then
        save_recovery_state "stage4_rollback"
        log_fatal "Refusing symlinked previous release record at ${prev_file}."
    fi
    if [[ ! -f "${prev_file}" ]]; then
        save_recovery_state "stage4_rollback"
        log_fatal "No previous release record found at ${prev_file}."
    fi

    local previous_target
    previous_target="$(cat "${prev_file}")"
    if [[ ! -d "${previous_target}" ]]; then
        save_recovery_state "stage4_rollback"
        log_fatal "Previous release directory missing: ${previous_target}."
    fi

    local current_before_rollback=""
    if [[ -L "${CURRENT_LINK}" ]]; then
        current_before_rollback="$(readlink -f "${CURRENT_LINK}" 2>/dev/null || true)"
    fi
    local prev_canon
    prev_canon="$(readlink -f "${previous_target}" 2>/dev/null || printf '%s' "${previous_target}")"
    if [[ -z "${RECOVERY_CANDIDATE_RELEASE}" && -n "${current_before_rollback}" && "${current_before_rollback}" != "${prev_canon}" ]]; then
        RECOVERY_CANDIDATE_RELEASE="${current_before_rollback}"
    fi
    RECOVERY_PREVIOUS_RELEASE="${previous_target}"
    save_recovery_state "stage4_rollback"

    local tmp_link="${CURRENT_LINK}.rollback.${EPOCH}.$$.${RANDOM}"
    ln -s "${previous_target}" "${tmp_link}"
    mv -Tf "${tmp_link}" "${CURRENT_LINK}"
    ROLLBACK_POST_SWAP_ACTIVE=true
    save_recovery_state "stage4_rollback"
    local cli_sync_failed=0 helper_sync_failed=0
    if ! sync_cli_entrypoints; then
        cli_sync_failed=1
        log_error "Rollback CLI entrypoint sync failed; continuing database recovery and health probe."
    fi
    if ! sync_legacy_package_paths; then
        helper_sync_failed=1
        log_error "Rollback package/helper sync failed; continuing database recovery and health probe."
    fi
    log_info "Symlink reverted: ${CURRENT_LINK} -> ${previous_target}"

    if [[ -z "${snapshot_release}" ]]; then
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
    if [[ "${cli_sync_failed}" -ne 0 || "${helper_sync_failed}" -ne 0 ]]; then
        log_fatal "Rollback reverted symlink and restored service health, but entrypoint/helper sync failed (cli=${cli_sync_failed}, helpers=${helper_sync_failed})."
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
    if ! python3 -I - "${RESOLVED_DB_PATH}" "${COMMAND}" "${EFFECTIVE_RELEASE_ROOT:-}" <<'PY'
import datetime, fcntl, os, pathlib, sqlite3, stat, sys, time, uuid

database = pathlib.Path(sys.argv[1])
command = sys.argv[2]
confine_root_raw = sys.argv[3] if len(sys.argv) > 3 else ""
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
MAX_SCRATCH_BYTES = 2 * 1024 * 1024 * 1024
is_root = os.geteuid() == 0

def open_dir_nofollow(dir_str):
    p = pathlib.PurePosixPath(os.path.abspath(dir_str))
    if ".." in p.parts:
        raise OSError(f"parent traversal in path: {dir_str}")
    confine = pathlib.PurePosixPath(confine_root_raw.rstrip("/") or "/") if confine_root_raw else None
    if confine is not None:
        try:
            rel_parts = p.relative_to(confine).parts
            anchor = pathlib.Path(str(confine))
        except ValueError:
            rel_parts = p.parts[1:]
            anchor = pathlib.Path("/")
    else:
        rel_parts = p.parts[1:]
        anchor = pathlib.Path("/")
    cur_fd = os.open(str(anchor), os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    try:
        for part in rel_parts:
            nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
            os.close(cur_fd)
            cur_fd = nxt_fd
        return cur_fd
    except Exception:
        os.close(cur_fd)
        raise

def is_trusted_root_path_dir(dir_str, allow_sticky):
    dp = pathlib.PurePosixPath(os.path.abspath(dir_str))
    if not dp.is_absolute() or ".." in dp.parts:
        return False
    cur_p = pathlib.Path("/")
    for part in dp.parts:
        cur_p = pathlib.Path("/") if part == "/" else cur_p / part
        try:
            cst = os.lstat(cur_p)
        except OSError:
            return False
        if stat.S_ISLNK(cst.st_mode) or not stat.S_ISDIR(cst.st_mode) or cst.st_uid != 0:
            return False
        writable = (cst.st_mode & 0o022) != 0
        sticky = (cst.st_mode & getattr(stat, "S_ISVTX", 0o1000)) != 0
        if writable and not (allow_sticky and sticky):
            return False
    return True

def copy_fd(in_fd, out_dir_fd, out_name, remaining_cap):
    out_fd = os.open(out_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600, dir_fd=out_dir_fd)
    copied = 0
    tail8 = b""
    try:
        while True:
            chunk = os.read(in_fd, 65536)
            if not chunk:
                break
            copied += len(chunk)
            if copied > remaining_cap:
                raise OSError("lifecycle scratch copy cap exceeded")
            tail8 = (tail8 + chunk)[-8:]
            view = memoryview(chunk)
            while view:
                w = os.write(out_fd, view)
                if w <= 0:
                    raise OSError("short write")
                view = view[w:]
        if out_name.endswith("-journal") and copied >= 16 and tail8 == b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7":
            raise OSError("forbidden SQLite super-journal trailer")
        return remaining_cap - copied
    finally:
        os.close(out_fd)

def create_root_scratch(min_free=16 * 1024 * 1024):
    sc_name = f".af-root-lc.{os.getpid()}.{uuid.uuid4().hex}"
    for cand in ("/var/tmp", "/tmp", "/run"):
        if not is_trusted_root_path_dir(cand, allow_sticky=True):
            continue
        cand_fd = -1
        try:
            cand_fd = os.open(cand, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            vfs = os.fstatvfs(cand_fd)
            avail = vfs.f_bavail * (vfs.f_frsize or vfs.f_bsize)
            if avail < min_free:
                os.close(cand_fd)
                continue
            os.mkdir(sc_name, 0o700, dir_fd=cand_fd)
            sc_fd = os.open(sc_name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cand_fd)
            if not stat.S_ISDIR(os.fstat(sc_fd).st_mode) or os.fstat(sc_fd).st_uid != 0:
                os.close(sc_fd)
                os.rmdir(sc_name, dir_fd=cand_fd)
                os.close(cand_fd)
                continue
            os.fchmod(sc_fd, 0o700)
            return cand_fd, sc_fd, sc_name, os.path.join(cand, sc_name)
        except OSError:
            if cand_fd >= 0:
                os.close(cand_fd)
    raise SystemExit("Cannot verify application lifecycle journal: failed to create root scratch dir")

def open_hardened_sqlite(target, *, uri=False, timeout=5):
    conn = sqlite3.connect(target, uri=uri, timeout=timeout)
    try:
        conn.execute("PRAGMA trusted_schema = OFF;")
    except Exception:
        conn.close()
        raise
    return conn

def close_fds(fds):
    for fd_c in fds:
        if fd_c >= 0:
            os.close(fd_c)

def open_validated_db_and_sidecars(parent_fd, leaf):
    db_fd = os.open(leaf, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=parent_fd)
    wal_fd = -1
    jrn_fd = -1
    try:
        st = os.fstat(db_fd)
        if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
            raise OSError("lifecycle database must be an exclusive regular non-symlink file")
        total_sz = st.st_size
        for suffix in ("-wal", "-shm", "-journal"):
            try:
                sc_fd = os.open(leaf + suffix, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=parent_fd)
            except FileNotFoundError:
                continue
            sc_st = os.fstat(sc_fd)
            if not stat.S_ISREG(sc_st.st_mode) or sc_st.st_nlink != 1:
                os.close(sc_fd)
                raise OSError(f"lifecycle database sidecar {suffix} must be an exclusive regular file")
            if suffix == "-wal":
                wal_fd = sc_fd
                total_sz += sc_st.st_size
            elif suffix == "-journal":
                if sc_st.st_size >= 16:
                    os.lseek(sc_fd, -8, os.SEEK_END)
                    jtail = os.read(sc_fd, 8)
                    os.lseek(sc_fd, 0, os.SEEK_SET)
                    if jtail == b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7":
                        os.close(sc_fd)
                        raise OSError("lifecycle database -journal contains forbidden super-journal trailer")
                jrn_fd = sc_fd
                total_sz += sc_st.st_size
            else:
                os.close(sc_fd)
        return db_fd, wal_fd, jrn_fd, total_sz
    except Exception:
        for fd_c in (db_fd, wal_fd, jrn_fd):
            if fd_c >= 0:
                os.close(fd_c)
        raise

db_abs = os.path.abspath(str(database))
parent_str = os.path.dirname(db_abs)
leaf_name = os.path.basename(db_abs)
try:
    parent_fd = open_dir_nofollow(parent_str)
except FileNotFoundError:
    sys.exit(0)
except OSError as exc:
    sys.exit(0 if command == "rollback" else f"Cannot verify application lifecycle journal: {exc}")

def db_files_root_owned_safe(pfd, lname):
    for sfx in ("", "-wal", "-shm", "-journal"):
        try:
            fst = os.stat(lname + sfx, dir_fd=pfd, follow_symlinks=False)
        except FileNotFoundError:
            fst = None
        if fst is not None and (fst.st_uid != 0 or (fst.st_mode & 0o022) != 0):
            return False
    return True

use_scratch = is_root and (
    not is_trusted_root_path_dir(parent_str, allow_sticky=False)
    or not db_files_root_owned_safe(parent_fd, leaf_name)
)
attempts = 3 if use_scratch else 1
last_db_error = None

try:
    for attempt in range(attempts):
        sc_tuple = None
        db_fd = wal_fd = jrn_fd = -1
        try:
            try:
                db_fd, wal_fd, jrn_fd, total_sz = open_validated_db_and_sidecars(parent_fd, leaf_name)
            except FileNotFoundError:
                sys.exit(0)
            except OSError as exc:
                sys.exit(0 if command == "rollback" else f"Cannot verify application lifecycle journal: {exc}")
            try:
                header = os.read(db_fd, 16)
                if not header:
                    sys.exit(0)
                if header != b"SQLite format 3\x00":
                    sys.exit(0 if command == "rollback" else "Cannot verify application lifecycle journal: invalid SQLite header")

                if use_scratch:
                    if total_sz > MAX_SCRATCH_BYTES:
                        sys.exit(f"Cannot verify application lifecycle journal: database exceeds {MAX_SCRATCH_BYTES} byte cap")
                    sc_tuple = create_root_scratch(total_sz * 2 + 16 * 1024 * 1024)
                    sc_base_fd, sc_fd, sc_name, sc_path = sc_tuple
                    os.lseek(db_fd, 0, os.SEEK_SET)
                    rem_cap = copy_fd(db_fd, sc_fd, "inspect.sqlite", MAX_SCRATCH_BYTES)
                    if wal_fd >= 0:
                        rem_cap = copy_fd(wal_fd, sc_fd, "inspect.sqlite-wal", rem_cap)
                    if jrn_fd >= 0:
                        copy_fd(jrn_fd, sc_fd, "inspect.sqlite-journal", rem_cap)
                    inspect_target = os.path.join(sc_path, "inspect.sqlite")
                else:
                    inspect_target = db_abs
            finally:
                for fd_c in (db_fd, wal_fd, jrn_fd):
                    if fd_c >= 0:
                        os.close(fd_c)
                db_fd = wal_fd = jrn_fd = -1

            if use_scratch:
                connection = open_hardened_sqlite(inspect_target, timeout=5)
            else:
                connection = open_hardened_sqlite(pathlib.Path(inspect_target).as_uri() + "?mode=ro", uri=True, timeout=5)
            try:
                table = connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='package_lifecycle_jobs'").fetchone()
                if not table:
                    sys.exit(0)
                columns = {row[1] for row in connection.execute("PRAGMA table_info(package_lifecycle_jobs)")}
                stale = []
                held_leases = []
                owners_dir_name = pathlib.Path(leaf_name).with_suffix(".lifecycle-owners").name
                owners_fd = -1
                try:
                    owners_fd = os.open(owners_dir_name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=parent_fd)
                except OSError:
                    owners_fd = -1
                try:
                    if "owner_id" in columns and owners_fd >= 0:
                        for package, job, owner in connection.execute("SELECT package_id,job_id,owner_id FROM package_lifecycle_jobs WHERE status IN ('installing','updating','uninstalling')").fetchall():
                            lease = None
                            try:
                                uuid.UUID(owner)
                                descriptor = os.open(owner, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=owners_fd)
                                lease = os.fdopen(descriptor, "rb")
                                lst = os.fstat(lease.fileno())
                                if not stat.S_ISREG(lst.st_mode) or lst.st_nlink != 1:
                                    lease.close()
                                    continue
                                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                                held_leases.append(lease)
                                stale.append((package, job, owner))
                            except (OSError, ValueError, TypeError):
                                if lease is not None:
                                    lease.close()
                                continue
                    if stale:
                        now = datetime.datetime.now(datetime.timezone.utc).isoformat()
                        if use_scratch:
                            # Never reopen live /var/lib/aetherflow/aetherflow.sqlite RW as root:
                            # reconcile stale rows strictly on the isolated scratch replica.
                            connection.executemany(
                                "UPDATE package_lifecycle_jobs SET status='interrupted',finished_at=? WHERE package_id=? AND job_id=? AND owner_id=? AND status IN ('installing','updating','uninstalling')",
                                [(now, package, job, owner) for package, job, owner in stale],
                            )
                            connection.commit()
                            active = connection.execute("SELECT 1 FROM package_lifecycle_jobs WHERE status NOT IN ('completed','failed','interrupted') LIMIT 1").fetchone()
                        else:
                            rw_fds = open_validated_db_and_sidecars(parent_fd, leaf_name)
                            close_fds(rw_fds[:3])
                            rw = open_hardened_sqlite(pathlib.Path(db_abs).as_uri() + "?mode=rw", uri=True, timeout=5)
                            try:
                                rw.executemany(
                                    "UPDATE package_lifecycle_jobs SET status='interrupted',finished_at=? WHERE package_id=? AND job_id=? AND owner_id=? AND status IN ('installing','updating','uninstalling')",
                                    [(now, package, job, owner) for package, job, owner in stale],
                                )
                                rw.commit()
                                active = rw.execute("SELECT 1 FROM package_lifecycle_jobs WHERE status NOT IN ('completed','failed','interrupted') LIMIT 1").fetchone()
                            finally:
                                rw.close()
                    else:
                        active = connection.execute("SELECT 1 FROM package_lifecycle_jobs WHERE status NOT IN ('completed','failed','interrupted') LIMIT 1").fetchone()
                finally:
                    if owners_fd >= 0:
                        os.close(owners_fd)
                    for held in held_leases:
                        try:
                            held.close()
                        except OSError:
                            _ = held
                if active:
                    sys.exit("Application lifecycle orchestration is active or its owner is unknown")
                sys.exit(0)
            finally:
                connection.close()
        except sqlite3.DatabaseError as error:
            last_db_error = error
            if attempt + 1 < attempts:
                time.sleep(0.025)
                continue
        finally:
            if sc_tuple is not None:
                sc_base_fd, sc_fd, sc_name, _ = sc_tuple
                for leftover in ("inspect.sqlite", "inspect.sqlite-wal", "inspect.sqlite-shm", "inspect.sqlite-journal"):
                    try:
                        os.unlink(leftover, dir_fd=sc_fd)
                    except FileNotFoundError:
                        _ = leftover
                os.close(sc_fd)
                try:
                    os.rmdir(sc_name, dir_fd=sc_base_fd)
                except OSError:
                    _ = sc_name
                os.close(sc_base_fd)

    if last_db_error is not None:
        code = getattr(last_db_error, "sqlite_errorcode", None)
        # Python 3.10 has neither sqlite_errorcode nor the SQLITE_* constants.
        corrupt = (code is not None and (code & 255) in (11, 26)) or (
            code is None and str(last_db_error) in ("database disk image is malformed", "file is not a database")
        )
        if command == "rollback" and corrupt:
            sys.exit(0)
        sys.exit(f"Cannot verify application lifecycle journal: {last_db_error}")
finally:
    os.close(parent_fd)
PY
    then
        log_fatal "Application lifecycle admission is unavailable; release was not started."
    fi
}

guard_and_init_recovery_state() {
    local parsed=""
    if ! parsed="$(python3 -I - "${RELEASES_DIR}" "${CURRENT_LINK}" "${COMMAND}" "${CHANNEL:-stable}" "${DRY_RUN:-false}" "${AETHERFLOW_UPDATE_OPERATION_ID:-}" <<'PY'
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
        and not ex_dry
        and (
            phase == "stage4_rollback"
            or (
                ex_cmd in ("", "deploy")
                and phase in ("stage2_symlink_swap", "stage3_health_probe")
            )
        )
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
            tmp_prev_name = f".previous_release.tmp.{os.getpid()}.{uuid.uuid4().hex}"
            rel_dfd = os.open(str(releases_dir), os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
            try:
                tfd = os.open(tmp_prev_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0), 0o644, dir_fd=rel_dfd)
                try:
                    payload = (ex_prev + "\n").encode("utf-8")
                    view = memoryview(payload)
                    while view:
                        w = os.write(tfd, view)
                        if w <= 0:
                            raise OSError("short write restoring .previous_release")
                        view = view[w:]
                    os.fchmod(tfd, 0o644)
                    os.fsync(tfd)
                except BaseException:
                    os.close(tfd)
                    try:
                        os.unlink(tmp_prev_name, dir_fd=rel_dfd)
                    except OSError as rm_err:
                        _ = rm_err
                    raise
                os.close(tfd)
                os.replace(tmp_prev_name, ".previous_release", src_dir_fd=rel_dfd, dst_dir_fd=rel_dfd)
            finally:
                os.close(rel_dfd)
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

AF_LOCK_COPROC_PID=""
AF_LOCK_COPROC_IN_FD=""
AF_LOCK_COPROC_OUT_FD=""

_start_fd_lock_coproc() {
    if [[ -n "${AF_LOCK_COPROC_PID:-}" ]]; then
        return 0
    fi
    local py_lock_holder=""
    IFS= read -r -d '' py_lock_holder <<'PY' || true
import ctypes, errno, fcntl, json, os, pathlib, pwd, select, signal, stat, sys, time

confine_root_raw = sys.argv[1] if len(sys.argv) > 1 else ""
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
is_root = os.geteuid() == 0
initial_ppid = os.getppid()

signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
# Ensure the lock holder exits immediately if the parent shell receives SIGKILL.
try:
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.prctl(1, signal.SIGTERM, 0, 0, 0)  # PR_SET_PDEATHSIG = 1
except OSError:
    _ = initial_ppid
if os.getppid() != initial_ppid:
    sys.exit(0)

def open_or_create_dir_nofollow(dir_str, create_mode):
    p = pathlib.PurePosixPath(os.path.abspath(dir_str))
    if ".." in p.parts:
        raise OSError(f"parent traversal in lock path: {dir_str}")
    confine = pathlib.PurePosixPath(confine_root_raw.rstrip("/") or "/") if confine_root_raw else None
    if confine is not None:
        try:
            rel_parts = p.relative_to(confine).parts
            anchor = pathlib.Path(str(confine))
        except ValueError:
            raise OSError(f"lock path escapes isolated root {confine}: {dir_str}")
        if not os.path.lexists(anchor):
            os.makedirs(anchor, mode=0o755, exist_ok=True)
    else:
        rel_parts = p.parts[1:]
        anchor = pathlib.Path("/")
    cur_fd = os.open(str(anchor), os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    try:
        for part in rel_parts:
            created_now = False
            try:
                nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(part, create_mode, dir_fd=cur_fd)
                    created_now = True
                except FileExistsError:
                    created_now = False
                nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
            if created_now:
                os.fchmod(nxt_fd, create_mode)
            os.close(cur_fd)
            cur_fd = nxt_fd
        return cur_fd
    except Exception:
        os.close(cur_fd)
        raise

def resolve_target_owner(parent_fd):
    uid_env = os.environ.get("AETHERFLOW_SERVICE_UID", "").strip()
    gid_env = os.environ.get("AETHERFLOW_SERVICE_GID", "").strip()
    if uid_env.isdigit() and gid_env.isdigit():
        return int(uid_env), int(gid_env)
    pst = os.fstat(parent_fd)
    if pst.st_uid != 0 and (pst.st_mode & getattr(stat, "S_ISVTX", 0o1000)) == 0:
        return pst.st_uid, pst.st_gid
    svc_user = os.environ.get("AETHERFLOW_SERVICE_USER", "").strip() or "aetherflow"
    try:
        pw = pwd.getpwnam(svc_user)
        return (int(uid_env) if uid_env.isdigit() else pw.pw_uid, int(gid_env) if gid_env.isdigit() else pw.pw_gid)
    except KeyError:
        return None

def acquire_one_lock(lock_path, timeout_s, shared_mode, is_runtime_anchor):
    abs_p = os.path.abspath(lock_path)
    parent_str = os.path.dirname(abs_p)
    leaf_name = os.path.basename(abs_p)
    if not leaf_name or leaf_name in (".", ".."):
        raise OSError(f"invalid lock filename: {lock_path}")
    dir_mode = 0o750 if shared_mode else 0o755
    file_mode = 0o660 if shared_mode else 0o600
    deadline = time.monotonic() + max(0.0, float(timeout_s))

    while True:
        parent_fd = open_or_create_dir_nofollow(parent_str, dir_mode)
        lock_fd = -1
        try:
            parent_st = os.fstat(parent_fd)
            target_owner = resolve_target_owner(parent_fd) if (is_root and shared_mode) else None
            if is_root and is_runtime_anchor:
                if target_owner is not None:
                    os.fchown(parent_fd, 0, target_owner[1])
                os.fchmod(parent_fd, 0o750)
            created_fresh = False
            try:
                lock_fd = os.open(leaf_name, os.O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=parent_fd)
            except FileNotFoundError:
                try:
                    lock_fd = os.open(leaf_name, os.O_RDWR | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, file_mode, dir_fd=parent_fd)
                    created_fresh = True
                except FileExistsError:
                    try:
                        lock_fd = os.open(leaf_name, os.O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=parent_fd)
                    except FileNotFoundError:
                        os.close(parent_fd)
                        parent_fd = -1
                        if time.monotonic() >= deadline:
                            raise TimeoutError(f"Could not acquire lock {lock_path} within {timeout_s}s")
                        time.sleep(0.05)
                        continue
            st = os.fstat(lock_fd)
            if not stat.S_ISREG(st.st_mode):
                raise OSError(f"lockfile is not a regular file: {lock_path}")
            if st.st_nlink != 1:
                raise OSError(f"lockfile must not have multiple hard links: {lock_path}")
            if shared_mode:
                if is_root:
                    if not is_runtime_anchor and parent_st.st_uid != 0 and not created_fresh:
                        expected_uid = target_owner[0] if target_owner is not None else parent_st.st_uid
                        if st.st_uid == 0 or st.st_uid != expected_uid:
                            raise OSError(f"refusing to chown pre-existing file (uid={st.st_uid}) at maintenance lock path inside non-root directory (uid={parent_st.st_uid}): {lock_path}")
                    if target_owner is not None:
                        desired_uid = 0 if is_runtime_anchor else target_owner[0]
                        os.fchown(lock_fd, desired_uid, target_owner[1])
                    os.fchmod(lock_fd, 0o660)
                elif st.st_uid == os.geteuid() and (st.st_mode & 0o777) != 0o660:
                    os.fchmod(lock_fd, 0o660)
            elif is_root or st.st_uid == os.geteuid():
                if (st.st_mode & 0o777) != 0o600:
                    os.fchmod(lock_fd, 0o600)
            while True:
                try:
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise TimeoutError(f"Could not acquire lock {lock_path} within {timeout_s}s")
                    time.sleep(0.05)
            # Post-flock verification: confirm our locked inode is still the live regular entry.
            held_st = os.fstat(lock_fd)
            try:
                live_st = os.stat(leaf_name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                os.close(lock_fd)
                os.close(parent_fd)
                lock_fd = parent_fd = -1
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"Lockfile {lock_path} unlinked during acquisition")
                time.sleep(0.05)
                continue
            if (
                not stat.S_ISREG(live_st.st_mode)
                or held_st.st_nlink != 1
                or live_st.st_nlink != 1
                or (held_st.st_dev, held_st.st_ino) != (live_st.st_dev, live_st.st_ino)
            ):
                os.close(lock_fd)
                os.close(parent_fd)
                lock_fd = parent_fd = -1
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"Lockfile {lock_path} identity changed during acquisition")
                time.sleep(0.05)
                continue
            return parent_fd, lock_fd
        except BaseException:
            if lock_fd >= 0:
                os.close(lock_fd)
            if parent_fd >= 0:
                os.close(parent_fd)
            raise

held_locks = []
stdin_fd = sys.stdin.fileno()
buf = b""
try:
    while True:
        ready, _, _ = select.select([stdin_fd], [], [], 0.5)
        if os.getppid() != initial_ppid:
            break
        if not ready:
            continue
        chunk = os.read(stdin_fd, 4096)
        if not chunk:
            break
        buf += chunk
        while b"\n" in buf:
            raw_line, buf = buf.split(b"\n", 1)
            line = raw_line.decode("utf-8", errors="replace").strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                pair = acquire_one_lock(
                    req["path"],
                    req["timeout"],
                    bool(req.get("shared", False)),
                    bool(req.get("runtime_anchor", False)),
                )
                held_locks.append(pair)
                sys.stdout.write("LOCKED\n")
                sys.stdout.flush()
            except Exception as exc:
                sys.stdout.write("ERR:" + str(exc).replace("\n", " ") + "\n")
                sys.stdout.flush()
                raise SystemExit(1)
finally:
    for pfd, lfd in reversed(held_locks):
        os.close(lfd)
        os.close(pfd)
PY
    coproc AF_LOCK_COPROC {
        exec python3 -I -u -c "${py_lock_holder}" "${EFFECTIVE_RELEASE_ROOT:-}"
    }
    AF_LOCK_COPROC_PID="${AF_LOCK_COPROC_PID:-$!}"
    AF_LOCK_COPROC_OUT_FD="${AF_LOCK_COPROC[0]}"
    AF_LOCK_COPROC_IN_FD="${AF_LOCK_COPROC[1]}"
}

acquire_fd_lock_coproc() {
    local _label="$1"
    local lock_path="$2"
    local timeout_s="$3"
    local shared_flag="${4:-false}"
    local runtime_anchor_flag="${5:-false}"
    _start_fd_lock_coproc
    local req_json
    req_json="$(python3 -I -c 'import json, sys; print(json.dumps({"path": sys.argv[1], "timeout": float(sys.argv[2]), "shared": sys.argv[3] == "true", "runtime_anchor": sys.argv[4] == "true"}))' "${lock_path}" "${timeout_s}" "${shared_flag}" "${runtime_anchor_flag}")"
    printf '%s\n' "${req_json}" >&"${AF_LOCK_COPROC_IN_FD}"
    local reply=""
    if ! IFS= read -r reply <&"${AF_LOCK_COPROC_OUT_FD}"; then
        reply="ERR:lock holder terminated unexpectedly"
    fi
    if [[ "${reply}" != "LOCKED" ]]; then
        log_fatal "Could not acquire ${_label} (${lock_path}): ${reply#ERR:}"
    fi
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
            elif [[ -n "${EFFECTIVE_RELEASE_ROOT}" && "${db_parent%/}" == "${EFFECTIVE_RELEASE_ROOT}/var/lib/aetherflow" ]] && {
                [[ -d "${EFFECTIVE_RELEASE_ROOT}/run/aetherflow" ]] || python3 -I - "${EFFECTIVE_RELEASE_ROOT}" "${db_parent}" <<'PY' >/dev/null 2>&1
import os, sys
root_st = os.lstat(sys.argv[1])
var_st = os.lstat(sys.argv[2])
sys.exit(0 if (root_st.st_uid == 0 and var_st.st_uid != 0) else 1)
PY
            }; then
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

    local shared_lock_dir is_runtime_anchor=false
    shared_lock_dir="$(dirname "${shared_db_lock}")"
    if [[ "${shared_lock_dir%/}" == "/run/aetherflow" || ( -n "${EFFECTIVE_RELEASE_ROOT}" && "${shared_lock_dir%/}" == "${EFFECTIVE_RELEASE_ROOT}/run/aetherflow" ) ]]; then
        is_runtime_anchor=true
    fi

    acquire_fd_lock_coproc "maintenance lock" "${shared_db_lock}" "${SNAPSHOT_TIMEOUT}" "true" "${is_runtime_anchor}"
    check_package_lifecycle_reservations
    local release_lock="${RELEASES_DIR}/.release.lock"
    acquire_fd_lock_coproc "release lock" "${release_lock}" "${SNAPSHOT_TIMEOUT}" "false" "false"
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
        restore_prior_previous_release() {
            local prior_prev="$1"
            if [[ -n "${prior_prev}" && -d "${prior_prev}" ]]; then
                local reverted_canon prior_canon
                reverted_canon="$(readlink -f "${CURRENT_LINK}" 2>/dev/null || true)"
                prior_canon="$(readlink -f "${prior_prev}" 2>/dev/null || printf '%s' "${prior_prev}")"
                if [[ "${prior_canon}" != "${reverted_canon}" && ! -L "${RELEASES_DIR}/.previous_release" ]]; then
                    write_atomic_private_file "${RELEASES_DIR}/.previous_release" "0644" "${prior_prev}"$'\n' || true
                fi
            fi
        }
        save_recovery_state "stage2_symlink_swap"
        if ! symlink_swap; then
            if [[ -L "${CURRENT_LINK}" && "$(readlink -f "${CURRENT_LINK}" 2>/dev/null || true)" == "$(readlink -f "${RELEASE_DIR}" 2>/dev/null || true)" && -f "${RELEASES_DIR}/.previous_release" ]]; then
                RECOVERY_FROM_UNFINISHED_POST_SWAP=true
                save_recovery_state "stage4_rollback" "${LAST_LOG_ERROR:-Post-swap helper sync failed}"
                rollback "${RELEASE_DIR}"
                restore_prior_previous_release "${PRIOR_PREVIOUS_RELEASE}"
                exit 2
            fi
            save_recovery_state "failed" "${LAST_LOG_ERROR:-Stage 2 symlink or helper sync preflight failed}"
            exit 4
        fi
        if [[ -f "${RELEASES_DIR}/.previous_release" ]]; then
            RECOVERY_PREVIOUS_RELEASE="$(cat "${RELEASES_DIR}/.previous_release")"
        fi
        save_recovery_state "stage3_health_probe"
        if ! health_probe; then
            RECOVERY_FROM_UNFINISHED_POST_SWAP=true
            save_recovery_state "stage4_rollback" "${LAST_LOG_ERROR:-Health probe failed}"
            rollback "${RELEASE_DIR}"
            restore_prior_previous_release "${PRIOR_PREVIOUS_RELEASE}"
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
