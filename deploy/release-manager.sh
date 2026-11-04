#!/bin/bash
###############################################################################
# AetherFlow Release Manager v4.0 — Pull-Based Single-Binary Atomic Engine
#
# Pulls pre-built, checksum-verified single-binary releases from GitHub Releases
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
    [[ ! -L "${SELF_UPDATE_STATUS_FILE}" ]] || return 0

    local status_dir
    status_dir="$(dirname "${SELF_UPDATE_STATUS_FILE}")"
    mkdir -p "${status_dir}" 2>/dev/null || return 0

    local tmp_status="${SELF_UPDATE_STATUS_FILE}.tmp.$$"
    if command -v python3 >/dev/null 2>&1; then
        python3 - "${tmp_status}" "${SELF_UPDATE_STATUS_FILE}" "${status_str}" "${completed_bool}" "${success_bool}" "${SELF_UPDATE_JOB_UNIT}" "${exit_code_val}" "${err_msg}" <<'PY' 2>/dev/null || true
import json, os, sys
tmp_path, final_path, status_str, completed_s, success_s, job_unit, exit_s, err_msg = sys.argv[1:9]
payload = {
    "status": status_str,
    "completed": completed_s == "true",
    "success": success_s == "true",
    "job_unit": job_unit,
    "error": err_msg,
    "exit_code": None if exit_s == "null" else int(exit_s),
}
fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as fh:
    json.dump(payload, fh)
    fh.flush()
    os.fsync(fh.fileno())
os.replace(tmp_path, final_path)
PY
    else
        local esc_err="${err_msg//\\/\\\\}"
        esc_err="${esc_err//\"/\\\"}"
        esc_err="${esc_err//$'\n'/ }"
        printf '{"status":"%s","completed":%s,"success":%s,"job_unit":"%s","error":"%s","exit_code":%s}\n' \
            "${status_str}" "${completed_bool}" "${success_bool}" "${SELF_UPDATE_JOB_UNIT}" "${esc_err}" "${exit_code_val}" > "${tmp_status}" 2>/dev/null || true
        chmod 0600 "${tmp_status}" 2>/dev/null || true
        mv -f "${tmp_status}" "${SELF_UPDATE_STATUS_FILE}" 2>/dev/null || true
    fi
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

if [[ -n "${SELF_UPDATE_STATUS_FILE}" ]]; then
    write_self_update_status_receipt "running" "false" "false" "null" ""
    trap 'finalize_self_update_status_on_exit $?' EXIT
fi

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
    "GITHUB_REPO", "RELEASE_CHANNEL", "ARTIFACT_NAME", "CHECKSUM_NAME", "GIT_BRANCH",
    "GIT_REMOTE", "GO_BIN", "NODE_HEAP_MB", "HEALTH_ENDPOINT", "HEALTH_RETRIES",
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
: "${HEALTH_ENDPOINT:=http://127.0.0.1:8080/api/v1/system/health}"
: "${ARTIFACT_NAME:=aetherflow-linux-amd64.tar.gz}"
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
mkdir -p "$(dirname "${LOG_FILE}")"

log() {
    local level="$1"
    shift
    local msg="$*"
    local ts
    ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
    local line="{\"ts\":\"${ts}\",\"level\":\"${level}\",\"msg\":\"${msg}\"}"
    echo "${line}" | tee -a "${LOG_FILE}"
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
        fi
    fi

    resolve_db_path

    # Only migrate a legacy DB when the resolved live path IS the FHS file and
    # that file is missing. Copying into DATA_DIR while the process uses another
    # path creates a divergent stale database (this host's /var/lib copy).
    local fhs_db="${CONFIG_DATA_DIR}/${SQLITE_DB}"
    if [[ "${RESOLVED_DB_PATH}" == "${fhs_db}" && ! -f "${fhs_db}" ]]; then
        local legacy_db
        for legacy_db in "${LEGACY_OPT_ROOT}/backend/data/${SQLITE_DB}" "${LEGACY_OPT_ROOT}/backend/${SQLITE_DB}"; do
            if [[ -f "${legacy_db}" ]]; then
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
        local legacy_env
        for legacy_env in "${LEGACY_OPT_ROOT}/backend/.env" "${LEGACY_OPT_ROOT}/.env"; do
            if [[ -f "${legacy_env}" ]]; then
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
resolve_release_tag() {
    local channel="$1"
    local api_url="https://api.github.com/repos/${GITHUB_REPO}/releases"
    local releases_json
    releases_json="$(curl -sfL --max-time 15 "${api_url}" 2>/dev/null)" || true

    if [[ "${channel}" == "nightly" ]]; then
        if [[ -n "${releases_json}" ]] && command -v python3 &>/dev/null; then
            local nightly_tag=""
            nightly_tag="$(printf '%s' "${releases_json}" | python3 -c '
import json, sys
try:
    for r in json.load(sys.stdin):
        if r.get("draft"):
            continue
        tag = (r.get("tag_name") or "").strip()
        target = (r.get("target_commitish") or "").strip().lower()
        if tag and tag.lower() not in ("nightly", "experimental") and target != "experimental" and "experimental" not in tag.lower() and (target == "nightly" or r.get("prerelease") or "nightly" in tag.lower()):
            print(tag)
            break
except Exception:
    pass
' 2>/dev/null)"
            if [[ -n "${nightly_tag}" ]]; then
                echo "${nightly_tag}"
                return 0
            fi
        fi
        echo "nightly"
        return 0
    fi

    if [[ -z "${releases_json}" ]]; then
        local latest_url latest_tag
        latest_url="$(curl -fsSL --max-time 15 -o /dev/null -w '%{url_effective}' "https://github.com/${GITHUB_REPO}/releases/latest" 2>/dev/null)" || return 1
        latest_tag="${latest_url##*/}"
        [[ "${latest_url}" == "https://github.com/${GITHUB_REPO}/releases/tag/"* && "${latest_tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
        printf '%s\n' "${latest_tag}"
        return 0
    fi

    if command -v python3 &>/dev/null; then
        local stable_tag=""
        stable_tag="$(printf '%s' "${releases_json}" | python3 -c '
import json, sys
try:
    for r in json.load(sys.stdin):
        if r.get("draft") or r.get("prerelease"):
            continue
        tag = (r.get("tag_name") or "").strip()
        target = (r.get("target_commitish") or "").strip().lower()
        if tag and "-" not in tag and target != "nightly":
            print(tag)
            break
except Exception:
    pass
' 2>/dev/null)"
        if [[ -n "${stable_tag}" ]]; then
            echo "${stable_tag}"
            return 0
        fi
    fi

    # Fallback: first release without a pre-release hyphen in tag_name
    echo "${releases_json}" | grep -o '"tag_name"\s*:\s*"[^"]*"' | cut -d'"' -f4 | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1
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
    if [[ -L "${RELEASE_DIR}/deploy/release-manager.sh" || -L "${RELEASE_DIR}/deploy/release-manager.conf" ]]; then
        log_error "Refusing to overwrite symlink inside ${RELEASE_DIR}/deploy."
        return 1
    fi
    if [[ -f "${SCRIPT_DIR}/release-manager.sh" ]]; then
        rm -f "${RELEASE_DIR}/deploy/release-manager.sh"
        cp -f "${SCRIPT_DIR}/release-manager.sh" "${RELEASE_DIR}/deploy/release-manager.sh"
        chmod +x "${RELEASE_DIR}/deploy/release-manager.sh"
        log_info "Staged the executing release-manager.sh into ${RELEASE_DIR}/deploy (published artifacts can predate this fix)."
    fi
    if [[ -f "${CONF_FILE}" ]]; then
        rm -f "${RELEASE_DIR}/deploy/release-manager.conf"
        cp -f "${CONF_FILE}" "${RELEASE_DIR}/deploy/release-manager.conf"
    fi
}

pull_prebuilt_artifact() {
    local tag="$1"
    local base_url="https://github.com/${GITHUB_REPO}/releases/download/${tag}"
    local tmp_dir
    tmp_dir="$(mktemp -d /tmp/af-release-XXXXXX)"

    log_info "Downloading pre-built release ${tag} (${ARTIFACT_NAME})..."
    if ! curl -fsSL --max-time 180 -o "${tmp_dir}/${ARTIFACT_NAME}" "${base_url}/${ARTIFACT_NAME}"; then
        rm -rf "${tmp_dir}"
        return 1
    fi

    log_info "Downloading SHA-256 manifest (${CHECKSUM_NAME})..."
    if ! curl -fsSL --max-time 30 -o "${tmp_dir}/${CHECKSUM_NAME}" "${base_url}/${CHECKSUM_NAME}"; then
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
    if [[ ! -s "${RELEASE_DIR}/.version" ]]; then
        echo "${tag}" > "${RELEASE_DIR}/.version"
    fi
    chmod +x "${RELEASE_DIR}/aetherflow-api"
    if [[ -f "${RELEASE_DIR}/af" && ! -L "${RELEASE_DIR}/af" ]]; then
        chmod +x "${RELEASE_DIR}/af"
        mkdir -p "${RELEASE_DIR}/bin"
        if [[ ! -e "${RELEASE_DIR}/bin/af" && ! -L "${RELEASE_DIR}/bin/af" ]]; then
            cp -f "${RELEASE_DIR}/af" "${RELEASE_DIR}/bin/af"
        fi
        chmod +x "${RELEASE_DIR}/bin/af"
    elif [[ -f "${RELEASE_DIR}/bin/af" && ! -L "${RELEASE_DIR}/bin/af" ]]; then
        chmod +x "${RELEASE_DIR}/bin/af"
        rm -f "${RELEASE_DIR}/af"
        cp -f "${RELEASE_DIR}/bin/af" "${RELEASE_DIR}/af"
        chmod +x "${RELEASE_DIR}/af"
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
    log_info "Building single-binary release from source (${GIT_REMOTE}/${target_branch})..."
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

    rsync -a --exclude='.git' --exclude='node_modules' --exclude='.next' --exclude='*.sqlite' \
        "${REPO_DIR}/" "${RELEASE_DIR}/" >> "${LOG_FILE}" 2>&1
    if [[ "${CHANNEL}" == "nightly" && ! -s "${RELEASE_DIR}/.version" ]]; then
        echo "${CHANNEL}-${source_sha}" > "${RELEASE_DIR}/.version"
    fi

    log_info "Building Next.js static export (NEXT_STATIC_EXPORT=1)..."
    cd "${RELEASE_DIR}/frontend" || log_fatal "Frontend directory missing."
    export NODE_OPTIONS="${NODE_OPTIONS:+${NODE_OPTIONS} }--max-old-space-size=${NODE_HEAP_MB}"
    export NEXT_STATIC_EXPORT="1"
    npm ci --no-fund --no-audit >> "${LOG_FILE}" 2>&1
    npm run build >> "${LOG_FILE}" 2>&1

    log_info "Embedding frontend static bundle into web/dist and backend/web/dist..."
    rm -rf "${RELEASE_DIR}/web/dist" "${RELEASE_DIR}/backend/web/dist"
    mkdir -p "${RELEASE_DIR}/web/dist" "${RELEASE_DIR}/backend/web/dist"
    cp -R "${RELEASE_DIR}/frontend/out/." "${RELEASE_DIR}/web/dist/"
    cp -R "${RELEASE_DIR}/frontend/out/." "${RELEASE_DIR}/backend/web/dist/"

    if [[ -d "${RELEASE_DIR}/backend-rs" ]] && command -v cargo &>/dev/null; then
        log_info "Compiling single-binary AetherFlow Rust control plane and CLI (backend-rs)..."
        cd "${RELEASE_DIR}/backend-rs" || log_fatal "Rust backend directory missing."
        local -a cargo_locked_args=(--locked)
        if [[ ! -f Cargo.lock ]]; then
            if [[ "${CARGO_ALLOW_UNLOCKED_DEV:-0}" == "1" ]]; then
                cargo_locked_args=()
            else
                log_error "Missing backend-rs/Cargo.lock. Refusing unlocked source build."
                return 1
            fi
        fi
        cargo build --release "${cargo_locked_args[@]}" --bin aetherflow-api --bin af >> "${LOG_FILE}" 2>&1 || return 1
        cp -f "target/release/aetherflow-api" "${RELEASE_DIR}/aetherflow-api"
        if [[ -f "target/release/af" ]]; then
            cp -f "target/release/af" "${RELEASE_DIR}/af"
            mkdir -p "${RELEASE_DIR}/bin"
            cp -f "target/release/af" "${RELEASE_DIR}/bin/af"
            chmod +x "${RELEASE_DIR}/af" "${RELEASE_DIR}/bin/af"
        fi
    else
        log_info "Compiling single-binary AetherFlow Go control plane..."
        cd "${RELEASE_DIR}/backend" || log_fatal "Backend directory missing."
        export GOOS=linux GOARCH=amd64 CGO_ENABLED=0
        "${GO_BIN}" build -trimpath -buildvcs=false -o "${RELEASE_DIR}/aetherflow-api" . >> "${LOG_FILE}" 2>&1 || return 1
    fi
    chmod +x "${RELEASE_DIR}/aetherflow-api"

    # Retain only runtime essentials (binary, af, config, packages, deploy, .version)
    rm -rf "${RELEASE_DIR}/frontend" "${RELEASE_DIR}/web/dist" "${RELEASE_DIR}/backend/web/dist" "${RELEASE_DIR}/backend-rs/target"
}

simulate_offline_artifact() {
    log_info "[DRY-RUN] Offline mode: simulating single-binary artifact verification and extraction."
    mkdir -p "${RELEASE_DIR}/deploy/systemd" "${RELEASE_DIR}/packages" "${RELEASE_DIR}/config" "${RELEASE_DIR}/bin"
    echo "#!/bin/bash" > "${RELEASE_DIR}/aetherflow-api"
    echo "#!/bin/bash" > "${RELEASE_DIR}/af"
    cp -f "${RELEASE_DIR}/af" "${RELEASE_DIR}/bin/af"
    chmod +x "${RELEASE_DIR}/aetherflow-api" "${RELEASE_DIR}/af" "${RELEASE_DIR}/bin/af"
    echo "v3.1.7-dryrun" > "${RELEASE_DIR}/.version"
    stage_running_release_manager
}

release_scaffold() {
    log_info "=== STAGE 1: Release Scaffold (Channel: ${CHANNEL}) ==="
    mkdir -p "${RELEASE_DIR}"

    if [[ "${DRY_RUN}" == true && "${OFFLINE}" == true ]]; then
        simulate_offline_artifact
        return 0
    fi

    if [[ "${OFFLINE}" == true && "${DRY_RUN}" == false ]]; then
        log_fatal "--offline is only valid with --dry-run. Refusing to deploy a placeholder binary."
    fi

    if [[ "${FROM_SOURCE}" == false ]]; then
        local target_tag=""
        target_tag="$(resolve_release_tag "${CHANNEL}" || true)"
        if [[ -z "${target_tag}" ]]; then
            log_error "Could not resolve a release tag for channel ${CHANNEL}. Refusing implicit source-build fallback."
            rm -rf "${RELEASE_DIR}"
            exit 1
        fi
        log_info "Resolved release tag ${target_tag} for channel ${CHANNEL}."
        if pull_prebuilt_artifact "${target_tag}"; then
            log_info "=== STAGE 1 COMPLETE: Pre-built release ${target_tag} staged at ${RELEASE_DIR} ==="
            return 0
        fi
        log_error "Pre-built artifact pull or verification failed for ${target_tag}. Refusing implicit source-build fallback."
        rm -rf "${RELEASE_DIR}"
        exit 1
    elif [[ "${DRY_RUN}" == true ]]; then
        log_error "[DRY-RUN] Refusing --from-source. Use a published artifact, or --offline for a placeholder."
        rm -rf "${RELEASE_DIR}"
        exit 1
    fi

    if ! build_from_source; then
        log_error "Source build failed. Cleaning up ${RELEASE_DIR}."
        rm -rf "${RELEASE_DIR}"
        exit 1
    fi

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
    if [[ -f "${RELEASE_DIR}/af" ]]; then
        chmod 0755 "${RELEASE_DIR}/af" || return 1
    fi
    if [[ "${DRY_RUN}" == false ]]; then
        if [[ "${EUID}" -eq 0 ]]; then
            if ! runuser -u "${service_user}" -- sh -c 'cd "$1" && test -r .version && test -x ./aetherflow-api' sh "${RELEASE_DIR}"; then
                log_error "Release is inaccessible to service user ${service_user}. Refusing symlink swap."
                return 1
            fi
        else
            if ! sh -c 'cd "$1" && test -r .version && test -x ./aetherflow-api' sh "${RELEASE_DIR}"; then
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

    (
        cd "${snapshot_dir}"
        sha256sum -- *.bak > MANIFEST.sha256
    ) || log_warn "Could not write snapshot SHA-256 manifest."

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
    local dest="${SYSTEMD_UNITS_DST}/$(basename "${src}")"
    [[ -f "${src}" ]] || return 0
    mkdir -p "${SYSTEMD_UNITS_DST}"
    if [[ -e "${dest}" ]]; then
        log_info "Keeping installed systemd unit ${dest}; not replacing it with ${src}."
        return 0
    fi
    cp -f "${src}" "${dest}"
    log_info "Installed systemd unit ${dest} from ${src}."
}

restart_systemd_units() {
    verify_isolated_systemd_lifecycle_authorized
    if [[ -d "${CURRENT_LINK}/deploy/systemd" ]]; then
        install_packaged_unit "${CURRENT_LINK}/deploy/systemd/aetherflow-runner.service"
        install_packaged_unit "${CURRENT_LINK}/deploy/systemd/aetherflow-api.service"
    fi

    systemctl daemon-reload

    systemctl stop aetherflow-frontend.service 2>/dev/null || true
    systemctl disable aetherflow-frontend.service 2>/dev/null || true
    if command -v pm2 &>/dev/null; then
        pm2 delete aetherflow-frontend aetherflow-api 2>/dev/null || true
    fi

    systemctl enable aetherflow-runner.service aetherflow-api.service >> "${LOG_FILE}" 2>&1 || true
    systemctl restart aetherflow-runner.service
    systemctl restart aetherflow-api.service
}

# Top-level "status" from a /health/ready body. Key order and whitespace do not matter.
# v4 Rust returns exactly {"database":"ok","redis":"disabled","status":"ready","uptime":"0.0s"}.
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

    restart_systemd_units

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
    if id -u aetherflow >/dev/null 2>&1; then
        chown aetherflow:aetherflow "${db_path}" || return 1
    fi
    chmod 0600 "${db_path}" || return 1
    log "CRITICAL" "Database RESTORED to ${db_path} from verified snapshot: ${bak_path}"
}

rollback() {
    local snapshot_release="${1:-}"
    log_error "=== STAGE 4: ROLLBACK INITIATED ==="
    local prev_file="${RELEASES_DIR}/.previous_release"
    if [[ ! -f "${prev_file}" ]]; then
        log_fatal "No previous release record found at ${prev_file}."
    fi

    local previous_target
    previous_target="$(cat "${prev_file}")"
    if [[ ! -d "${previous_target}" ]]; then
        log_fatal "Previous release directory missing: ${previous_target}."
    fi

    local tmp_link="${CURRENT_LINK}.rollback.${EPOCH}"
    ln -s "${previous_target}" "${tmp_link}"
    mv -Tf "${tmp_link}" "${CURRENT_LINK}"
    sync_cli_entrypoints
    sync_legacy_package_paths
    log_info "Symlink reverted: ${CURRENT_LINK} -> ${previous_target}"

    if [[ -z "${snapshot_release}" ]]; then
        snapshot_release="${previous_target}"
    fi
    log_info "Database recovery snapshot release: ${snapshot_release}"

    if ! state_restore "${snapshot_release}"; then
        if ! stop_database_services "${RESOLVED_DB_PATH}"; then
            log_fatal "Database recovery failed; writer quiescence also failed. Refusing to restart services."
        fi
        log_fatal "Database recovery failed; database services remain stopped. Refusing to report rollback completion."
    fi

    if [[ "${DRY_RUN}" == false ]]; then
        restart_systemd_units
    fi
    log_error "=== ROLLBACK COMPLETE: Reverted to ${previous_target} ==="
}

###############################################################################
# STAGE 5: Housekeeping
###############################################################################
cleanup_old_releases() {
    log_info "=== STAGE 5: Pruning Old Releases (retaining ${MAX_RELEASES}) ==="

    local current_target=""
    [[ -L "${CURRENT_LINK}" ]] && current_target="$(readlink -f "${CURRENT_LINK}")"

    local previous_target=""
    [[ -f "${RELEASES_DIR}/.previous_release" ]] && previous_target="$(cat "${RELEASES_DIR}/.previous_release")"

    local releases=()
    while IFS= read -r dir; do
        releases+=("${dir}")
    done < <(find "${RELEASES_DIR}" -mindepth 1 -maxdepth 1 -type d | sort -n)

    local count=${#releases[@]}
    [[ ${count} -le ${MAX_RELEASES} ]] && return 0

    local to_prune=$((count - MAX_RELEASES))
    local pruned=0
    for dir in "${releases[@]}"; do
        [[ ${pruned} -ge ${to_prune} ]] && break
        if [[ "${dir}" == "${current_target}" ]] || [[ "${dir}" == "${previous_target}" ]]; then
            continue
        fi
        rm -rf "${dir}"
        pruned=$((pruned + 1))
    done
    log_info "Pruned ${pruned} old release(s)."
}

###############################################################################
# STAGE 6: One-Shot PM2 -> Systemd Migration
###############################################################################
migrate_systemd() {
    log_info "=== STAGE 6: PM2 -> Systemd Single-Binary Migration ==="
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
    restart_systemd_units
    if ! health_probe; then
        log_fatal "Health probe failed after systemd migration."
    fi
    log_info "MIGRATION COMPLETE: AetherFlow is running under hardened systemd units."
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
        chmod 1770 "${shared_lock_dir}" 2>/dev/null || true
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
    mkdir -p "${RELEASES_DIR}"
    local release_lock="${RELEASES_DIR}/.release.lock"
    if [[ -L "${release_lock}" ]]; then
        log_fatal "Release lockfile is a symbolic link: ${release_lock}"
    fi
    exec 201>"${release_lock}"
    if ! flock -w "${SNAPSHOT_TIMEOUT}" 201; then
        log_fatal "Could not acquire release lock ${release_lock} within ${SNAPSHOT_TIMEOUT}s."
    fi
}

case "${COMMAND}" in
    deploy)
        acquire_release_lock
        ensure_fhs_layout
        release_scaffold
        prepare_release_permissions || exit 1
        state_snapshot || exit 1
        symlink_swap
        if ! health_probe; then
            rollback "${RELEASE_DIR}"
            exit 2
        fi
        cleanup_old_releases
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
        cleanup_old_releases
        ;;
    migrate-systemd)
        acquire_release_lock
        migrate_systemd
        ;;
    *)
        echo "Usage: $0 {deploy|rollback|cleanup|migrate-systemd} [--channel stable|nightly] [--from-source] [--dry-run] [--offline]"
        exit 4
        ;;
esac
