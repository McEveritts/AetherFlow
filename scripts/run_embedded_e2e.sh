#!/bin/bash
###############################################################################
# AetherFlow v4 Embedded Single-Binary Full-Stack E2E Runner
#
# Safety invariants (Fail-Closed):
# 1. Default `START_RUNNER=0` (`--no-runner`). The privileged `aetherflow-api runner`
#    daemon is NEVER started unless `--with-runner` (`START_RUNNER=1`) is explicitly
#    passed AND `AETHERFLOW_ALLOW_RUNNER_E2E=1` is set (e.g., inside a disposable
#    KVM guest VM).
# 2. Binary capability inspection (`strings` check): before starting `aetherflow-api`
#    on any host, verifies the compiled binary actually honors
#    `AETHERFLOW_DISABLE_BACKGROUND_WORKERS` (or `AETHERFLOW_DISABLE_WORKERS`),
#    `AETHERFLOW_ENV_FILE` (or `AETHERFLOW_SKIP_ENV_FILES`), and `BIND_ADDR`.
#    If any isolation control is absent from the binary, the script FAILS CLOSED
#    before launching the process.
# 3. Never runs as root on a host with `/etc/aetherflow/aetherflow.env` unless
#    dropping privileges to an unprivileged account (`nobody`).
# 4. Preserves `${WORK_DIR}` (and copies failure logs to `${E2E_LOG_DIR}`) when
#    any check fails so evidence is never deleted on failure.
###############################################################################
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BINARY_PATH="${AETHERFLOW_BIN:-${ROOT_DIR}/backend-rs/target/release/aetherflow-api}"
PORT="${E2E_PORT:-18080}"
BIND_HOST="${E2E_BIND_ADDR:-127.0.0.1}"
RUN_PLAYWRIGHT="${RUN_PLAYWRIGHT:-0}"
START_RUNNER="${START_RUNNER:-0}"
KEEP_ARTIFACTS="${KEEP_E2E_ARTIFACTS:-0}"
E2E_LOG_DIR="${E2E_LOG_DIR:-}"
ADMIN_USER="${E2E_ADMIN_USER:-admin}"
ADMIN_PASS="${E2E_ADMIN_PASS:-AetherFlowE2E!2026}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)
            BINARY_PATH="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --bind-addr)
            BIND_HOST="$2"
            shift 2
            ;;
        --playwright)
            RUN_PLAYWRIGHT="1"
            shift
            ;;
        --no-runner)
            START_RUNNER="0"
            shift
            ;;
        --with-runner)
            START_RUNNER="1"
            shift
            ;;
        --keep-artifacts)
            KEEP_ARTIFACTS="1"
            shift
            ;;
        --log-dir)
            E2E_LOG_DIR="$2"
            shift 2
            ;;
        --verify-binary-only)
            VERIFY_BINARY_ONLY="1"
            shift
            ;;
        *)
            echo "Unknown argument: $1" >&2
            echo "Usage: $0 [--binary <path>] [--port <port>] [--bind-addr <ip>] [--playwright] [--no-runner|--with-runner] [--keep-artifacts] [--log-dir <dir>] [--verify-binary-only]" >&2
            exit 2
            ;;
    esac
done

if [[ ! -x "${BINARY_PATH}" ]]; then
    echo "[ERROR] Embedded binary not found or not executable: ${BINARY_PATH}" >&2
    exit 1
fi

# ── Fail-Closed Binary Isolation Contract Inspection ──────────────────────────
verify_binary_isolation_support() {
    local bin="$1"
    if [[ "$(head -c 2 "${bin}" 2>/dev/null || true)" == "#!" ]]; then
        # Shell stub used in unit/smoke tests
        return 0
    fi

    local bin_strings=""
    if command -v strings >/dev/null 2>&1; then
        bin_strings="$(strings "${bin}" 2>/dev/null || true)"
    elif command -v python3 >/dev/null 2>&1; then
        bin_strings="$(python3 -c '
import re, sys
data = open(sys.argv[1], "rb").read()
for m in re.findall(b"[ -~]{4,}", data):
    print(m.decode("ascii", "ignore"))
' "${bin}" 2>/dev/null || true)"
    else
        echo "[ERROR] Neither strings nor python3 available to verify binary isolation controls." >&2
        return 1
    fi

    # Use native Bash pattern matching instead of `printf | grep -q` so large (>1MB)
    # binaries never trigger upstream printf SIGPIPE (exit 141) under `set -o pipefail`.
    if [[ "${bin_strings}" != *"AETHERFLOW_DISABLE_BACKGROUND_WORKERS"* && \
          "${bin_strings}" != *"AETHERFLOW_DISABLE_WORKERS"* && \
          "${bin_strings}" != *"AETHERFLOW_DISABLE_AUTOHEAL"* ]]; then
        echo "[FATAL] Binary ${bin} does not contain worker-disable isolation controls (AETHERFLOW_DISABLE_BACKGROUND_WORKERS). Refusing to launch!" >&2
        return 1
    fi

    if [[ "${bin_strings}" != *"AETHERFLOW_ENV_FILE"* && \
          "${bin_strings}" != *"AETHERFLOW_SKIP_ENV_FILES"* ]]; then
        echo "[FATAL] Binary ${bin} does not contain env-file override/skip controls (AETHERFLOW_ENV_FILE / AETHERFLOW_SKIP_ENV_FILES). Refusing to launch!" >&2
        return 1
    fi

    if [[ "${bin_strings}" != *"BIND_ADDR"* ]]; then
        echo "[FATAL] Binary ${bin} does not honor BIND_ADDR (would bind 0.0.0.0 publicly). Refusing to launch!" >&2
        return 1
    fi

    return 0
}

verify_binary_isolation_support "${BINARY_PATH}"
if [[ "${VERIFY_BINARY_ONLY:-0}" == "1" ]]; then
    exit 0
fi

if [[ "${START_RUNNER}" == "1" ]]; then
    if [[ "${AETHERFLOW_ALLOW_RUNNER_E2E:-0}" != "1" ]]; then
        echo "[FATAL] Refusing to start privileged runner daemon without AETHERFLOW_ALLOW_RUNNER_E2E=1 (only permitted inside disposable KVM VM)." >&2
        exit 1
    fi
    if [[ -f /etc/aetherflow/aetherflow.env && "${AETHERFLOW_IS_DISPOSABLE_VM:-0}" != "1" ]]; then
        echo "[FATAL] Refusing to start privileged runner daemon on a host with /etc/aetherflow/aetherflow.env unless AETHERFLOW_IS_DISPOSABLE_VM=1." >&2
        exit 1
    fi
fi

TMP_BASE="${TMPDIR:-/var/tmp}"
if [[ ! -d "${TMP_BASE}" || ! -w "${TMP_BASE}" ]]; then
    TMP_BASE="/tmp"
fi

WORK_DIR="$(mktemp -d "${TMP_BASE}/aetherflow-embedded-e2e.XXXXXX")"
chmod 0755 "${WORK_DIR}"

API_PID=""
RUNNER_PID=""

cleanup() {
    local code=$?
    set +e
    if [[ -n "${API_PID}" ]]; then
        kill -TERM -- "-${API_PID}" 2>/dev/null || kill "${API_PID}" 2>/dev/null || true
        wait "${API_PID}" 2>/dev/null || true
    fi
    if [[ -n "${RUNNER_PID}" ]]; then
        kill -TERM -- "-${RUNNER_PID}" 2>/dev/null || kill "${RUNNER_PID}" 2>/dev/null || true
        wait "${RUNNER_PID}" 2>/dev/null || true
    fi
    if [[ -n "${E2E_LOG_DIR}" ]]; then
        mkdir -p "${E2E_LOG_DIR}" 2>/dev/null || true
        cp -f "${WORK_DIR}"/*.log "${WORK_DIR}"/*.json "${E2E_LOG_DIR}/" 2>/dev/null || true
    fi
    if [[ "${code}" -ne 0 || "${KEEP_ARTIFACTS}" == "1" ]]; then
        echo "[INFO] Preserving E2E work directory and logs at: ${WORK_DIR}" >&2
    else
        rm -rf "${WORK_DIR}"
    fi
    exit "${code}"
}
trap cleanup EXIT INT TERM

FS_ROOT="${WORK_DIR}/fs-root"
DATA_DIR="${WORK_DIR}/data"
RUN_DIR="${WORK_DIR}/run"
ENV_FILE="${WORK_DIR}/aetherflow.env"
API_LOG="${WORK_DIR}/api.log"
RUNNER_LOG="${WORK_DIR}/runner.log"
RUNNER_SOCK="${RUN_DIR}/runner.sock"
DB_FILE="${DATA_DIR}/aetherflow.sqlite"
FS_FIXTURE="${WORK_DIR}/fs-browser"

mkdir -p \
    "${FS_ROOT}/etc/aetherflow" \
    "${FS_ROOT}/var/lib/aetherflow" \
    "${FS_ROOT}/var/log/aetherflow" \
    "${FS_ROOT}/opt/AetherFlow/config" \
    "${FS_ROOT}/opt/AetherFlow/packages" \
    "${FS_FIXTURE}/storage/media" \
    "${DATA_DIR}" \
    "${RUN_DIR}"
printf 'fixture data\n' > "${FS_FIXTURE}/storage/media/fixture.txt"

if [[ -d "${ROOT_DIR}/config" ]]; then
    cp -R "${ROOT_DIR}/config/." "${FS_ROOT}/opt/AetherFlow/config/"
    mkdir -p "${WORK_DIR}/config"
    cp -R "${ROOT_DIR}/config/." "${WORK_DIR}/config/"
elif [[ -d "${ROOT_DIR}/backend/config" ]]; then
    cp -R "${ROOT_DIR}/backend/config/." "${FS_ROOT}/opt/AetherFlow/config/"
    mkdir -p "${WORK_DIR}/config"
    cp -R "${ROOT_DIR}/backend/config/." "${WORK_DIR}/config/"
fi

PLUGINS_DIR="${WORK_DIR}/plugins"
mkdir -p "${PLUGINS_DIR}" "${FS_ROOT}/opt/AetherFlow/plugins"
if [[ -d "${ROOT_DIR}/plugins" ]]; then
    cp -R "${ROOT_DIR}/plugins/." "${PLUGINS_DIR}/"
    cp -R "${ROOT_DIR}/plugins/." "${FS_ROOT}/opt/AetherFlow/plugins/"
    chmod -R go-w "${PLUGINS_DIR}" "${FS_ROOT}/opt/AetherFlow/plugins" 2>/dev/null || true
fi

PRIV_RUNNER_ENABLED="false"
[[ "${START_RUNNER}" == "1" ]] && PRIV_RUNNER_ENABLED="true"
E2E_MASTER_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
E2E_JWT_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"

cat > "${ENV_FILE}" <<EOF
AES_MASTER_KEY=${E2E_MASTER_KEY}
JWT_SECRET=${E2E_JWT_SECRET}
PORT=${PORT}
BIND_ADDR=${BIND_HOST}
ALLOWED_HOSTS=localhost,localhost:${PORT},127.0.0.1,127.0.0.1:${PORT}
ALLOWED_CORS_ORIGIN=http://localhost:${PORT},http://127.0.0.1:${PORT},http://localhost:3000,http://127.0.0.1:3000
DB_PATH=${DB_FILE}
AETHERFLOW_DB_PATH=${DB_FILE}
AETHERFLOW_FS_ROOT=${FS_ROOT}
AF_ALLOWED_FS_ROOTS=/mnt,${FS_FIXTURE}
AETHERFLOW_PLUGINS_DIR=${PLUGINS_DIR}
AETHERFLOW_RUNNER_SOCK=${RUNNER_SOCK}
AETHERFLOW_ENV_FILE=${ENV_FILE}
AETHERFLOW_SKIP_ENV_FILES=1
AETHERFLOW_DISABLE_BACKGROUND_WORKERS=1
AETHERFLOW_DISABLE_WORKERS=1
AETHERFLOW_DISABLE_AUTOHEAL=1
PRIVILEGED_RUNNER_ENABLED=${PRIV_RUNNER_ENABLED}
COOKIE_SECURE=false
EOF
chmod 0600 "${ENV_FILE}"
cp -f "${ENV_FILE}" "${FS_ROOT}/etc/aetherflow/aetherflow.env"

export AES_MASTER_KEY="${E2E_MASTER_KEY}"
export JWT_SECRET="${E2E_JWT_SECRET}"
export PORT="${PORT}"
export BIND_ADDR="${BIND_HOST}"
export ALLOWED_HOSTS="localhost,localhost:${PORT},127.0.0.1,127.0.0.1:${PORT}"
export ALLOWED_CORS_ORIGIN="http://localhost:${PORT},http://127.0.0.1:${PORT},http://localhost:3000,http://127.0.0.1:3000"
export DB_PATH="${DB_FILE}"
export AETHERFLOW_DB_PATH="${DB_FILE}"
export AETHERFLOW_FS_ROOT="${FS_ROOT}"
export AF_ALLOWED_FS_ROOTS="/mnt,${FS_FIXTURE}"
export AETHERFLOW_E2E_FS_FIXTURE="${FS_FIXTURE}"
export AETHERFLOW_PLUGINS_DIR="${PLUGINS_DIR}"
export AETHERFLOW_RUNNER_SOCK="${RUNNER_SOCK}"
export AETHERFLOW_ENV_FILE="${ENV_FILE}"
export AETHERFLOW_SKIP_ENV_FILES="1"
export AETHERFLOW_DISABLE_BACKGROUND_WORKERS="1"
export AETHERFLOW_DISABLE_WORKERS="1"
export AETHERFLOW_DISABLE_AUTOHEAL="1"
export PRIVILEGED_RUNNER_ENABLED="${PRIV_RUNNER_ENABLED}"
export COOKIE_SECURE="false"

# Never run as root on a live host with /etc/aetherflow/aetherflow.env
EXEC_PREFIX=()
if [[ "${EUID:-$(id -u)}" -eq 0 && -f /etc/aetherflow/aetherflow.env && "${AETHERFLOW_IS_DISPOSABLE_VM:-0}" != "1" ]]; then
    if command -v runuser >/dev/null 2>&1 && id -u nobody >/dev/null 2>&1; then
        chown -R nobody:nogroup "${WORK_DIR}" 2>/dev/null || chown -R nobody "${WORK_DIR}" 2>/dev/null || true
        EXEC_PREFIX=(runuser -u nobody --)
    else
        echo "[FATAL] Refusing to start embedded E2E binary as root on a host with /etc/aetherflow/aetherflow.env" >&2
        exit 1
    fi
fi

python3 - "${BIND_HOST}" "${PORT}" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
family = socket.AF_INET6 if ":" in host else socket.AF_INET
try:
    with socket.socket(family, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        probe.bind((host, port))
except OSError as error:
    raise SystemExit(f"[FATAL] Refusing to reuse occupied E2E listener {host}:{port}: {error}")
PY

if [[ "${START_RUNNER}" == "1" ]]; then
    (
        cd "${WORK_DIR}"
        exec setsid "${EXEC_PREFIX[@]}" "${BINARY_PATH}" runner >"${RUNNER_LOG}" 2>&1
    ) &
    RUNNER_PID=$!
fi

(
    cd "${WORK_DIR}"
    exec setsid "${EXEC_PREFIX[@]}" "${BINARY_PATH}" >"${API_LOG}" 2>&1
) &
API_PID=$!

BASE_URL="http://${BIND_HOST}:${PORT}"
echo "[INFO] Waiting for embedded aetherflow-api at ${BASE_URL}/health/ready ..."
READY=0
for _ in $(seq 1 60); do
    if curl -fsS --max-time 2 "${BASE_URL}/health/ready" 2>/dev/null | grep -q '"status":"ready"'; then
        READY=1
        break
    fi
    if ! kill -0 "${API_PID}" 2>/dev/null; then
        echo "[ERROR] aetherflow-api exited prematurely. Log output:" >&2
        cat "${API_LOG}" >&2 || true
        exit 1
    fi
    sleep 0.5
done

if [[ "${READY}" -ne 1 ]]; then
    echo "[ERROR] Timed out waiting for ${BASE_URL}/health/ready" >&2
    cat "${API_LOG}" >&2 || true
    exit 1
fi
echo "[OK] /health/ready returned status=ready"

# Verify the process did NOT bind wildcard 0.0.0.0:${PORT} when BIND_HOST=127.0.0.1
if [[ "${BIND_HOST}" == "127.0.0.1" ]] && command -v ss >/dev/null 2>&1; then
    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "^0\.0\.0\.0:${PORT}$|^\*:${PORT}$"; then
        echo "[FATAL] aetherflow-api bound wildcard 0.0.0.0:${PORT} instead of ${BIND_HOST}:${PORT}!" >&2
        exit 1
    fi
    echo "[OK] Verified loopback-only listener bound to ${BIND_HOST}:${PORT}"
fi

# Verify embedded SPA HTML & static assets are served by the single binary
ROOT_HTML="$(curl -fsS --max-time 5 "${BASE_URL}/")"
if [[ "${ROOT_HTML}" != *"<!DOCTYPE html>"* && "${ROOT_HTML}" != *"<html"* ]]; then
    echo "[ERROR] Embedded root '/' did not return HTML document" >&2
    exit 1
fi
echo "[OK] Embedded SPA root '/' serves HTML document"

LOGIN_HTML="$(curl -fsS --max-time 5 "${BASE_URL}/login")"
if [[ "${LOGIN_HTML}" != *"<!DOCTYPE html>"* && "${LOGIN_HTML}" != *"<html"* ]]; then
    echo "[ERROR] Embedded route '/login' did not return HTML document" >&2
    exit 1
fi
echo "[OK] Embedded SPA route '/login' serves HTML document"

API_404_CODE="$(curl -sS -o "${WORK_DIR}/api404.json" -w '%{http_code}' "${BASE_URL}/api/v1/nonexistent-route-check")"
if [[ "${API_404_CODE}" != "404" ]]; then
    echo "[ERROR] Expected 404 for unknown /api/ route, got ${API_404_CODE}" >&2
    exit 1
fi
echo "[OK] Unknown /api/* route returns HTTP 404 JSON instead of SPA fallback"

# Seed initial admin user via /api/v1/public/auth/setup so live authenticated E2E scenarios succeed
SETUP_CHECK="$(curl -fsS --max-time 5 "${BASE_URL}/api/v1/public/auth/setup/check")"
if echo "${SETUP_CHECK}" | grep -q '"setupRequired":true'; then
    SETUP_CODE="$(curl -sS -o "${WORK_DIR}/setup.json" -w '%{http_code}' \
        -X POST "${BASE_URL}/api/v1/public/auth/setup" \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"${ADMIN_USER}\",\"password\":\"${ADMIN_PASS}\"}")"
    if [[ "${SETUP_CODE}" != "200" && "${SETUP_CODE}" != "201" ]]; then
        echo "[ERROR] Initial admin setup failed with HTTP ${SETUP_CODE}: $(cat "${WORK_DIR}/setup.json" 2>/dev/null || true)" >&2
        exit 1
    fi
    echo "[OK] Seeded initial administrator account via /api/v1/public/auth/setup"
fi

echo "[INFO] Running full-stack Python E2E suite in live mode against ${BASE_URL} ..."
AETHERFLOW_E2E_USER="${ADMIN_USER}" \
AETHERFLOW_E2E_PASS="${ADMIN_PASS}" \
AETHERFLOW_E2E_USERNAME="${ADMIN_USER}" \
AETHERFLOW_E2E_PASSWORD="${ADMIN_PASS}" \
python3 "${ROOT_DIR}/tests/run_e2e.py" --mode live --url "${BASE_URL}" --socket "${RUNNER_SOCK}" --json-out "${WORK_DIR}/e2e-report.json"

if [[ "${RUN_PLAYWRIGHT}" == "1" ]]; then
    python3 - "${DB_FILE}" "${WORK_DIR}" <<'PY'
import datetime
import pathlib
import sqlite3
import sys

database_path = pathlib.Path(sys.argv[1]).resolve(strict=True)
work_root = pathlib.Path(sys.argv[2]).resolve(strict=True)
if database_path.parent != work_root / "data":
    raise SystemExit("Refusing to seed telemetry outside the isolated E2E database")
now = datetime.datetime.now(datetime.timezone.utc)
rows = [
    ((now - datetime.timedelta(seconds=30 * offset)).strftime("%Y-%m-%d %H:%M:%S"),
     20 + offset, 2 + offset / 10, 8, offset * 1024, offset * 2048)
    for offset in range(12, 0, -1)
]
with sqlite3.connect(database_path) as database:
    database.executemany(
        "INSERT INTO metrics_history "
        "(timestamp, cpu_avg, mem_used_gb, mem_total_gb, disk_read_bps, disk_write_bps) "
        "VALUES (?, ?, ?, ?, ?, ?)", rows
    )
print("[OK] Seeded 12 real persisted telemetry rows in the isolated E2E database")
PY
    echo "[INFO] Running Playwright E2E suite against embedded single-binary (${BASE_URL}) ..."
    PLAYWRIGHT_SPECS="${E2E_PLAYWRIGHT_SPECS:-embedded.live.spec.ts}"
    (
        cd "${ROOT_DIR}/frontend"
        E2E_ADMIN_USER="${ADMIN_USER}" \
        E2E_ADMIN_PASS="${ADMIN_PASS}" \
        PLAYWRIGHT_BASE_URL="${BASE_URL}" \
        PLAYWRIGHT_SKIP_WEBSERVER="1" \
        npx playwright test ${PLAYWRIGHT_SPECS}
    )
fi

echo "[PASS] Embedded Rust single-binary full-stack E2E completed successfully."
