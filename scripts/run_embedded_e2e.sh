#!/bin/bash
###############################################################################
# AetherFlow Rust API + external WASM frontend full-stack E2E runner
#
# Safety invariants (Fail-Closed):
# 1. The privileged `aetherflow-api runner` daemon is never started.
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
# 5. Only the explicitly selected external WASM directory is served. The API
#    runs with a clean environment and isolated, newly generated credentials.
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
MEMBER_USER="${E2E_MEMBER_USER:-live-member}"
STATIC_DIR_OPTION=""
STATIC_DIR_EXPLICIT=0
VERIFY_ASSETS_ONLY=0

usage() {
    echo "Usage: $0 [--binary <path>] [--static-dir <path>] [--port <port>] [--bind-addr 127.0.0.1] [--playwright] [--no-runner] [--keep-artifacts] [--log-dir <dir>] [--verify-binary-only|--verify-assets-only]"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary|--static-dir|--port|--bind-addr|--log-dir)
            if [[ $# -lt 2 || -z "$2" || "$2" == --* ]]; then
                echo "[ERROR] $1 requires a nonempty value" >&2
                usage >&2
                exit 2
            fi
            ;;
    esac
    case "$1" in
        --binary)
            BINARY_PATH="$2"
            shift 2
            ;;
        --static-dir)
            STATIC_DIR_OPTION="$2"
            STATIC_DIR_EXPLICIT=1
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
            echo "[FATAL] The privileged runner is disabled for this E2E harness." >&2
            exit 2
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
        --verify-assets-only)
            VERIFY_ASSETS_ONLY=1
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            echo "Unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [[ ! -x "${BINARY_PATH}" ]]; then
    echo "[ERROR] API binary not found or not executable: ${BINARY_PATH}" >&2
    exit 1
fi
# Match current_exe(): resolve relative paths and symlinks before changing cwd.
BINARY_PATH="$(python3 -c 'import pathlib,sys; print(pathlib.Path(sys.argv[1]).resolve(strict=True))' "${BINARY_PATH}")"

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

if [[ "${START_RUNNER}" != "0" ]]; then
    echo "[FATAL] START_RUNNER must be 0; the privileged runner is disabled for this E2E harness." >&2
    exit 1
fi

# CLI selection wins over an inherited STATIC_DIR, including an empty value;
# only an unset STATIC_DIR selects the API's current_exe() sibling web/dist.
if [[ "${STATIC_DIR_EXPLICIT}" == "1" ]]; then
    SELECTED_STATIC_DIR="${STATIC_DIR_OPTION}"
elif [[ -n "${STATIC_DIR+x}" ]]; then
    SELECTED_STATIC_DIR="${STATIC_DIR}"
else
    SELECTED_STATIC_DIR="$(dirname "${BINARY_PATH}")/web/dist"
fi
if [[ -z "${SELECTED_STATIC_DIR}" ]]; then
    echo "[ERROR] STATIC_DIR is set but empty; unset it or select a valid --static-dir." >&2
    exit 1
fi
if [[ ! -d "${SELECTED_STATIC_DIR}" ]]; then
    echo "[ERROR] External WASM asset directory does not exist: ${SELECTED_STATIC_DIR} (use --static-dir or STATIC_DIR)" >&2
    exit 1
fi
STATIC_DIR="$(cd "${SELECTED_STATIC_DIR}" && pwd -P)"
export STATIC_DIR

# Validate the actual document references, not merely unrelated files in dist.
# Like the API, reject links below the resolved asset root and enforce its file size cap.
python3 - "${STATIC_DIR}" <<'PY'
from html.parser import HTMLParser
import base64
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from urllib.parse import unquote, urljoin, urlsplit

root = Path(sys.argv[1])
max_asset_bytes = 32 * 1024 * 1024

def asset(reference, base="/"):
    url = urlsplit(urljoin(base, reference))
    if url.scheme or url.netloc or url.query or url.fragment:
        raise ValueError(f"asset reference must be a local path: {reference}")
    relative = unquote(url.path, errors="strict").lstrip("/")
    parts = PurePosixPath(relative).parts
    if not parts or ".." in parts or "\\" in relative or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in relative):
        raise ValueError(f"invalid asset path: {reference}")
    path = root
    for part in parts:
        path /= part
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"symbolic link below the asset directory: {reference}")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"asset must be a regular file with one link: {reference}")
    if not 0 < metadata.st_size <= max_asset_bytes:
        raise ValueError(f"asset is empty or exceeds 32 MiB: {reference}")
    return path

class Document(HTMLParser):
    def __init__(self):
        super().__init__()
        self.scripts, self.wasm, self.app_wasm, self.modules, self.workers = [], [], [], [], []
    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == "script" and attrs.get("src"):
            self.scripts.append(attrs["src"])
        if tag == "link" and (attrs.get("href") or "").endswith(".wasm"):
            self.wasm.append(attrs["href"])
        if tag == "link" and "modulepreload" in (attrs.get("rel") or "").lower().split() and attrs.get("href"):
            self.modules.append(attrs["href"])
        if tag == "meta" and attrs.get("name") == "af-app-wasm-url":
            self.app_wasm.append(attrs.get("content") or "")
        if tag == "meta" and attrs.get("name") == "af-worker-url" and attrs.get("content"):
            self.workers.append(attrs["content"])

try:
    document = Document()
    document.feed(asset("/index.html").read_text(encoding="utf-8"))
    if not document.scripts or not (document.app_wasm or document.wasm) or len(document.workers) != 1:
        raise ValueError("index.html must reference the bootstrap, application WASM, and worker loader")
    script_paths = [asset(reference) for reference in document.scripts]
    if document.app_wasm:
        if len(document.app_wasm) != 1 or not document.app_wasm[0].endswith(".wasm"):
            raise ValueError("index.html must have exactly one valid application WASM metadata reference")
    application_paths = set()
    for reference in document.wasm + document.app_wasm:
        application_path = asset(reference)
        application_paths.add(application_path)
        if application_path.read_bytes()[:8] != b"\0asm\x01\0\0\0":
            raise ValueError(f"invalid application WASM header: {reference}")
    if document.app_wasm:
        reference = document.app_wasm[0]
        digest = base64.b64encode(hashlib.sha384(asset(reference).read_bytes()).digest()).decode("ascii")
        scripts = [path.read_text(encoding="utf-8") for path in script_paths]
        # Check the complete shape emitted by the finalizer: this exact fetch
        # feeds bindgen and runs with the preloaded app module. Merely finding
        # an unrelated valid WASM file or a stray fetch is insufficient.
        fetch = (r"\bconst\s*\[\s*wasmResponse\s*,\s*\{\s*default\s*:\s*init\s*\}\s*\]"
                 r"\s*=\s*await\s+Promise\.all\s*\(\s*\[\s*fetch\s*\(\s*"
                 + re.escape(json.dumps(reference)) + r"\s*,\s*\{\s*integrity\s*:\s*"
                 + re.escape(json.dumps("sha384-" + digest))
                 + r'''\s*\}\s*\)\s*,\s*import\s*\(\s*"([^"\\]+\.js)"\s*\)\s*\]\s*\)''')
        initialize = r"\bconst\s+wasm\s*=\s*await\s+init\s*\(\s*\{\s*module_or_path\s*:\s*wasmResponse\s*\}\s*\)"
        matches = [match for script in scripts if re.search(initialize, script)
                   for match in re.finditer(fetch, script)]
        if len(matches) != 1:
            raise ValueError("bootstrap does not initialize from the integrity-checked application WASM metadata reference")
        module = matches[0].group(1)
        if module not in document.modules:
            raise ValueError("application module is not referenced by a modulepreload")
        asset(module)
    worker_url = document.workers[0]
    loader = asset(worker_url).read_text(encoding="utf-8")
    imports = re.findall(r'''(?:from\s*|import\s*)["']([^"']+\.js)["']''', loader)
    if not imports:
        raise ValueError("worker loader must reference its JavaScript module")
    for reference in imports:
        worker_js = asset(reference, worker_url)
        worker_wasm = re.findall(r'''["']([^"']+\.wasm)["']''', worker_js.read_text(encoding="utf-8"))
        if not worker_wasm:
            raise ValueError(f"worker module does not reference its WASM: {reference}")
        for wasm in worker_wasm:
            worker_path = asset(wasm, urljoin(worker_url, reference))
            if document.app_wasm and worker_path in application_paths:
                raise ValueError("application and worker must reference separate WASM modules")
            if worker_path.read_bytes()[:8] != b"\0asm\x01\0\0\0":
                raise ValueError(f"invalid worker WASM header: {wasm}")
except (OSError, UnicodeError, ValueError) as error:
    raise SystemExit(f"[ERROR] Invalid external WASM frontend at {root}: {error}")
print(f"[OK] External Rust WASM assets validated: {root}")
PY

if [[ "${VERIFY_ASSETS_ONLY}" == "1" ]]; then
    exit 0
fi

if [[ "${BIND_HOST}" != "127.0.0.1" ]]; then
    echo "[FATAL] The E2E API must bind to 127.0.0.1." >&2
    exit 1
fi
if [[ ! "${PORT}" =~ ^[0-9]{1,5}$ ]] || (( 10#${PORT} < 1 || 10#${PORT} > 65535 )); then
    echo "[ERROR] E2E port must be an integer from 1 to 65535: ${PORT}" >&2
    exit 2
fi
PORT=$((10#${PORT}))

# Local checks must never be redirected to an inherited proxy.
unset HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy
export NO_PROXY="127.0.0.1,localhost" no_proxy="127.0.0.1,localhost"

TMP_BASE="${TMPDIR:-/var/tmp}"
if [[ ! -d "${TMP_BASE}" || ! -w "${TMP_BASE}" ]]; then
    TMP_BASE="/tmp"
fi

WORK_DIR="$(mktemp -d "${TMP_BASE}/aetherflow-embedded-e2e.XXXXXX")"
chmod 0755 "${WORK_DIR}"

API_PID=""
RUNNER_PID=""
SQLITE_GUARD_PID=""

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
    if [[ -n "${SQLITE_GUARD_PID}" ]]; then
        kill "${SQLITE_GUARD_PID}" 2>/dev/null || true
        wait "${SQLITE_GUARD_PID}" 2>/dev/null || true
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
MCBROWSER_DIR="${WORK_DIR}/mcbrowser"
UPLOAD_DIR="${WORK_DIR}/uploads"

mkdir -p \
    "${FS_ROOT}/etc/aetherflow" \
    "${FS_ROOT}/var/lib/aetherflow" \
    "${FS_ROOT}/var/log/aetherflow" \
    "${FS_ROOT}/opt/AetherFlow/config" \
    "${FS_ROOT}/opt/AetherFlow/packages" \
    "${FS_FIXTURE}/storage/media" \
    "${MCBROWSER_DIR}/user-1" \
    "${UPLOAD_DIR}" \
    "${DATA_DIR}" \
    "${RUN_DIR}"
printf 'fixture data\n' > "${FS_FIXTURE}/storage/media/fixture.txt"

if [[ -d "${ROOT_DIR}/config" ]]; then
    cp -R "${ROOT_DIR}/config/." "${FS_ROOT}/opt/AetherFlow/config/"
    mkdir -p "${WORK_DIR}/config"
    cp -R "${ROOT_DIR}/config/." "${WORK_DIR}/config/"
else
    echo "error: canonical config directory '${ROOT_DIR}/config' not found" >&2
    exit 1
fi

PLUGINS_DIR="${WORK_DIR}/plugins"
mkdir -p "${PLUGINS_DIR}" "${FS_ROOT}/opt/AetherFlow/plugins"
if [[ -d "${ROOT_DIR}/plugins" ]]; then
    cp -R "${ROOT_DIR}/plugins/." "${PLUGINS_DIR}/"
    cp -R "${ROOT_DIR}/plugins/." "${FS_ROOT}/opt/AetherFlow/plugins/"
    chmod -R go-w "${PLUGINS_DIR}" "${FS_ROOT}/opt/AetherFlow/plugins" 2>/dev/null || true
fi

PRIV_RUNNER_ENABLED="false"
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
MCBROWSER_ROOT=${MCBROWSER_DIR}
AF_MCBROWSER_ROOT=${MCBROWSER_DIR}
AETHERFLOW_UPLOAD_DIR=${UPLOAD_DIR}
AF_ALLOWED_FS_ROOTS=/mnt,${FS_FIXTURE},${MCBROWSER_DIR}
AETHERFLOW_PLUGINS_DIR=${PLUGINS_DIR}
AETHERFLOW_RUNNER_SOCK=${RUNNER_SOCK}
AETHERFLOW_ENV_FILE=${ENV_FILE}
AETHERFLOW_SKIP_ENV_FILES=1
AETHERFLOW_DISABLE_BACKGROUND_WORKERS=1
AETHERFLOW_DISABLE_WORKERS=1
AETHERFLOW_DISABLE_AUTOHEAL=1
AETHERFLOW_E2E_ISOLATED=1
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
export MCBROWSER_ROOT="${MCBROWSER_DIR}"
export AF_MCBROWSER_ROOT="${MCBROWSER_DIR}"
export AETHERFLOW_UPLOAD_DIR="${UPLOAD_DIR}"
export AF_ALLOWED_FS_ROOTS="/mnt,${FS_FIXTURE},${MCBROWSER_DIR}"
export AETHERFLOW_E2E_FS_FIXTURE="${FS_FIXTURE}"
export AETHERFLOW_PLUGINS_DIR="${PLUGINS_DIR}"
export AETHERFLOW_RUNNER_SOCK="${RUNNER_SOCK}"
export AETHERFLOW_ENV_FILE="${ENV_FILE}"
export AETHERFLOW_SKIP_ENV_FILES="1"
export AETHERFLOW_DISABLE_BACKGROUND_WORKERS="1"
export AETHERFLOW_DISABLE_WORKERS="1"
export AETHERFLOW_DISABLE_AUTOHEAL="1"
export AETHERFLOW_E2E_ISOLATED="1"
export PRIVILEGED_RUNNER_ENABLED="${PRIV_RUNNER_ENABLED}"
export COOKIE_SECURE="false"

# Do not pass host credentials, service endpoints, proxy settings, or other
# application configuration to the API or any plugin process it creates.
API_ENV=(
    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    "HOME=${WORK_DIR}" "TMPDIR=${WORK_DIR}" "STATIC_DIR=${STATIC_DIR}"
    "AES_MASTER_KEY=${AES_MASTER_KEY}" "JWT_SECRET=${JWT_SECRET}"
    "PORT=${PORT}" "BIND_ADDR=${BIND_ADDR}"
    "ALLOWED_HOSTS=${ALLOWED_HOSTS}" "ALLOWED_CORS_ORIGIN=${ALLOWED_CORS_ORIGIN}"
    "DB_PATH=${DB_PATH}" "AETHERFLOW_DB_PATH=${AETHERFLOW_DB_PATH}"
    "AETHERFLOW_FS_ROOT=${AETHERFLOW_FS_ROOT}"
    "MCBROWSER_ROOT=${MCBROWSER_ROOT}" "AF_MCBROWSER_ROOT=${AF_MCBROWSER_ROOT}"
    "AETHERFLOW_UPLOAD_DIR=${AETHERFLOW_UPLOAD_DIR}" "AF_ALLOWED_FS_ROOTS=${AF_ALLOWED_FS_ROOTS}"
    "AETHERFLOW_PLUGINS_DIR=${AETHERFLOW_PLUGINS_DIR}" "AETHERFLOW_RUNNER_SOCK=${AETHERFLOW_RUNNER_SOCK}"
    "AETHERFLOW_ENV_FILE=${AETHERFLOW_ENV_FILE}" "AETHERFLOW_SKIP_ENV_FILES=1"
    "AETHERFLOW_DISABLE_BACKGROUND_WORKERS=1" "AETHERFLOW_DISABLE_WORKERS=1"
    "AETHERFLOW_DISABLE_AUTOHEAL=1" "AETHERFLOW_E2E_ISOLATED=1"
    "PRIVILEGED_RUNNER_ENABLED=false" "COOKIE_SECURE=false"
)

curl() {
    command curl --disable --noproxy '*' "$@"
}

# Never run as root on a live host with /etc/aetherflow/aetherflow.env
EXEC_PREFIX=()
if [[ "${EUID:-$(id -u)}" -eq 0 && -f /etc/aetherflow/aetherflow.env && "${AETHERFLOW_IS_DISPOSABLE_VM:-0}" != "1" ]]; then
    if command -v runuser >/dev/null 2>&1 && id -u nobody >/dev/null 2>&1; then
        chown -R nobody:nogroup "${WORK_DIR}" 2>/dev/null || chown -R nobody "${WORK_DIR}" 2>/dev/null || true
        EXEC_PREFIX=(runuser -u nobody --)
    else
        echo "[FATAL] Refusing to start the E2E API as root on a host with /etc/aetherflow/aetherflow.env" >&2
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

(
    cd "${WORK_DIR}"
    exec setsid "${EXEC_PREFIX[@]}" env -i "${API_ENV[@]}" "${BINARY_PATH}" >"${API_LOG}" 2>&1
) &
API_PID=$!

BASE_URL="http://${BIND_HOST}:${PORT}"
echo "[INFO] Waiting for aetherflow-api at ${BASE_URL}/health/ready ..."
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

# Verify the selected external SPA directory is served by the API.
curl -fsS --max-time 5 -H 'Accept-Encoding: identity' -o "${WORK_DIR}/root.html" "${BASE_URL}/"
if ! cmp -s "${STATIC_DIR}/index.html" "${WORK_DIR}/root.html"; then
    echo "[ERROR] External frontend root '/' does not match ${STATIC_DIR}/index.html" >&2
    exit 1
fi
echo "[OK] External SPA root '/' serves the selected index.html"

curl -fsS --max-time 5 -H 'Accept-Encoding: identity' -o "${WORK_DIR}/login.html" "${BASE_URL}/login"
if ! cmp -s "${STATIC_DIR}/index.html" "${WORK_DIR}/login.html"; then
    echo "[ERROR] External SPA route '/login' does not fall back to the selected index.html" >&2
    exit 1
fi
echo "[OK] External SPA route '/login' serves the selected index.html"

API_404_CODE="$(curl -sS -o "${WORK_DIR}/api404.json" -w '%{http_code}' "${BASE_URL}/api/v1/nonexistent-route-check")"
if [[ "${API_404_CODE}" != "404" ]]; then
    echo "[ERROR] Expected 404 for unknown /api/ route, got ${API_404_CODE}" >&2
    exit 1
fi
echo "[OK] Unknown /api/* route returns HTTP 404 JSON instead of SPA fallback"

WS_404_CODE="$(curl -sS -o "${WORK_DIR}/ws404.json" -w '%{http_code}' "${BASE_URL}/ws/nonexistent-route-check")"
if [[ "${WS_404_CODE}" != "404" ]]; then
    echo "[ERROR] Expected 404 for unknown /ws/ route, got ${WS_404_CODE}" >&2
    exit 1
fi
python3 - "${WORK_DIR}/api404.json" "${WORK_DIR}/ws404.json" <<'PY'
import json, sys
for filename in sys.argv[1:]:
    with open(filename, encoding="utf-8") as response:
        body = json.load(response)
    if not isinstance(body, dict) or not body.get("error"):
        raise SystemExit(f"[ERROR] Expected a JSON error response in {filename}")
PY
echo "[OK] Unknown /ws/* route returns HTTP 404 JSON instead of SPA fallback"

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

# Seed the role fixture before browser scenarios mutate session/profile state.
# There is no public user-creation endpoint; all authentication still uses HTTP.
if [[ "${RUN_PLAYWRIGHT}" == "1" ]]; then
    # Keep a read transaction open while short-lived Python fixtures access the
    # bundled SQLite server's WAL. This prevents their final connection close
    # from unlinking sidecars still used by the running API's connection pools.
    coproc AF_SQLITE_GUARD {
        exec python3 -u -c '
import pathlib, sqlite3, sys
database = pathlib.Path(sys.argv[1]).resolve(strict=True)
work_root = pathlib.Path(sys.argv[2]).resolve(strict=True)
if database.parent != work_root / "data":
    raise SystemExit("Refusing to pin a database outside the isolated E2E root")
connection = sqlite3.connect(database, timeout=15)
if connection.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
    raise SystemExit("The isolated SQLite fixture must use WAL mode")
connection.execute("BEGIN")
connection.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
print("SQLITE_GUARD_READY", flush=True)
sys.stdin.buffer.read()
connection.rollback()
connection.close()
' "${DB_FILE}" "${WORK_DIR}"
    }
    SQLITE_GUARD_PID="${AF_SQLITE_GUARD_PID}"
    if ! read -r sqlite_guard_status <&"${AF_SQLITE_GUARD[0]}" || [[ "${sqlite_guard_status}" != "SQLITE_GUARD_READY" ]]; then
        echo "[ERROR] Failed to pin the isolated SQLite fixture WAL." >&2
        exit 1
    fi
    echo "[OK] Pinned SQLite WAL sidecars for the live fixture lifetime"
    python3 - "${DB_FILE}" "${WORK_DIR}" "${ADMIN_USER}" "${MEMBER_USER}" <<'PY'
import pathlib
import sqlite3
import sys

database_path = pathlib.Path(sys.argv[1]).resolve(strict=True)
work_root = pathlib.Path(sys.argv[2]).resolve(strict=True)
if database_path.parent != work_root / "data":
    raise SystemExit("Refusing to seed a role fixture outside the isolated E2E database")
with sqlite3.connect(database_path, timeout=15) as database:
    admin = database.execute(
        "SELECT password_hash FROM users WHERE username=? AND role='admin'", (sys.argv[3],)
    ).fetchone()
    if not admin or not admin[0]:
        raise SystemExit("The role fixture requires a local administrator password")
    existing = database.execute("SELECT role FROM users WHERE username=?", (sys.argv[4],)).fetchone()
    if existing and existing[0] != "user":
        raise SystemExit("The role fixture username must belong to an ordinary user")
    if not existing:
        database.execute(
            "INSERT INTO users(username,password_hash,role) VALUES(?,?,'user')", (sys.argv[4], admin[0])
        )
print("[OK] Seeded the ordinary-user role fixture before browser execution")
PY
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
    echo "[INFO] Running Playwright E2E suite against the external WASM frontend (${BASE_URL}) ..."
    PLAYWRIGHT_SPECS="${E2E_PLAYWRIGHT_SPECS:-[.]live[.]spec[.]ts$}"
    (
        cd "${ROOT_DIR}/e2e"
        E2E_ADMIN_USER="${ADMIN_USER}" \
        E2E_ADMIN_PASS="${ADMIN_PASS}" \
        E2E_MEMBER_USER="${MEMBER_USER}" \
        PLAYWRIGHT_BASE_URL="${BASE_URL}" \
        PLAYWRIGHT_SKIP_WEBSERVER="1" \
        npx playwright test ${PLAYWRIGHT_SPECS}
    )
fi

echo "[PASS] Rust API and external WASM frontend full-stack E2E completed successfully."
