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

# ── Load Configuration ───────────────────────────────────────────────────────
CONF_FILE="${SCRIPT_DIR}/release-manager.conf"
if [[ -f "${CONF_FILE}" ]]; then
    # shellcheck source=release-manager.conf
    source "${CONF_FILE}"
else
    echo "[FATAL] Configuration file not found: ${CONF_FILE}"
    exit 4
fi

# ── Parse CLI Arguments ──────────────────────────────────────────────────────
COMMAND="${1:-deploy}"
shift || true

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
        stable|nightly|experimental)
            CHANNEL="$1"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# Captured before the dry-run rewrite so resolution still sees the host layout.
CONFIG_ENV_FILE="${ENV_FILE}"
CONFIG_DATA_DIR="${DATA_DIR}"
LEGACY_OPT_ROOT="${LEGACY_OPT_ROOT:-/opt/AetherFlow}"
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
log_error() { log "ERROR" "$@"; }
log_fatal() { log "FATAL" "$@"; exit 4; }

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

resolve_db_path() {
    RESOLVED_DB_PATH=""
    RESOLVED_DB_SOURCE=""

    if [[ -n "${AF_DB_PATH:-}" ]]; then
        RESOLVED_DB_PATH="${AF_DB_PATH}"
        RESOLVED_DB_SOURCE="AF_DB_PATH"
    else
        local val=""
        if val="$(read_env_file_value "${CONFIG_ENV_FILE}" "DB_PATH")"; then
            RESOLVED_DB_PATH="${val}"
            RESOLVED_DB_SOURCE="env-file:${CONFIG_ENV_FILE}:DB_PATH"
        elif val="$(read_env_file_value "${CONFIG_ENV_FILE}" "AETHERFLOW_DB_PATH")"; then
            RESOLVED_DB_PATH="${val}"
            RESOLVED_DB_SOURCE="env-file:${CONFIG_ENV_FILE}:AETHERFLOW_DB_PATH"
        else
            local unit_blob=""
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
    # Do not pipe through head: pipefail plus SIGPIPE makes a good check look failed.
    result="$(sqlite3 "${db}" "PRAGMA integrity_check;" 2>/dev/null || true)"
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

    if [[ "${channel}" == "experimental" ]]; then
        if [[ -n "${releases_json}" ]] && command -v python3 &>/dev/null; then
            local exp_tag=""
            exp_tag="$(printf '%s' "${releases_json}" | python3 -c '
import json, sys
try:
    for r in json.load(sys.stdin):
        if r.get("draft"):
            continue
        tag = (r.get("tag_name") or "").strip()
        target = (r.get("target_commitish") or "").strip().lower()
        if tag and (tag.lower() == "experimental" or target == "experimental" or "experimental" in tag.lower()):
            print(tag)
            break
except Exception:
    pass
' 2>/dev/null)"
            if [[ -n "${exp_tag}" ]]; then
                echo "${exp_tag}"
                return 0
            fi
        fi
        echo "experimental"
        return 0
    fi

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

    [[ -z "${releases_json}" ]] && return 1

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

stage_running_release_manager() {
    mkdir -p "${RELEASE_DIR}/deploy"
    if [[ -f "${SCRIPT_DIR}/release-manager.sh" ]]; then
        cp -f "${SCRIPT_DIR}/release-manager.sh" "${RELEASE_DIR}/deploy/release-manager.sh"
        chmod +x "${RELEASE_DIR}/deploy/release-manager.sh"
        log_info "Staged the executing release-manager.sh into ${RELEASE_DIR}/deploy (published artifacts can predate this fix)."
    fi
    if [[ -f "${CONF_FILE}" ]]; then
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

    log_info "SHA-256 checksum verified. Extracting into ${RELEASE_DIR}..."
    # pull_prebuilt_artifact is called from an if, which disables set -e.
    if ! tar -xzf "${tmp_dir}/${ARTIFACT_NAME}" -C "${RELEASE_DIR}"; then
        log_error "Failed to extract ${ARTIFACT_NAME}."
        rm -rf "${tmp_dir}"
        return 1
    fi
    if [[ ! -f "${RELEASE_DIR}/aetherflow-api" ]]; then
        log_error "Release archive has no ./aetherflow-api. Refusing to continue."
        rm -rf "${tmp_dir}"
        return 1
    fi
    if [[ ! -s "${RELEASE_DIR}/.version" ]]; then
        echo "${tag}" > "${RELEASE_DIR}/.version"
    fi
    chmod +x "${RELEASE_DIR}/aetherflow-api"
    stage_running_release_manager
    rm -rf "${tmp_dir}"
    return 0
}

build_from_source() {
    local target_branch="${GIT_BRANCH}"
    if [[ "${CHANNEL}" == "nightly" ]]; then
        target_branch="nightly"
    elif [[ "${CHANNEL}" == "experimental" ]]; then
        target_branch="experimental"
    fi
    log_info "Building single-binary release from source (${GIT_REMOTE}/${target_branch})..."
    cd "${REPO_DIR}" || log_fatal "Repository directory not found: ${REPO_DIR}"
    if ! git fetch "${GIT_REMOTE}" "${target_branch}" --tags >> "${LOG_FILE}" 2>&1; then
        if [[ "${CHANNEL}" == "nightly" ]] && git fetch "${GIT_REMOTE}" "Nightly" --tags >> "${LOG_FILE}" 2>&1; then
            target_branch="Nightly"
        else
            log_warn "Branch ${target_branch} not found on ${GIT_REMOTE}; falling back to ${GIT_BRANCH}."
            target_branch="${GIT_BRANCH}"
            git fetch "${GIT_REMOTE}" "${target_branch}" --tags >> "${LOG_FILE}" 2>&1
        fi
    fi
    git checkout -f "${GIT_REMOTE}/${target_branch}" >> "${LOG_FILE}" 2>&1 || true
    local source_sha
    source_sha="$(git rev-parse --short=7 HEAD 2>/dev/null || echo 'unknown')"

    rsync -a --exclude='.git' --exclude='node_modules' --exclude='.next' --exclude='*.sqlite' \
        "${REPO_DIR}/" "${RELEASE_DIR}/" >> "${LOG_FILE}" 2>&1
    if [[ ( "${CHANNEL}" == "nightly" || "${CHANNEL}" == "experimental" ) && ! -s "${RELEASE_DIR}/.version" ]]; then
        echo "${CHANNEL}-${source_sha}" > "${RELEASE_DIR}/.version"
    fi

    log_info "Building Next.js static export (NEXT_STATIC_EXPORT=1)..."
    cd "${RELEASE_DIR}/frontend" || log_fatal "Frontend directory missing."
    export NODE_OPTIONS="${NODE_OPTIONS:+${NODE_OPTIONS} }--max-old-space-size=${NODE_HEAP_MB}"
    export NEXT_STATIC_EXPORT="1"
    npm ci --no-fund --no-audit >> "${LOG_FILE}" 2>&1
    npm run build >> "${LOG_FILE}" 2>&1

    log_info "Embedding frontend static bundle into backend/web/dist..."
    rm -rf "${RELEASE_DIR}/backend/web/dist"
    mkdir -p "${RELEASE_DIR}/backend/web/dist"
    cp -R "${RELEASE_DIR}/frontend/out/." "${RELEASE_DIR}/backend/web/dist/"

    if [[ -d "${RELEASE_DIR}/backend-rs" ]] && command -v cargo &>/dev/null; then
        log_info "Compiling single-binary AetherFlow Rust control plane (backend-rs)..."
        cd "${RELEASE_DIR}/backend-rs" || log_fatal "Rust backend directory missing."
        cargo build --release --bin aetherflow-api >> "${LOG_FILE}" 2>&1
        cp -f "target/release/aetherflow-api" "${RELEASE_DIR}/aetherflow-api"
    else
        log_info "Compiling single-binary AetherFlow Go control plane..."
        cd "${RELEASE_DIR}/backend" || log_fatal "Backend directory missing."
        export GOOS=linux GOARCH=amd64 CGO_ENABLED=0
        "${GO_BIN}" build -trimpath -buildvcs=false -o "${RELEASE_DIR}/aetherflow-api" . >> "${LOG_FILE}" 2>&1
    fi
    chmod +x "${RELEASE_DIR}/aetherflow-api"

    # Retain only runtime essentials (binary, config, packages, deploy, .version)
    rm -rf "${RELEASE_DIR}/frontend" "${RELEASE_DIR}/backend/web/dist" "${RELEASE_DIR}/backend-rs/target"
}

simulate_offline_artifact() {
    log_info "[DRY-RUN] Offline mode: simulating single-binary artifact verification and extraction."
    mkdir -p "${RELEASE_DIR}/deploy/systemd" "${RELEASE_DIR}/packages" "${RELEASE_DIR}/config"
    echo "#!/bin/bash" > "${RELEASE_DIR}/aetherflow-api"
    chmod +x "${RELEASE_DIR}/aetherflow-api"
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
        if [[ -n "${target_tag}" ]]; then
            log_info "Resolved release tag ${target_tag} for channel ${CHANNEL}."
            if pull_prebuilt_artifact "${target_tag}"; then
                log_info "=== STAGE 1 COMPLETE: Pre-built release ${target_tag} staged at ${RELEASE_DIR} ==="
                return 0
            fi
            if [[ "${DRY_RUN}" == true ]]; then
                log_error "[DRY-RUN] Pre-built artifact pull failed for ${target_tag}. Refusing source-build fallback."
                rm -rf "${RELEASE_DIR}"
                exit 1
            fi
            log_warn "Pre-built artifact pull failed for ${target_tag}; falling back to source build."
        else
            if [[ "${DRY_RUN}" == true ]]; then
                log_error "[DRY-RUN] Could not resolve a release tag for channel ${CHANNEL}."
                rm -rf "${RELEASE_DIR}"
                exit 1
            fi
            log_warn "Could not resolve pre-built release tag for channel ${CHANNEL}; falling back to source build."
        fi
    elif [[ "${DRY_RUN}" == true ]]; then
        log_error "[DRY-RUN] Refusing --from-source. Use a published artifact, or --offline for a placeholder."
        rm -rf "${RELEASE_DIR}"
        exit 1
    fi

    if [[ "${DRY_RUN}" == true ]]; then
        log_error "[DRY-RUN] Refusing source build."
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
    mkdir -p "${snapshot_dir}"
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
    # Go and Rust releases both ship aetherflow-api and honor the `runner`
    # subcommand. Installed units already point at /opt/AetherFlow/current, so
    # a symlink rollback does not need a unit rewrite. Replacing a live unit
    # would drop host ReadWritePaths (the live DB may sit outside /var/lib).
    if [[ -d "${CURRENT_LINK}/deploy/systemd" ]]; then
        install_packaged_unit "${CURRENT_LINK}/deploy/systemd/aetherflow-runner.service"
        install_packaged_unit "${CURRENT_LINK}/deploy/systemd/aetherflow-api.service"
    fi

    systemctl daemon-reload

    # Stop legacy separate frontend service or PM2 if still present
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
    if ! command -v systemctl >/dev/null 2>&1; then
        log_warn "systemctl is absent; cannot stop aetherflow units before restoring ${1}."
        return 0
    fi
    log_info "Stopping aetherflow-api and aetherflow-runner before restoring ${1}."
    systemctl stop aetherflow-api.service aetherflow-runner.service || true
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
        log_warn "sqlite3 is absent; skipping integrity restore for ${db_path}."
        return 0
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

    local bak_integrity
    bak_integrity="$(sqlite_integrity "${bak_path}")"
    if [[ "${bak_integrity}" != "ok" ]]; then
        log_error "Refusing to restore snapshot ${bak_path} (integrity=${bak_integrity})."
        return 1
    fi

    stop_database_services "${db_path}"
    # Sidecars belong to this path only. Removing them before the service is
    # stopped would let a live process recreate a WAL over the restored file.
    rm -f "${db_path}-wal" "${db_path}-shm"
    if [[ -f "${db_path}" ]]; then
        mv "${db_path}" "${db_path}.corrupted.$(date +%s)"
    fi
    cp -pf "${bak_path}" "${db_path}"
    if id -u aetherflow >/dev/null 2>&1; then
        chown aetherflow:aetherflow "${db_path}" || true
    fi
    chmod 0600 "${db_path}" || true
    log "CRITICAL" "Database RESTORED to ${db_path} from verified snapshot: ${bak_path}"
}

rollback() {
    # $1, when set, is the release whose data-snapshot was taken before the
    # swap that just failed. That backup is the live database. A manual
    # rollback has no argument and uses the previous release's snapshot.
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
    log_info "Symlink reverted: ${CURRENT_LINK} -> ${previous_target}"

    if [[ -z "${snapshot_release}" ]]; then
        snapshot_release="${previous_target}"
    fi
    log_info "Database recovery snapshot release: ${snapshot_release}"

    # Both the Rust and Go control planes are the aetherflow-api binary and
    # both honor `aetherflow-api runner`, so the installed units stay valid.
    # Restore failure must not skip the restart of the reverted symlink.
    state_restore "${snapshot_release}" || log_error "Database restore failed; continuing with the reverted symlink."

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

case "${COMMAND}" in
    deploy)
        ensure_fhs_layout
        release_scaffold
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
        rollback
        ;;
    cleanup)
        cleanup_old_releases
        ;;
    migrate-systemd)
        migrate_systemd
        ;;
    *)
        echo "Usage: $0 {deploy|rollback|cleanup|migrate-systemd} [--channel stable|nightly|experimental] [--from-source] [--dry-run] [--offline]"
        exit 4
        ;;
esac
