#!/bin/bash
###############################################################################
# AetherFlow Release Manager v3.0 — Pull-Based Single-Binary Atomic Engine
#
# Pulls pre-built, checksum-verified single-binary releases from GitHub Releases
# (or builds in fallback --from-source mode), snapshots /var/lib/aetherflow
# SQLite state using online backup + flock, atomically swaps /opt/AetherFlow/current,
# restarts systemd units (aetherflow-runner + aetherflow-api), and runs a deep
# readiness probe with automatic rollback + SQLite PRAGMA integrity recovery.
#
# Usage:
#   release-manager.sh deploy [--channel stable|beta|nightly] [--from-source] [--dry-run]
#   release-manager.sh rollback [--dry-run]
#   release-manager.sh cleanup [--dry-run]
#   release-manager.sh migrate-systemd [--dry-run]
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
CHANNEL="${RELEASE_CHANNEL:-stable}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
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
        stable|beta|nightly)
            CHANNEL="$1"
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# ── Dry-Run Override ─────────────────────────────────────────────────────────
if [[ "${DRY_RUN}" == true ]]; then
    RELEASES_DIR="/tmp/aetherflow-dryrun/releases"
    CURRENT_LINK="/tmp/aetherflow-dryrun/current"
    REPO_DIR="/tmp/aetherflow-dryrun/repo"
    DATA_DIR="/tmp/aetherflow-dryrun/data"
    ENV_DIR="/tmp/aetherflow-dryrun/etc"
    ENV_FILE="/tmp/aetherflow-dryrun/etc/aetherflow.env"
    LOG_FILE="/tmp/aetherflow-dryrun/deploy.log"
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

    # Migrate legacy SQLite DB if /var/lib/aetherflow/aetherflow.sqlite is not yet populated
    local target_db="${DATA_DIR}/${SQLITE_DB}"
    if [[ ! -f "${target_db}" ]]; then
        for legacy_db in "/opt/AetherFlow/backend/data/${SQLITE_DB}" "/opt/AetherFlow/backend/${SQLITE_DB}"; do
            if [[ -f "${legacy_db}" ]]; then
                log_info "Migrating legacy SQLite database from ${legacy_db} to ${target_db}..."
                cp -pf "${legacy_db}" "${target_db}"
                if [[ "${DRY_RUN}" == false ]] && id -u aetherflow &>/dev/null; then
                    chown aetherflow:aetherflow "${target_db}"
                    chmod 0600 "${target_db}"
                fi
                break
            fi
        done
    fi

    # Migrate legacy .env if /etc/aetherflow/aetherflow.env is not yet populated
    if [[ ! -f "${ENV_FILE}" ]]; then
        for legacy_env in "/opt/AetherFlow/backend/.env" "/opt/AetherFlow/.env"; do
            if [[ -f "${legacy_env}" ]]; then
                log_info "Migrating legacy environment secrets from ${legacy_env} to ${ENV_FILE}..."
                cp -pf "${legacy_env}" "${ENV_FILE}"
                chmod 0600 "${ENV_FILE}"
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

    if [[ "${channel}" == "nightly" ]]; then
        echo "nightly"
        return 0
    fi

    local releases_json
    releases_json="$(curl -sfL --max-time 15 "${api_url}" 2>/dev/null)" || return 1

    if [[ "${channel}" == "beta" ]]; then
        echo "${releases_json}" | grep -o '"tag_name"\s*:\s*"[^"]*"' | head -1 | cut -d'"' -f4
    else
        # Stable: first release without a pre-release hyphen in tag_name
        echo "${releases_json}" | grep -o '"tag_name"\s*:\s*"[^"]*"' | cut -d'"' -f4 | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | head -1
    fi
}

pull_prebuilt_artifact() {
    local tag="$1"
    local base_url="https://github.com/${GITHUB_REPO}/releases/download/${tag}"
    local tmp_dir
    tmp_dir="$(mktemp -d /tmp/af-release-XXXXXX)"

    log_info "Downloading pre-built release ${tag} (${ARTIFACT_NAME})..."
    if ! curl -fsSL --max-time 120 -o "${tmp_dir}/${ARTIFACT_NAME}" "${base_url}/${ARTIFACT_NAME}"; then
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
    (
        cd "${tmp_dir}"
        local expected_hash actual_hash
        expected_hash="$(awk -v f="${ARTIFACT_NAME}" '$2 == f || $2 == "*"f {print tolower($1); exit}' "${CHECKSUM_NAME}")"
        actual_hash="$(sha256sum "${ARTIFACT_NAME}" | awk '{print tolower($1)}')"
        [[ -n "${expected_hash}" && "${#expected_hash}" -eq 64 && "${actual_hash}" == "${expected_hash}" ]]
    ) || {
        log_error "SHA-256 verification FAILED for ${ARTIFACT_NAME}! Aborting deployment."
        rm -rf "${tmp_dir}"
        return 1
    }

    log_info "SHA-256 checksum verified. Extracting into ${RELEASE_DIR}..."
    tar -xzf "${tmp_dir}/${ARTIFACT_NAME}" -C "${RELEASE_DIR}"
    if [[ ! -s "${RELEASE_DIR}/.version" ]]; then
        echo "${tag}" > "${RELEASE_DIR}/.version"
    fi
    chmod +x "${RELEASE_DIR}/aetherflow-api"
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
    if [[ "${CHANNEL}" == "nightly" ]]; then
        echo "nightly-${source_sha}" > "${RELEASE_DIR}/.version"
    fi

    log_info "Building Next.js static export (NEXT_STATIC_EXPORT=1)..."
    cd "${RELEASE_DIR}/frontend" || log_fatal "Frontend directory missing."
    export NODE_OPTIONS="${NODE_OPTIONS:+${NODE_OPTIONS} }--max-old-space-size=${NODE_HEAP_MB}"
    export NEXT_STATIC_EXPORT="1"
    npm ci --no-fund --no-audit >> "${LOG_FILE}" 2>&1
    npm run build >> "${LOG_FILE}" 2>&1

    log_info "Embedding frontend static bundle into Go binary (backend/web/dist)..."
    rm -rf "${RELEASE_DIR}/backend/web/dist"
    mkdir -p "${RELEASE_DIR}/backend/web/dist"
    cp -R "${RELEASE_DIR}/frontend/out/." "${RELEASE_DIR}/backend/web/dist/"

    log_info "Compiling single-binary AetherFlow control plane..."
    cd "${RELEASE_DIR}/backend" || log_fatal "Backend directory missing."
    export GOOS=linux GOARCH=amd64 CGO_ENABLED=0
    "${GO_BIN}" build -trimpath -buildvcs=false -o "${RELEASE_DIR}/aetherflow-api" . >> "${LOG_FILE}" 2>&1
    chmod +x "${RELEASE_DIR}/aetherflow-api"

    # Retain only runtime essentials (binary, config, packages, deploy, .version)
    rm -rf "${RELEASE_DIR}/frontend" "${RELEASE_DIR}/backend/web/dist"
}

release_scaffold() {
    log_info "=== STAGE 1: Release Scaffold (Channel: ${CHANNEL}) ==="
    mkdir -p "${RELEASE_DIR}"

    if [[ "${DRY_RUN}" == true ]]; then
        log_info "[DRY-RUN] Simulating single-binary artifact verification and extraction."
        mkdir -p "${RELEASE_DIR}/deploy/systemd" "${RELEASE_DIR}/packages" "${RELEASE_DIR}/config"
        echo "#!/bin/bash" > "${RELEASE_DIR}/aetherflow-api"
        chmod +x "${RELEASE_DIR}/aetherflow-api"
        echo "v3.1.7-dryrun" > "${RELEASE_DIR}/.version"
        return 0
    fi

    if [[ "${FROM_SOURCE}" == false ]]; then
        local target_tag=""
        target_tag="$(resolve_release_tag "${CHANNEL}" || true)"
        if [[ -n "${target_tag}" ]]; then
            if pull_prebuilt_artifact "${target_tag}"; then
                log_info "=== STAGE 1 COMPLETE: Pre-built release ${target_tag} staged at ${RELEASE_DIR} ==="
                return 0
            fi
            log_warn "Pre-built artifact pull failed for ${target_tag}; falling back to source build."
        else
            log_warn "Could not resolve pre-built release tag for channel ${CHANNEL}; falling back to source build."
        fi
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

    local snapshot_dir="${RELEASE_DIR}/data-snapshot"
    mkdir -p "${snapshot_dir}"

    local db_path="${DATA_DIR}/${SQLITE_DB}"

    if [[ "${DRY_RUN}" == true ]] && [[ ! -f "${db_path}" ]]; then
        if command -v sqlite3 &>/dev/null; then
            sqlite3 "${db_path}" "CREATE TABLE IF NOT EXISTS _meta (key TEXT, value TEXT); INSERT INTO _meta VALUES ('version','dryrun');"
        else
            touch "${db_path}"
        fi
    fi

    local lock_file="${DATA_DIR}/.snapshot.lock"
    (
        if ! flock -w "${SNAPSHOT_TIMEOUT}" 200; then
            log_error "Failed to acquire snapshot lock within ${SNAPSHOT_TIMEOUT}s."
            return 1
        fi

        if [[ -f "${db_path}" ]]; then
            local bak_path="${snapshot_dir}/${SQLITE_DB}.bak"
            if command -v sqlite3 &>/dev/null; then
                log_info "Executing SQLite online backup: ${db_path} -> ${bak_path}"
                sqlite3 "${db_path}" ".backup '${bak_path}'" 2>>"${LOG_FILE}"
            else
                cp -pf "${db_path}" "${bak_path}"
            fi
        fi
    ) 200>"${lock_file}"

    (
        cd "${snapshot_dir}"
        sha256sum -- *.bak 2>/dev/null > MANIFEST.sha256 || true
    )
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
restart_systemd_units() {
    if [[ -d "${CURRENT_LINK}/deploy/systemd" ]]; then
        cp -f "${CURRENT_LINK}/deploy/systemd/aetherflow-runner.service" "${SYSTEMD_UNITS_DST}/" 2>/dev/null || true
        cp -f "${CURRENT_LINK}/deploy/systemd/aetherflow-api.service" "${SYSTEMD_UNITS_DST}/" 2>/dev/null || true
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
        local http_code response
        response="$(curl -sf --max-time 5 "${HEALTH_ENDPOINT}" 2>/dev/null)" || true
        http_code="$(curl -so /dev/null -w "%{http_code}" --max-time 5 "${HEALTH_ENDPOINT}" 2>/dev/null)" || http_code="000"

        if [[ "${http_code}" == "200" ]]; then
            local status
            status="$(echo "${response}" | grep -o '"status"\s*:\s*"[^"]*"' | head -1 | grep -o '"[^"]*"$' | tr -d '"')" || status="unknown"
            if [[ "${status}" == "ready" || "${status}" == "ok" ]]; then
                log_info "Health probe PASSED on attempt ${attempt}/${HEALTH_RETRIES} (status=${status})"
                return 0
            fi
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
state_restore() {
    local target_release="${1}"
    local db_path="${DATA_DIR}/${SQLITE_DB}"
    local bak_path="${target_release}/data-snapshot/${SQLITE_DB}.bak"

    [[ ! -f "${db_path}" ]] && return 0
    [[ "${DRY_RUN}" == true ]] && return 0

    if command -v sqlite3 &>/dev/null; then
        local integrity
        integrity="$(sqlite3 "${db_path}" 'PRAGMA integrity_check;' 2>/dev/null)" || integrity="error"
        if [[ "${integrity}" == "ok" ]]; then
            log_info "Database integrity check PASSED."
            return 0
        fi

        log "CRITICAL" "DATABASE CORRUPTION DETECTED (${integrity}) — Restoring snapshot..."
        if [[ -f "${bak_path}" ]]; then
            local bak_integrity
            bak_integrity="$(sqlite3 "${bak_path}" 'PRAGMA integrity_check;' 2>/dev/null)" || bak_integrity="error"
            if [[ "${bak_integrity}" == "ok" ]]; then
                mv "${db_path}" "${db_path}.corrupted.$(date +%s)"
                cp -pf "${bak_path}" "${db_path}"
                log "CRITICAL" "Database RESTORED from verified snapshot: ${bak_path}"
            fi
        fi
    fi
}

rollback() {
    log_error "=== STAGE 4: ROLLBACK INITIATED ==="
    local prev_file="${RELEASES_DIR}/.previous_release"
    if [[ ! -f "${prev_file}" ]]; then
        log_fatal "No previous release record found at ${prev_file}."
        exit 3
    fi

    local previous_target
    previous_target="$(cat "${prev_file}")"
    if [[ ! -d "${previous_target}" ]]; then
        log_fatal "Previous release directory missing: ${previous_target}."
        exit 3
    fi

    local tmp_link="${CURRENT_LINK}.rollback.${EPOCH}"
    ln -s "${previous_target}" "${tmp_link}"
    mv -Tf "${tmp_link}" "${CURRENT_LINK}"
    log_info "Symlink reverted: ${CURRENT_LINK} -> ${previous_target}"

    state_restore "${previous_target}"

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
        state_snapshot
        symlink_swap
        if ! health_probe; then
            rollback
            exit 2
        fi
        cleanup_old_releases
        log_info "DEPLOYMENT SUCCESSFUL: Release ${EPOCH} (${CHANNEL}) is now live."
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
        echo "Usage: $0 {deploy|rollback|cleanup|migrate-systemd} [--channel stable|beta|nightly] [--from-source] [--dry-run]"
        exit 4
        ;;
esac
