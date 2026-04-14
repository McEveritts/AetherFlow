#!/bin/bash
###############################################################################
# AetherFlow Release Manager — Phase 2: State Snapshot & Systemd Migration
#
# Implements a Blue/Green symlink-based deployment engine with forensic
# state snapshots and an optional PM2 → systemd migration path.
#
# Usage:
#   release-manager.sh deploy              Full deploy cycle
#   release-manager.sh rollback            Manual rollback to previous release
#   release-manager.sh cleanup             Prune old release directories
#   release-manager.sh migrate-systemd     One-shot PM2 → systemd handoff
#   release-manager.sh deploy --dry-run    Simulate without touching /opt
#
# Exit Codes:
#   0 — Success
#   1 — Build failure (pre-swap, no rollback needed)
#   2 — Health probe failure (rollback executed)
#   3 — Rollback failure (manual intervention required)
#   4 — Configuration or environment error
#   5 — Systemd migration failure
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

# ── Runtime Flags ────────────────────────────────────────────────────────────
DRY_RUN=false
MIGRATE_SYSTEMD=false
for arg in "$@"; do
    case "${arg}" in
        --dry-run) DRY_RUN=true ;;
    esac
done

# ── Dry-Run Override ─────────────────────────────────────────────────────────
if [[ "${DRY_RUN}" == true ]]; then
    RELEASES_DIR="/tmp/aetherflow-dryrun/releases"
    CURRENT_LINK="/tmp/aetherflow-dryrun/current"
    REPO_DIR="/tmp/aetherflow-dryrun/repo"
    DATA_DIR="/tmp/aetherflow-dryrun/data"
    LOG_FILE="/tmp/aetherflow-dryrun/deploy.log"
    mkdir -p "${REPO_DIR}" "${DATA_DIR}"
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

# ── Epoch Generation ─────────────────────────────────────────────────────────
EPOCH="$(date +%s)"
RELEASE_DIR="${RELEASES_DIR}/${EPOCH}"

###############################################################################
# STAGE 1: Directory Scaffolding
###############################################################################
release_scaffold() {
    log_info "=== STAGE 1: Release Scaffold ==="
    log_info "Creating release directory: ${RELEASE_DIR}"
    mkdir -p "${RELEASE_DIR}"

    if [[ "${DRY_RUN}" == true ]]; then
        log_info "[DRY-RUN] Simulating source copy and build."
        mkdir -p "${RELEASE_DIR}/backend"
        mkdir -p "${RELEASE_DIR}/frontend"
        # Create a stub binary for dry-run verification
        echo "#!/bin/bash" > "${RELEASE_DIR}/backend/aetherflow-api"
        chmod +x "${RELEASE_DIR}/backend/aetherflow-api"
        return 0
    fi

    # ── Git Fetch & Verify ───────────────────────────────────────────────────
    log_info "Fetching latest from ${GIT_REMOTE}/${GIT_BRANCH}..."
    cd "${REPO_DIR}" || log_fatal "Repository directory not found: ${REPO_DIR}"
    git fetch "${GIT_REMOTE}" "${GIT_BRANCH}" >> "${LOG_FILE}" 2>&1

    local LOCAL_HEAD REMOTE_HEAD
    LOCAL_HEAD="$(git rev-parse HEAD)"
    REMOTE_HEAD="$(git rev-parse "${GIT_REMOTE}/${GIT_BRANCH}")"

    if [[ "${LOCAL_HEAD}" == "${REMOTE_HEAD}" ]]; then
        log_info "Already at latest commit (${LOCAL_HEAD:0:8}). Nothing to deploy."
        rmdir "${RELEASE_DIR}"
        exit 0
    fi

    # Stash local changes, pull, restore
    git stash --include-untracked -m "release-manager-${EPOCH}" >> "${LOG_FILE}" 2>&1 || true
    if ! git pull --ff-only "${GIT_REMOTE}" "${GIT_BRANCH}" >> "${LOG_FILE}" 2>&1; then
        log_warn "Fast-forward failed, attempting rebase..."
        if ! git pull --rebase "${GIT_REMOTE}" "${GIT_BRANCH}" >> "${LOG_FILE}" 2>&1; then
            log_error "Rebase failed. Aborting scaffold."
            git rebase --abort >> "${LOG_FILE}" 2>&1 || true
            rmdir "${RELEASE_DIR}" 2>/dev/null || true
            exit 1
        fi
    fi

    # ── Copy Source into Isolated Release ─────────────────────────────────────
    log_info "Copying source tree into ${RELEASE_DIR}..."
    rsync -a --exclude='.git' --exclude='node_modules' --exclude='.next' \
        "${REPO_DIR}/" "${RELEASE_DIR}/" >> "${LOG_FILE}" 2>&1

    # ── Build Go API ─────────────────────────────────────────────────────────
    log_info "Building Go API binary..."
    cd "${RELEASE_DIR}/backend" || log_fatal "Backend directory missing in release."
    export GOOS=linux GOARCH=amd64 CGO_ENABLED=1
    if ! "${GO_BIN}" mod tidy >> "${LOG_FILE}" 2>&1; then
        log_error "go mod tidy failed."
        exit 1
    fi
    if ! "${GO_BIN}" build -trimpath -buildvcs=false -o aetherflow-api main.go >> "${LOG_FILE}" 2>&1; then
        log_error "go build failed. Release directory will be removed."
        rm -rf "${RELEASE_DIR}"
        exit 1
    fi
    log_info "Go API binary compiled successfully."

    # ── Build Next.js Frontend ───────────────────────────────────────────────
    log_info "Building Next.js frontend..."
    cd "${RELEASE_DIR}/frontend" || log_fatal "Frontend directory missing in release."
    export NODE_OPTIONS="${NODE_OPTIONS:+${NODE_OPTIONS} }--max-old-space-size=${NODE_HEAP_MB}"
    if ! npm ci --no-fund --no-audit >> "${LOG_FILE}" 2>&1; then
        log_error "npm ci failed."
        rm -rf "${RELEASE_DIR}"
        exit 1
    fi
    if ! npm run build >> "${LOG_FILE}" 2>&1; then
        log_error "npm run build failed. Release directory will be removed."
        rm -rf "${RELEASE_DIR}"
        exit 1
    fi
    log_info "Next.js frontend built successfully."

    log_info "=== STAGE 1 COMPLETE: Release ${EPOCH} scaffolded ==="
}

###############################################################################
# STAGE 1.5: State Snapshot (Phase 2)
###############################################################################
state_snapshot() {
    log_info "=== STAGE 1.5: State Snapshot ==="

    local snapshot_dir="${RELEASE_DIR}/data-snapshot"
    mkdir -p "${snapshot_dir}"

    # ── Bootstrap Data Directory ─────────────────────────────────────────────
    if [[ ! -d "${DATA_DIR}" ]]; then
        log_warn "Data directory ${DATA_DIR} does not exist. Creating (fresh node bootstrap)."
        mkdir -p "${DATA_DIR}"
    fi

    local db_path="${DATA_DIR}/${SQLITE_DB}"
    local config_path="${DATA_DIR}/config.json"

    if [[ "${DRY_RUN}" == true ]]; then
        # Create mock data files for dry-run snapshot simulation
        if [[ ! -f "${db_path}" ]]; then
            # Create a minimal SQLite database for testing
            if command -v sqlite3 &>/dev/null; then
                sqlite3 "${db_path}" "CREATE TABLE IF NOT EXISTS _meta (key TEXT, value TEXT); INSERT INTO _meta VALUES ('version','dryrun');"
            else
                touch "${db_path}"
            fi
        fi
        if [[ ! -f "${config_path}" ]]; then
            echo '{"mode":"dryrun"}' > "${config_path}"
        fi
    fi

    # ── Flock-Guarded Snapshot ────────────────────────────────────────────────
    local lock_file="${DATA_DIR}/.snapshot.lock"
    log_info "Acquiring snapshot lock: ${lock_file}"

    (
        if ! flock -w "${SNAPSHOT_TIMEOUT}" 200; then
            log_error "Failed to acquire snapshot lock within ${SNAPSHOT_TIMEOUT}s."
            return 1
        fi

        # SQLite Hot Backup (Online Backup API — does not lock the live WAL)
        if [[ -f "${db_path}" ]]; then
            local bak_path="${snapshot_dir}/${SQLITE_DB}.bak"
            if command -v sqlite3 &>/dev/null; then
                log_info "Executing SQLite online backup: ${db_path} -> ${bak_path}"
                sqlite3 "${db_path}" ".backup '${bak_path}'" 2>>"${LOG_FILE}"
            else
                # Fallback: raw copy (less safe, but better than nothing)
                log_warn "sqlite3 not found. Using raw copy for database backup."
                cp "${db_path}" "${bak_path}"
            fi
        else
            log_warn "No SQLite database found at ${db_path}. Skipping DB snapshot."
        fi

        # JSON Configuration Snapshot
        if [[ -f "${config_path}" ]]; then
            cp "${config_path}" "${snapshot_dir}/config.json.bak"
            log_info "Configuration snapshot captured."
        else
            log_warn "No config.json found at ${config_path}. Skipping config snapshot."
        fi

    ) 200>"${lock_file}"

    # ── SHA-256 Manifest ─────────────────────────────────────────────────────
    log_info "Generating SHA-256 checksum manifest..."
    (
        cd "${snapshot_dir}"
        sha256sum -- *.bak 2>/dev/null > MANIFEST.sha256 || true
    )

    if [[ -f "${snapshot_dir}/MANIFEST.sha256" ]]; then
        log_info "Manifest written: ${snapshot_dir}/MANIFEST.sha256"
    fi

    log_info "=== STAGE 1.5 COMPLETE: State snapshot captured ==="
}

###############################################################################
# STAGE 2: Atomic Symlink Swap
###############################################################################
symlink_swap() {
    log_info "=== STAGE 2: Symlink Swap ==="

    # Record the previous release target for rollback
    if [[ -L "${CURRENT_LINK}" ]]; then
        local previous_target
        previous_target="$(readlink -f "${CURRENT_LINK}")"
        echo "${previous_target}" > "${RELEASES_DIR}/.previous_release"
        log_info "Previous release recorded: ${previous_target}"
    else
        log_warn "No existing symlink at ${CURRENT_LINK}. First deployment."
    fi

    # Atomic swap: ln -sfn creates a new symlink then renames over the old one
    # We use a temporary link + mv for true atomicity (ln -sfn is not atomic on
    # all filesystems when the target already exists).
    local tmp_link="${CURRENT_LINK}.tmp.${EPOCH}"
    ln -s "${RELEASE_DIR}" "${tmp_link}"
    mv -Tf "${tmp_link}" "${CURRENT_LINK}"

    log_info "Symlink updated: ${CURRENT_LINK} -> ${RELEASE_DIR}"
    log_info "=== STAGE 2 COMPLETE ==="
}

###############################################################################
# STAGE 3: Service Restart & Deep Health Probe
###############################################################################
health_probe() {
    log_info "=== STAGE 3: Health Probe ==="

    if [[ "${DRY_RUN}" == true ]]; then
        log_info "[DRY-RUN] Skipping service restart and health probe."
        return 0
    fi

    # Restart services via PM2 (Phase 1 — systemd migration deferred)
    log_info "Restarting Go API via PM2..."
    pm2 restart aetherflow-api 2>/dev/null || \
        pm2 start "${CURRENT_LINK}/backend/aetherflow-api" --name "aetherflow-api" >> "${LOG_FILE}" 2>&1

    log_info "Restarting Next.js frontend via PM2..."
    cd "${CURRENT_LINK}/frontend" || log_fatal "Frontend directory not found in current release."
    pm2 restart aetherflow-frontend 2>/dev/null || \
        pm2 start npm --name "aetherflow-frontend" -- start >> "${LOG_FILE}" 2>&1

    pm2 save >> "${LOG_FILE}" 2>&1

    # ── Deep Readiness Polling ───────────────────────────────────────────────
    log_info "Polling ${HEALTH_ENDPOINT} (${HEALTH_RETRIES} attempts, ${HEALTH_INTERVAL}s interval)..."

    local attempt=1
    while [[ ${attempt} -le ${HEALTH_RETRIES} ]]; do
        local http_code response
        response="$(curl -sf --max-time 5 "${HEALTH_ENDPOINT}" 2>/dev/null)" || true
        http_code="$(curl -so /dev/null -w "%{http_code}" --max-time 5 "${HEALTH_ENDPOINT}" 2>/dev/null)" || http_code="000"

        if [[ "${http_code}" == "200" ]]; then
            # Parse the deep status field — must be "ready", not just "alive"
            local status
            status="$(echo "${response}" | grep -o '"status"\s*:\s*"[^"]*"' | head -1 | grep -o '"[^"]*"$' | tr -d '"')" || status="unknown"

            if [[ "${status}" == "ready" ]]; then
                log_info "Health probe PASSED on attempt ${attempt}/${HEALTH_RETRIES} (status=${status})"
                log_info "=== STAGE 3 COMPLETE ==="
                return 0
            else
                log_warn "Attempt ${attempt}/${HEALTH_RETRIES}: HTTP 200 but status=\"${status}\" (expected \"ready\")"
            fi
        else
            log_warn "Attempt ${attempt}/${HEALTH_RETRIES}: HTTP ${http_code}"
        fi

        sleep "${HEALTH_INTERVAL}"
        attempt=$((attempt + 1))
    done

    log_error "Health probe FAILED after ${HEALTH_RETRIES} attempts."
    return 1
}

###############################################################################
# STAGE 4: Rollback (with State Integrity Check)
###############################################################################
rollback() {
    log_error "=== STAGE 4: ROLLBACK INITIATED ==="

    local prev_file="${RELEASES_DIR}/.previous_release"
    if [[ ! -f "${prev_file}" ]]; then
        log_fatal "No previous release record found at ${prev_file}. Manual intervention required."
        exit 3
    fi

    local previous_target
    previous_target="$(cat "${prev_file}")"

    if [[ ! -d "${previous_target}" ]]; then
        log_fatal "Previous release directory does not exist: ${previous_target}. MANUAL INTERVENTION REQUIRED."
        exit 3
    fi

    # Revert symlink
    local tmp_link="${CURRENT_LINK}.rollback.${EPOCH}"
    ln -s "${previous_target}" "${tmp_link}"
    mv -Tf "${tmp_link}" "${CURRENT_LINK}"
    log_info "Symlink reverted: ${CURRENT_LINK} -> ${previous_target}"

    # ── State Integrity Check & Conditional Restore ───────────────────────────
    state_restore "${previous_target}"

    if [[ "${DRY_RUN}" == true ]]; then
        log_info "[DRY-RUN] Skipping service restart on rollback."
        log_info "=== ROLLBACK COMPLETE (DRY-RUN) ==="
        return 0
    fi

    # Restart services against the reverted release
    pm2 restart aetherflow-api 2>/dev/null || \
        pm2 start "${CURRENT_LINK}/backend/aetherflow-api" --name "aetherflow-api" >> "${LOG_FILE}" 2>&1
    cd "${CURRENT_LINK}/frontend" || true
    pm2 restart aetherflow-frontend 2>/dev/null || \
        pm2 start npm --name "aetherflow-frontend" -- start >> "${LOG_FILE}" 2>&1
    pm2 save >> "${LOG_FILE}" 2>&1

    log_error "=== ROLLBACK COMPLETE: Reverted to ${previous_target} ==="
}

###############################################################################
# STAGE 4.5: State Integrity Verification & Restore
###############################################################################
state_restore() {
    local target_release="${1}"
    local db_path="${DATA_DIR}/${SQLITE_DB}"
    local snapshot_dir="${target_release}/data-snapshot"
    local bak_path="${snapshot_dir}/${SQLITE_DB}.bak"

    log_info "=== STAGE 4.5: State Integrity Check ==="

    # Skip if no database exists (fresh node)
    if [[ ! -f "${db_path}" ]]; then
        log_warn "No live database found. Skipping integrity check."
        return 0
    fi

    if [[ "${DRY_RUN}" == true ]]; then
        log_info "[DRY-RUN] Simulating integrity check."
        if command -v sqlite3 &>/dev/null && [[ -f "${db_path}" ]]; then
            local integrity
            integrity="$(sqlite3 "${db_path}" 'PRAGMA integrity_check;' 2>/dev/null)" || integrity="error"
            log_info "[DRY-RUN] Integrity result: ${integrity}"
        fi
        return 0
    fi

    # ── PRAGMA Integrity Check ────────────────────────────────────────────────
    if command -v sqlite3 &>/dev/null; then
        local integrity
        integrity="$(sqlite3 "${db_path}" 'PRAGMA integrity_check;' 2>/dev/null)" || integrity="error"

        if [[ "${integrity}" == "ok" ]]; then
            log_info "Database integrity check PASSED."
            return 0
        fi

        # ── Corruption Detected — Restore from Snapshot ──────────────────────
        log "CRITICAL" "DATABASE CORRUPTION DETECTED: ${integrity}"

        if [[ -f "${bak_path}" ]]; then
            # Verify the backup's own integrity before restoring
            local bak_integrity
            bak_integrity="$(sqlite3 "${bak_path}" 'PRAGMA integrity_check;' 2>/dev/null)" || bak_integrity="error"

            if [[ "${bak_integrity}" == "ok" ]]; then
                # Quarantine the corrupted database
                local quarantine="${db_path}.corrupted.$(date +%s)"
                mv "${db_path}" "${quarantine}"
                log_info "Corrupted database quarantined: ${quarantine}"

                # Restore from verified backup
                cp "${bak_path}" "${db_path}"
                log "CRITICAL" "Database RESTORED from snapshot: ${bak_path}"
            else
                log_error "Backup snapshot is ALSO corrupted (${bak_integrity}). Manual intervention required."
            fi
        else
            log_error "No backup snapshot found at ${bak_path}. Cannot auto-restore."
        fi

        # Restore config.json if available
        local config_bak="${snapshot_dir}/config.json.bak"
        local config_live="${DATA_DIR}/config.json"
        if [[ -f "${config_bak}" ]] && [[ -f "${config_live}" ]]; then
            cp "${config_bak}" "${config_live}"
            log_info "Configuration restored from snapshot."
        fi
    else
        log_warn "sqlite3 not available. Skipping integrity check."
    fi
}

###############################################################################
# STAGE 5: Housekeeping
###############################################################################
cleanup_old_releases() {
    log_info "=== Housekeeping: Pruning old releases ==="

    local current_target=""
    if [[ -L "${CURRENT_LINK}" ]]; then
        current_target="$(readlink -f "${CURRENT_LINK}")"
    fi

    local previous_target=""
    if [[ -f "${RELEASES_DIR}/.previous_release" ]]; then
        previous_target="$(cat "${RELEASES_DIR}/.previous_release")"
    fi

    # List release directories sorted oldest first
    local releases=()
    while IFS= read -r dir; do
        releases+=("${dir}")
    done < <(find "${RELEASES_DIR}" -mindepth 1 -maxdepth 1 -type d | sort -n)

    local count=${#releases[@]}
    if [[ ${count} -le ${MAX_RELEASES} ]]; then
        log_info "Only ${count} releases exist (max=${MAX_RELEASES}). Nothing to prune."
        return 0
    fi

    local to_prune=$((count - MAX_RELEASES))
    local pruned=0
    for dir in "${releases[@]}"; do
        if [[ ${pruned} -ge ${to_prune} ]]; then
            break
        fi
        # Never delete the current or previous release
        if [[ "${dir}" == "${current_target}" ]] || [[ "${dir}" == "${previous_target}" ]]; then
            log_warn "Skipping protected release: ${dir}"
            continue
        fi
        log_info "Pruning old release: ${dir}"
        rm -rf "${dir}"
        pruned=$((pruned + 1))
    done

    log_info "Pruned ${pruned} old release(s)."
}

###############################################################################
# STAGE 6: PM2 → Systemd Migration (One-Shot)
###############################################################################
migrate_systemd() {
    log_info "=== STAGE 6: PM2 → Systemd Migration ==="

    if [[ "${DRY_RUN}" == true ]]; then
        log_info "[DRY-RUN] Would copy service units from ${SYSTEMD_UNITS_SRC}/ to ${SYSTEMD_UNITS_DST}/"
        log_info "[DRY-RUN] Would execute: pm2 kill → systemctl daemon-reload → systemctl start"
        log_info "=== STAGE 6 COMPLETE (DRY-RUN) ==="
        return 0
    fi

    # Validate prerequisites
    if [[ ! -d "${SYSTEMD_UNITS_SRC}" ]]; then
        log_fatal "Systemd unit source directory not found: ${SYSTEMD_UNITS_SRC}"
    fi

    if ! command -v systemctl &>/dev/null; then
        log_fatal "systemctl not found. Cannot perform systemd migration."
    fi

    # ── Step 1: Install service unit files ────────────────────────────────────
    log_info "Installing systemd unit files..."
    for unit_file in "${SYSTEMD_UNITS_SRC}"/*.service; do
        local basename
        basename="$(basename "${unit_file}")"
        cp "${unit_file}" "${SYSTEMD_UNITS_DST}/${basename}"
        log_info "Installed: ${SYSTEMD_UNITS_DST}/${basename}"
    done

    # ── Step 2: Reload systemd daemon ─────────────────────────────────────────
    systemctl daemon-reload
    log_info "systemd daemon reloaded."

    # ── Step 3: Kill PM2 to release bound sockets ────────────────────────────
    log_warn "Killing PM2 to release port binds (EADDRINUSE prevention)..."
    pm2 kill >> "${LOG_FILE}" 2>&1 || log_warn "PM2 was not running."
    # Brief pause to ensure sockets are fully released by the kernel
    sleep 2

    # ── Step 4: Start services via systemd ────────────────────────────────────
    log_info "Starting aetherflow-api.service..."
    if ! systemctl start aetherflow-api.service >> "${LOG_FILE}" 2>&1; then
        log_error "Failed to start aetherflow-api.service. Attempting PM2 recovery."
        _migration_rollback_pm2
        exit 5
    fi

    log_info "Starting aetherflow-frontend.service..."
    if ! systemctl start aetherflow-frontend.service >> "${LOG_FILE}" 2>&1; then
        log_error "Failed to start aetherflow-frontend.service. Attempting PM2 recovery."
        systemctl stop aetherflow-api.service >> "${LOG_FILE}" 2>&1 || true
        _migration_rollback_pm2
        exit 5
    fi

    # ── Step 5: Deep health probe ─────────────────────────────────────────────
    if ! health_probe; then
        log_error "Health probe failed after systemd migration. Rolling back to PM2."
        systemctl stop aetherflow-api.service >> "${LOG_FILE}" 2>&1 || true
        systemctl stop aetherflow-frontend.service >> "${LOG_FILE}" 2>&1 || true
        _migration_rollback_pm2
        exit 5
    fi

    # ── Step 6: Enable units and remove PM2 from startup ─────────────────────
    systemctl enable aetherflow-api.service >> "${LOG_FILE}" 2>&1
    systemctl enable aetherflow-frontend.service >> "${LOG_FILE}" 2>&1
    log_info "Systemd units enabled for boot."

    # Remove PM2 startup hook (if it exists)
    pm2 unstartup >> "${LOG_FILE}" 2>&1 || true

    log_info "========================================================"
    log_info "MIGRATION COMPLETE: PM2 → systemd. All services healthy."
    log_info "========================================================"
}

# Helper: Rollback to PM2 if systemd migration fails
_migration_rollback_pm2() {
    log_warn "Restoring PM2 process management..."
    pm2 start "${CURRENT_LINK}/backend/aetherflow-api" --name "aetherflow-api" >> "${LOG_FILE}" 2>&1 || true
    cd "${CURRENT_LINK}/frontend" 2>/dev/null || true
    pm2 start npm --name "aetherflow-frontend" -- start >> "${LOG_FILE}" 2>&1 || true
    pm2 save >> "${LOG_FILE}" 2>&1 || true
    log_warn "PM2 restored. Systemd migration ABORTED."
}

###############################################################################
# ENTRYPOINT
###############################################################################
main() {
    local command="${1:-deploy}"

    log_info "========================================================"
    log_info "AetherFlow Release Manager v2.0"
    log_info "Command: ${command} | Epoch: ${EPOCH} | Dry-Run: ${DRY_RUN}"
    log_info "========================================================"

    case "${command}" in
        deploy)
            release_scaffold
            state_snapshot
            symlink_swap
            if ! health_probe; then
                rollback
                exit 2
            fi
            cleanup_old_releases
            log_info "========================================================"
            log_info "DEPLOYMENT SUCCESSFUL: Release ${EPOCH} is now live."
            log_info "========================================================"
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
            echo "Usage: $0 {deploy|rollback|cleanup|migrate-systemd} [--dry-run]"
            exit 4
            ;;
    esac
}

main "$@"
