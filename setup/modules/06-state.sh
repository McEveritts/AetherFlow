#!/bin/bash
# Module: 06-state.sh
# Installer State Tracking & Recovery Engine
#
# Provides checkpoint/resume capability so failed installs can be
# resumed without a full OS reinstall.
#
# v2 — Atomic writes, step versioning, lockfile integrity, safe config overlay.

STATE_FILE="${STATE_FILE:-/install/.aetherflow.state}"
CONFIG_FILE="${CONFIG_FILE:-/install/.aetherflow.conf}"
INSTALL_LOG="${INSTALL_LOG:-/install/.aetherflow.install.log}"
LOCKFILE="${LOCKFILE:-/var/run/aetherflow-setup.lock}"

# State file format version. Bump this when step IDs change incompatibly.
STATE_VERSION="2"

# REPAIR_STEPS is set by --repair flag parsing in the main script
# It is a space-separated list of step IDs to force re-run
REPAIR_STEPS="${REPAIR_STEPS:-}"
FRESH_INSTALL="${FRESH_INSTALL:-false}"

################################################################################
# Lockfile — Prevents concurrent installer instances
################################################################################

# Acquire an exclusive lockfile. Uses bash noclobber (set -C) for atomic
# creation — no race condition possible between check-and-write.
_acquire_lock() {
    local lockdir
    lockdir="$(dirname "${LOCKFILE}")"
    mkdir -p "${lockdir}" 2>/dev/null || true

    if ( set -C; echo $$ > "${LOCKFILE}" ) 2>/dev/null; then
        # Lock acquired successfully
        return 0
    fi

    # Lockfile already exists — check if the owning process is still alive
    local existing_pid
    existing_pid="$(cat "${LOCKFILE}" 2>/dev/null)" || existing_pid=""

    if [[ -z "${existing_pid}" ]]; then
        # Empty/corrupt lockfile — reclaim it
        rm -f "${LOCKFILE}"
        ( set -C; echo $$ > "${LOCKFILE}" ) 2>/dev/null && return 0
    fi

    # Check if the PID is still running
    if kill -0 "${existing_pid}" 2>/dev/null; then
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "  ERROR: Another instance of AetherFlow Setup is running!"
        echo ""
        echo "  PID: ${existing_pid}"
        echo "  Lockfile: ${LOCKFILE}"
        echo ""
        echo "  If you believe this is stale, remove the lockfile manually:"
        echo "    rm -f ${LOCKFILE}"
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        exit 1
    fi

    # Process is dead — stale lock. Reclaim it.
    echo "[INFO] Reclaiming stale lockfile from dead PID ${existing_pid}"
    rm -f "${LOCKFILE}"
    ( set -C; echo $$ > "${LOCKFILE}" ) 2>/dev/null && return 0

    echo "[ERROR] Failed to acquire lockfile: ${LOCKFILE}"
    exit 1
}

# Release the lockfile, but only if it belongs to us (PID match).
_release_lock() {
    if [[ -f "${LOCKFILE}" ]]; then
        local lock_pid
        lock_pid="$(cat "${LOCKFILE}" 2>/dev/null)" || lock_pid=""
        if [[ "${lock_pid}" == "$$" ]]; then
            rm -f "${LOCKFILE}"
        fi
    fi
}

# Register cleanup traps so the lockfile is always released.
_setup_lock_trap() {
    trap '_release_lock' EXIT INT TERM HUP
}

################################################################################
# State File Functions — Atomic & Versioned
################################################################################

# Ensure /install directory exists and state file has a version header
_init_state() {
    mkdir -p "$(dirname "${STATE_FILE}")"
    touch "${STATE_FILE}" 2>/dev/null
    touch "${CONFIG_FILE}" 2>/dev/null

    # Inject version header if missing
    if [[ -s "${STATE_FILE}" ]]; then
        local first_line
        first_line="$(head -n1 "${STATE_FILE}")"
        if [[ "${first_line}" != "# STATE_VERSION="* ]]; then
            # Legacy state file (v1) — prepend version header
            local tmp_state
            tmp_state="$(mktemp "${STATE_FILE}.XXXXXX")" || return 1
            echo "# STATE_VERSION=${STATE_VERSION}" > "${tmp_state}"
            cat "${STATE_FILE}" >> "${tmp_state}"
            sync "${tmp_state}" 2>/dev/null || true
            mv -f "${tmp_state}" "${STATE_FILE}"
        fi
    else
        echo "# STATE_VERSION=${STATE_VERSION}" > "${STATE_FILE}"
    fi
}

# Validate that the state file version matches the current installer
_validate_state_version() {
    if [[ ! -s "${STATE_FILE}" ]]; then
        return 0
    fi

    local first_line file_version
    first_line="$(head -n1 "${STATE_FILE}")"
    if [[ "${first_line}" == "# STATE_VERSION="* ]]; then
        file_version="${first_line#*=}"
    else
        file_version="1"
    fi

    if [[ "${file_version}" != "${STATE_VERSION}" ]]; then
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "  WARNING: State file version mismatch!"
        echo ""
        echo "  State file version: ${file_version}"
        echo "  Installer version:  ${STATE_VERSION}"
        echo ""
        echo "  The installer has been upgraded since the last run."
        echo "  Already-completed steps will still be honored, but new"
        echo "  steps may be added. Updating state version marker."
        echo "═══════════════════════════════════════════════════════════════"
        echo ""
        # Update the version header in-place
        local tmp_state
        tmp_state="$(mktemp "${STATE_FILE}.XXXXXX")" || return 1
        echo "# STATE_VERSION=${STATE_VERSION}" > "${tmp_state}"
        # Copy all non-header lines
        tail -n +2 "${STATE_FILE}" >> "${tmp_state}"
        sync "${tmp_state}" 2>/dev/null || true
        mv -f "${tmp_state}" "${STATE_FILE}"
    fi
}

# Check if a step has been completed
# Usage: _step_done "step_id" && echo "already done"
_step_done() {
    local step_id="$1"
    [[ -f "${STATE_FILE}" ]] && grep -qx "${step_id}" "${STATE_FILE}" 2>/dev/null
}

# Mark a step as completed — atomic temp-file + mv to prevent corruption
_mark_step() {
    local step_id="$1"
    if ! _step_done "${step_id}"; then
        local tmp_state
        tmp_state="$(mktemp "${STATE_FILE}.XXXXXX")" || return 1
        if [[ -f "${STATE_FILE}" ]]; then
            cat "${STATE_FILE}" > "${tmp_state}"
        else
            echo "# STATE_VERSION=${STATE_VERSION}" > "${tmp_state}"
        fi
        echo "${step_id}" >> "${tmp_state}"
        sync "${tmp_state}" 2>/dev/null || true
        mv -f "${tmp_state}" "${STATE_FILE}"
    fi
}

# Remove a step from the completed list (for --repair) — atomic
_clear_step() {
    local step_id="$1"
    if [[ -f "${STATE_FILE}" ]]; then
        local tmp_state
        tmp_state="$(mktemp "${STATE_FILE}.XXXXXX")" || return 1
        sed "/^${step_id}$/d" "${STATE_FILE}" > "${tmp_state}"
        sync "${tmp_state}" 2>/dev/null || true
        mv -f "${tmp_state}" "${STATE_FILE}"
    fi
}

# Wipe all state (for --fresh)
_cleanup_state() {
    rm -f "${STATE_FILE}" "${CONFIG_FILE}"
    _init_state
}

################################################################################
# Config Persistence Functions — Atomic Writes
################################################################################

# Save a user config value — atomic temp-file + mv
# Usage: _save_config "key" "value"
_save_config() {
    local key="$1"
    local value="$2"
    local tmp_config
    tmp_config="$(mktemp "${CONFIG_FILE}.XXXXXX")" || return 1

    if [[ -f "${CONFIG_FILE}" ]]; then
        # Remove existing entry, then copy remaining
        sed "/^${key}=/d" "${CONFIG_FILE}" > "${tmp_config}"
    fi
    printf '%s=%q\n' "${key}" "${value}" >> "${tmp_config}"
    sync "${tmp_config}" 2>/dev/null || true
    mv -f "${tmp_config}" "${CONFIG_FILE}"
}

# Load a user config value
# Usage: result=$(_load_config "key")
_load_config() {
    local key="$1"
    if [[ -f "${CONFIG_FILE}" ]]; then
        (
            # shellcheck disable=1090
            source "${CONFIG_FILE}" 2>/dev/null
            printf '%s' "${!key}"
        )
    fi
}

################################################################################
# Safe Configuration Overlay — Preserves User Modifications
################################################################################

# Safely overlay a configuration file from a template.
#
# Behavior:
#   1. Target doesn't exist           → install from template
#   2. Target matches previous hash   → overwrite (no user edits)
#   3. Target has user modifications  → backup, then install new template
#
# Usage: _safe_overlay_config "source_template" "target_path"
_safe_overlay_config() {
    local source_template="$1"
    local target_path="$2"
    local hash_sidecar="${target_path}.aetherflow-sha256"

    if [[ ! -f "${source_template}" ]]; then
        echo "[ERROR] Template not found: ${source_template}" >&2
        return 1
    fi

    local new_hash
    new_hash="$(sha256sum "${source_template}" | awk '{print $1}')"

    if [[ ! -f "${target_path}" ]]; then
        # Case 1: Target doesn't exist — fresh install
        \cp -f "${source_template}" "${target_path}"
        echo "${new_hash}" > "${hash_sidecar}"
        return 0
    fi

    # Target exists — check if user has modified it
    if [[ -f "${hash_sidecar}" ]]; then
        local installed_hash
        installed_hash="$(cat "${hash_sidecar}" 2>/dev/null)"

        local current_hash
        current_hash="$(sha256sum "${target_path}" | awk '{print $1}')"

        if [[ "${current_hash}" == "${installed_hash}" ]]; then
            # Case 2: Unmodified by user — safe to overwrite
            \cp -f "${source_template}" "${target_path}"
            echo "${new_hash}" > "${hash_sidecar}"
            return 0
        fi
    fi

    # Case 3: User has modified the file — backup and replace
    local backup_path="${target_path}.user-backup.$(date +%Y%m%d-%H%M%S)"
    \cp -f "${target_path}" "${backup_path}"
    echo "[INFO] User-modified config backed up: ${backup_path}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Backed up user-modified: ${target_path} → ${backup_path}" >> "${INSTALL_LOG}"

    \cp -f "${source_template}" "${target_path}"
    echo "${new_hash}" > "${hash_sidecar}"
    return 0
}

################################################################################
# Step Runner — The Core Recovery Mechanism
################################################################################

# Run a step with checkpoint tracking
# Usage: _run_step "step_id" "Description" function_name [args...]
#
# Behavior:
#   1. If step already done AND not in REPAIR_STEPS → skip
#   2. Run the function
#   3. If success → mark done
#   4. If failure → log error, print resume instructions, exit
_run_step() {
    local step_id="$1"
    local description="$2"
    local func_name="$3"
    shift 3

    # Check if this step is being force-repaired
    local force_repair=false
    if [[ -n "${REPAIR_STEPS}" ]]; then
        for rs in ${REPAIR_STEPS}; do
            if [[ "${rs}" == "${step_id}" ]]; then
                force_repair=true
                _clear_step "${step_id}"
                break
            fi
        done
    fi

    # Skip if already completed (and not being repaired)
    if [[ "${force_repair}" == "false" ]] && _step_done "${step_id}"; then
        echo -e "[ ${bold:-}${green:-\033[32m}SKIP${normal:-\033[0m} ] ${description} (already completed)"
        return 0
    fi

    # Run the step
    echo -n "${description} ... "
    
    # Execute the function (in a subshell to capture failures)
    # We background + spinner for visual feedback, just like the original
    ${func_name} "$@" &
    local pid=$!

    # Use the spinner if it's available
    if type spinner &>/dev/null; then
        spinner ${pid}
    else
        wait ${pid}
    fi

    local exit_code=$?

    if [[ ${exit_code} -eq 0 ]]; then
        _mark_step "${step_id}"
        echo ""
        # Log success
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✓ ${step_id}: ${description}" >> "${INSTALL_LOG}"
        return 0
    else
        echo ""
        echo -e "[ ${bold:-}${red:-\033[31m}FAIL${normal:-\033[0m} ] ${description}"
        echo ""
        echo "═══════════════════════════════════════════════════════════════"
        echo "  Installation paused at step: ${step_id}"
        echo "  Error occurred in: ${func_name}"
        echo ""
        echo "  To resume from this point, simply re-run:"
        echo "    bash AetherFlow-Setup --resume"
        echo ""
        echo "  To retry just this step:"
        echo "    bash AetherFlow-Setup --repair ${step_id}"
        echo ""
        echo "  To see all steps and their status:"
        echo "    bash AetherFlow-Setup --list-steps"
        echo "═══════════════════════════════════════════════════════════════"
        # Log failure
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✗ ${step_id}: ${description} (exit code: ${exit_code})" >> "${INSTALL_LOG}"
        exit 1
    fi
}

# Run a step that should NOT be backgrounded (interactive prompts, etc.)
# Same as _run_step but runs in the foreground without spinner
_run_step_fg() {
    local step_id="$1"
    local description="$2"
    local func_name="$3"
    shift 3

    # Check if this step is being force-repaired
    local force_repair=false
    if [[ -n "${REPAIR_STEPS}" ]]; then
        for rs in ${REPAIR_STEPS}; do
            if [[ "${rs}" == "${step_id}" ]]; then
                force_repair=true
                _clear_step "${step_id}"
                break
            fi
        done
    fi

    # Skip if already completed
    if [[ "${force_repair}" == "false" ]] && _step_done "${step_id}"; then
        echo -e "[ ${bold:-}${green:-\033[32m}SKIP${normal:-\033[0m} ] ${description} (already completed)"
        return 0
    fi

    # Run the function directly (foreground, for interactive steps)
    ${func_name} "$@"
    local exit_code=$?

    if [[ ${exit_code} -eq 0 ]]; then
        _mark_step "${step_id}"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✓ ${step_id}: ${description}" >> "${INSTALL_LOG}"
        return 0
    else
        echo -e "[ ${bold:-}${red:-\033[31m}FAIL${normal:-\033[0m} ] ${description}"
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✗ ${step_id}: ${description} (exit code: ${exit_code})" >> "${INSTALL_LOG}"
        exit 1
    fi
}

################################################################################
# Detection & Reporting
################################################################################

# All known step IDs in order
ALL_STEPS=(
    bashrc intro checkroot logcheck checkkernel hostname locale
    ssdpblock askcontinue askpartition ask10g askrtorrent
    asktr askqb askdashtheme adduser askffmpeg askvsftpd denyhosts askbbr
    repos updates depends openssl syscommands skel lshell ffmpeg
    apachesudo xmlrpc libtorrent rtorrent
    transmission transmission_web transmission_apache
    qbittorrent qbittorrent_apache
    install_go install_node build_modern
    apacheconf fix_cert rconf autodl makedirs
    installftpd ftpdconfig quickconsole boot
    firewall harden_perms perms bbr bcm
)

# Detect previous install and print summary
_detect_previous_install() {
    if [[ ! -f "${STATE_FILE}" ]] || [[ ! -s "${STATE_FILE}" ]]; then
        echo "No previous installation state found. Starting fresh."
        return 1
    fi

    # Validate state version on resume
    _validate_state_version

    local total=${#ALL_STEPS[@]}
    local completed=0
    for step in "${ALL_STEPS[@]}"; do
        _step_done "${step}" && ((completed++))
    done

    echo ""
    echo "═══════════════════════════════════════════════════════════════"
    echo "  Previous installation detected!"
    echo "  Progress: ${completed}/${total} steps completed"
    echo ""
    echo "  The installer will automatically resume from where it"
    echo "  left off. Already-completed steps will be skipped."
    echo "═══════════════════════════════════════════════════════════════"
    echo ""
    return 0
}

# List all steps with completion status
_list_steps() {
    _init_state
    echo ""
    echo "AetherFlow Installation Steps"
    echo "════════════════════════════════════════"
    for step in "${ALL_STEPS[@]}"; do
        if _step_done "${step}"; then
            echo -e "  [${green:-\033[32m}✓${normal:-\033[0m}] ${step}"
        else
            echo -e "  [ ] ${step}"
        fi
    done
    echo "════════════════════════════════════════"
    echo ""
}
