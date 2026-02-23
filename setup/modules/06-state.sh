#!/bin/bash
# Module: 06-state.sh
# Installer State Tracking & Recovery Engine
#
# Provides checkpoint/resume capability so failed installs can be
# resumed without a full OS reinstall.

STATE_FILE="${STATE_FILE:-/install/.aetherflow.state}"
CONFIG_FILE="${CONFIG_FILE:-/install/.aetherflow.conf}"
INSTALL_LOG="${INSTALL_LOG:-/install/.aetherflow.install.log}"

# REPAIR_STEPS is set by --repair flag parsing in the main script
# It is a space-separated list of step IDs to force re-run
REPAIR_STEPS="${REPAIR_STEPS:-}"
FRESH_INSTALL="${FRESH_INSTALL:-false}"

################################################################################
# State File Functions
################################################################################

# Ensure /install directory exists
_init_state() {
    mkdir -p "$(dirname "${STATE_FILE}")"
    touch "${STATE_FILE}" 2>/dev/null
    touch "${CONFIG_FILE}" 2>/dev/null
}

# Check if a step has been completed
# Usage: _step_done "step_id" && echo "already done"
_step_done() {
    local step_id="$1"
    [[ -f "${STATE_FILE}" ]] && grep -qx "${step_id}" "${STATE_FILE}" 2>/dev/null
}

# Mark a step as completed
_mark_step() {
    local step_id="$1"
    if ! _step_done "${step_id}"; then
        echo "${step_id}" >> "${STATE_FILE}"
    fi
}

# Remove a step from the completed list (for --repair)
_clear_step() {
    local step_id="$1"
    if [[ -f "${STATE_FILE}" ]]; then
        sed -i "/^${step_id}$/d" "${STATE_FILE}"
    fi
}

# Wipe all state (for --fresh)
_cleanup_state() {
    rm -f "${STATE_FILE}" "${CONFIG_FILE}"
    _init_state
}

################################################################################
# Config Persistence Functions
################################################################################

# Save a user config value
# Usage: _save_config "key" "value"
_save_config() {
    local key="$1"
    local value="$2"
    # Remove existing entry if present, then append
    if [[ -f "${CONFIG_FILE}" ]]; then
        sed -i "/^${key}=/d" "${CONFIG_FILE}"
    fi
    echo "${key}=${value}" >> "${CONFIG_FILE}"
}

# Load a user config value
# Usage: result=$(_load_config "key")
_load_config() {
    local key="$1"
    if [[ -f "${CONFIG_FILE}" ]]; then
        grep "^${key}=" "${CONFIG_FILE}" 2>/dev/null | head -1 | cut -d'=' -f2-
    fi
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
    installftpd ftpdconfig quickconsole boot perms bbr bcm
)

# Detect previous install and print summary
_detect_previous_install() {
    if [[ ! -f "${STATE_FILE}" ]] || [[ ! -s "${STATE_FILE}" ]]; then
        echo "No previous installation state found. Starting fresh."
        return 1
    fi

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
