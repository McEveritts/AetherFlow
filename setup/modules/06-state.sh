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
LOCKFILE="${LOCKFILE:-/run/aetherflow-setup.lock}"

# State file format version. Bump this when step IDs change incompatibly.
STATE_VERSION="2"

# REPAIR_STEPS is set by --repair flag parsing in the main script
# It is a space-separated list of step IDs to force re-run
REPAIR_STEPS="${REPAIR_STEPS:-}"
FRESH_INSTALL="${FRESH_INSTALL:-false}"

################################################################################
# Lockfile — Prevents concurrent installer instances
################################################################################

# Dedicated lockfile FD, owning shell PID, and captured path for kernel-enforced flock locking.
AF_LOCK_FD="${AF_LOCK_FD:-}"
AF_LOCK_OWNER_PID="${AF_LOCK_OWNER_PID:-}"
AF_LOCK_PATH="${AF_LOCK_PATH:-}"

# Acquire an exclusive kernel-enforced flock on LOCKFILE.
# Eliminates check-then-write and PID-reuse races on stale lock reclamation.
_acquire_lock() {
    if [[ "${LOCKFILE}" == /var/run/* && -L /var/run && "$(stat -c '%u' /var/run 2>/dev/null)" == "0" ]]; then
        local var_run_target
        var_run_target="$(readlink /var/run 2>/dev/null || true)"
        if [[ ( "${var_run_target}" == "/run" || "${var_run_target}" == "../run" ) && ! -L /run && -d /run && "$(stat -c '%u' /run 2>/dev/null)" == "0" ]]; then
            LOCKFILE="/run/${LOCKFILE#/var/run/}"
        fi
    fi
    if [[ -z "${LOCKFILE}" || "${LOCKFILE}" == ".." || "${LOCKFILE}" == "../"* || "${LOCKFILE}" == *"/../"* || "${LOCKFILE}" == *"/.." ]]; then
        echo "[ERROR] Refusing unsafe lockfile path: ${LOCKFILE}" >&2
        exit 1
    fi
    local lockdir check_dir parent_dir
    lockdir="$(dirname "${LOCKFILE}")"
    check_dir="${lockdir}"
    while [[ -n "${check_dir}" && "${check_dir}" != "/" && "${check_dir}" != "." ]]; do
        if [[ -L "${check_dir}" ]]; then
            echo "[ERROR] Refusing symlinked lockfile directory: ${check_dir}" >&2
            exit 1
        fi
        parent_dir="$(dirname "${check_dir}")"
        if [[ "${parent_dir}" == "${check_dir}" ]]; then
            break
        fi
        check_dir="${parent_dir}"
    done
    mkdir -p "${lockdir}" 2>/dev/null || {
        echo "[ERROR] Failed to create lockfile directory: ${lockdir}" >&2
        exit 1
    }
    if [[ -L "${lockdir}" || ! -d "${lockdir}" ]]; then
        echo "[ERROR] Refusing symlinked lockfile directory: ${lockdir}" >&2
        exit 1
    fi
    if [[ -L "${LOCKFILE}" || ( -e "${LOCKFILE}" && ! -f "${LOCKFILE}" ) ]]; then
        echo "[ERROR] Refusing unsafe lockfile path: ${LOCKFILE}" >&2
        exit 1
    fi
    if ! command -v flock >/dev/null 2>&1; then
        echo "[ERROR] Required 'flock' utility not found; refusing unlocked execution." >&2
        exit 1
    fi

    local my_pid="${BASHPID:-$$}"
    if [[ -n "${AF_LOCK_FD:-}" && "${AF_LOCK_OWNER_PID:-}" == "${my_pid}" ]]; then
        return 0
    fi

    local attempt fd existing_pid fd_id path_id prev_umask
    for attempt in 1 2 3; do
        if [[ -L "${LOCKFILE}" || ( -e "${LOCKFILE}" && ! -f "${LOCKFILE}" ) ]]; then
            echo "[ERROR] Refusing unsafe lockfile path: ${LOCKFILE}" >&2
            exit 1
        fi

        # Open without truncation (<>) under umask 0077 so an existing holder's
        # PID metadata is never clobbered prior to acquiring the kernel lock.
        prev_umask="$(umask)"
        umask 0077
        if ! exec {fd}<>"${LOCKFILE}"; then
            umask "${prev_umask}"
            echo "[ERROR] Failed to open lockfile: ${LOCKFILE}" >&2
            exit 1
        fi
        umask "${prev_umask}"

        if ! flock -n "${fd}"; then
            existing_pid="$(head -c 64 <&"${fd}" 2>/dev/null | tr -dc '0-9' || true)"
            exec {fd}>&- 2>/dev/null || true
            echo ""
            echo "═══════════════════════════════════════════════════════════════"
            echo "  ERROR: Another instance of AetherFlow Setup is running!"
            echo ""
            echo "  PID: ${existing_pid:-unknown}"
            echo "  Lockfile: ${LOCKFILE}"
            echo ""
            echo "  Wait for the active installer to finish before re-running."
            echo "═══════════════════════════════════════════════════════════════"
            echo ""
            exit 1
        fi

        # Verify the locked descriptor is a regular file and still matches the live
        # LOCKFILE inode (guards against concurrent unlink/replace before flock).
        fd_id="$(stat -L -c '%d:%i' "/proc/${my_pid}/fd/${fd}" 2>/dev/null || true)"
        path_id="$(stat -c '%d:%i' "${LOCKFILE}" 2>/dev/null || true)"
        if [[ -f "/proc/${my_pid}/fd/${fd}" && -n "${fd_id}" && "${fd_id}" == "${path_id}" ]]; then
            AF_LOCK_FD="${fd}"
            AF_LOCK_OWNER_PID="${my_pid}"
            AF_LOCK_PATH="${LOCKFILE}"
            # Update PID metadata directly via the locked FD path (noclobber-safe,
            # immune to LOCKFILE path swaps while holding the kernel flock).
            printf '%s\n' "${my_pid}" >| "/proc/${my_pid}/fd/${fd}" 2>/dev/null || true
            return 0
        fi

        flock -u "${fd}" 2>/dev/null || true
        exec {fd}>&- 2>/dev/null || true
    done

    echo "[ERROR] Failed to acquire lockfile: ${LOCKFILE}" >&2
    exit 1
}

# Release the kernel flock held by this shell process and clear PID metadata
# without unlinking the lockfile inode (avoids flock unlink races).
_release_lock() {
    local my_pid="${BASHPID:-$$}"
    if [[ -n "${AF_LOCK_FD:-}" && "${AF_LOCK_OWNER_PID:-}" == "${my_pid}" ]]; then
        local lock_fd="${AF_LOCK_FD}"
        local lock_path="${AF_LOCK_PATH:-}"
        local fd_id="" path_id=""
        fd_id="$(stat -L -c '%d:%i' "/proc/${my_pid}/fd/${lock_fd}" 2>/dev/null || true)"
        if [[ -n "${lock_path}" && -f "${lock_path}" && ! -L "${lock_path}" ]]; then
            path_id="$(stat -c '%d:%i' "${lock_path}" 2>/dev/null || true)"
        fi
        if [[ -n "${fd_id}" && "${fd_id}" == "${path_id}" ]]; then
            : >| "/proc/${my_pid}/fd/${lock_fd}" 2>/dev/null || true
        fi
        flock -u "${lock_fd}" 2>/dev/null || true
        exec {lock_fd}>&- 2>/dev/null || true
        AF_LOCK_FD=""
        AF_LOCK_OWNER_PID=""
        AF_LOCK_PATH=""
    fi
}

# Release installer scratch directory only when owned/allocated under /var/tmp/aetherflow-setup.*
_af_cleanup_setup_scratch() {
    local dir="${AF_SETUP_SCRATCH_DIR:-}"
    if [[ -n "${dir}" && "${dir}" == /var/tmp/aetherflow-setup.* && "${dir}" != *".."* && -d "${dir}" && ! -L "${dir}" ]]; then
        rm -rf -- "${dir}"
    fi
}

_af_cleanup_on_exit() {
    local rc=$?
    _release_lock
    _af_cleanup_setup_scratch
    return "${rc}"
}

_af_cleanup_on_signal() {
    local sig="$1"
    _release_lock
    _af_cleanup_setup_scratch
    trap - "${sig}" EXIT
    kill -s "${sig}" "${BASHPID:-$$}" 2>/dev/null || exit 1
}

# Register cleanup traps so the kernel flock and installer scratch dir are always released.
_setup_lock_trap() {
    trap '_af_cleanup_on_exit' EXIT
    trap '_af_cleanup_on_signal INT' INT
    trap '_af_cleanup_on_signal TERM' TERM
    trap '_af_cleanup_on_signal HUP' HUP
}

################################################################################
# State File Functions — Atomic & Versioned
################################################################################

# Ensure /install directory exists and state file has a version header
_init_state() {
    local state_dir
    state_dir="$(dirname "${STATE_FILE}")"
    if [[ "${state_dir}" == "/install" && "${EUID:-$(id -u)}" -eq 0 ]]; then
        local install_group="root"
        if getent group aetherflow >/dev/null 2>&1; then
            install_group="aetherflow"
        fi
        install -d -m 0750 -o root -g "${install_group}" /install
    else
        mkdir -p "${state_dir}"
    fi
    touch "${STATE_FILE}" 2>/dev/null
    touch "${CONFIG_FILE}" 2>/dev/null
    chmod 0600 "${CONFIG_FILE}" 2>/dev/null || true

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
    tmp_config="$(umask 0077; mktemp "${CONFIG_FILE}.XXXXXX")" || return 1

    if [[ -f "${CONFIG_FILE}" ]]; then
        # Remove existing entry, then copy remaining
        sed "/^${key}=/d" "${CONFIG_FILE}" > "${tmp_config}"
    fi
    printf '%s=%q\n' "${key}" "${value}" >> "${tmp_config}"
    chmod 0600 "${tmp_config}" 2>/dev/null || true
    sync "${tmp_config}" 2>/dev/null || true
    mv -f "${tmp_config}" "${CONFIG_FILE}"
}

# Remove sensitive or transient keys from CONFIG_FILE atomically
# Usage: _scrub_config_keys "passwd" "ha1pass"
_scrub_config_keys() {
    [[ -f "${CONFIG_FILE}" && $# -gt 0 ]] || return 0
    local tmp_config
    tmp_config="$(umask 0077; mktemp "${CONFIG_FILE}.XXXXXX")" || return 1
    python3 - "${CONFIG_FILE}" "${tmp_config}" "$@" <<'PY'
import os, re, sys

src_path, dst_path, *drop_keys = sys.argv[1:]
drop_set = set(drop_keys)
key_re = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=")
kept = []
with open(src_path, "r", encoding="utf-8", errors="replace") as fh:
    for line in fh:
        m = key_re.match(line)
        if m and m.group(1) in drop_set:
            continue
        kept.append(line)
with open(dst_path, "w", encoding="utf-8") as fh:
    os.fchmod(fh.fileno(), 0o600)
    fh.writelines(kept)
    fh.flush()
    os.fsync(fh.fileno())
PY
    if [[ $? -ne 0 ]]; then
        rm -f "${tmp_config}"
        return 1
    fi
    mv -f "${tmp_config}" "${CONFIG_FILE}"
}

# Load a user config value safely with Python key-value parsing (never source CONFIG_FILE)
# Usage: result=$(_load_config "key")
_load_config() {
    local key="$1"
    [[ -f "${CONFIG_FILE}" ]] || return 0
    python3 - "${CONFIG_FILE}" "${key}" <<'PY'
import codecs, os, re, shlex, sys

cfg_path, target_key = sys.argv[1], sys.argv[2]
if not os.path.isfile(cfg_path) or os.path.islink(cfg_path):
    sys.exit(0)

key_re = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")

def unquote(raw: str) -> str:
    raw = raw.rstrip("\r\n")
    if not raw or raw in ('""', "''"):
        return ""
    if raw.startswith("$'") and raw.endswith("'") and len(raw) >= 3:
        try:
            return codecs.decode(raw[2:-1], "unicode_escape")
        except Exception:
            return raw[2:-1]
    try:
        parts = shlex.split(raw, posix=True)
        if not parts:
            return ""
        if len(parts) == 1:
            return parts[0]
        return " ".join(parts)
    except ValueError:
        return raw.strip("\"'")

val = ""
with open(cfg_path, "r", encoding="utf-8", errors="replace") as fh:
    for line in fh:
        s = line.lstrip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("export "):
            s = s[7:].lstrip()
        m = key_re.match(s)
        if m and m.group(1) == target_key:
            val = unquote(m.group(2))

sys.stdout.write(val)
PY
}

# Safely populate shell variables from CONFIG_FILE without sourcing arbitrary shell code
_load_config_into_vars() {
    [[ -f "${CONFIG_FILE}" ]] || return 0
    local k v
    while IFS= read -r -d '' k && IFS= read -r -d '' v; do
        if [[ "${k}" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
            printf -v "${k}" '%s' "${v}"
        fi
    done < <(python3 - "${CONFIG_FILE}" <<'PY'
import codecs, os, re, shlex, sys

cfg_path = sys.argv[1]
if not os.path.isfile(cfg_path) or os.path.islink(cfg_path):
    sys.exit(0)

key_re = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")

def unquote(raw: str) -> str:
    raw = raw.rstrip("\r\n")
    if not raw or raw in ('""', "''"):
        return ""
    if raw.startswith("$'") and raw.endswith("'") and len(raw) >= 3:
        try:
            return codecs.decode(raw[2:-1], "unicode_escape")
        except Exception:
            return raw[2:-1]
    try:
        parts = shlex.split(raw, posix=True)
        if not parts:
            return ""
        if len(parts) == 1:
            return parts[0]
        return " ".join(parts)
    except ValueError:
        return raw.strip("\"'")

parsed = {}
with open(cfg_path, "r", encoding="utf-8", errors="replace") as fh:
    for line in fh:
        s = line.lstrip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("export "):
            s = s[7:].lstrip()
        m = key_re.match(s)
        if m:
            parsed[m.group(1)] = unquote(m.group(2))

for k, v in parsed.items():
    sys.stdout.write(f"{k}\0{v}\0")
PY
    )
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
    
    # Execute the function in a background subshell with the parent's lock FD
    # closed so background children can never pin the setup flock past exit.
    (
        if [[ -n "${AF_LOCK_FD:-}" ]]; then
            local _child_lock_fd="${AF_LOCK_FD}"
            exec {_child_lock_fd}>&- 2>/dev/null || true
            AF_LOCK_FD=""
            AF_LOCK_OWNER_PID=""
            AF_LOCK_PATH=""
        fi
        "${func_name}" "$@"
    ) &
    local pid=$!

    # Use the spinner if it's available
    if type spinner &>/dev/null; then
        spinner "${pid}"
    else
        wait "${pid}"
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
    "${func_name}" "$@"
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
    ssdpblock askcontinue askpartition ask10g
    adduser askffmpeg askvsftpd denyhosts askbbr
    repos updates depends syscommands skel ffmpeg
    apachesudo
    build_modern
    apacheconf fix_cert makedirs
    installftpd ftpdconfig boot
    firewall harden_perms perms bbr
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
        if _step_done "${step}"; then
            completed=$((completed + 1))
        fi
    done

    if [[ ${completed} -eq 0 ]]; then
        echo "No previous installation state found. Starting fresh."
        return 1
    fi

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
