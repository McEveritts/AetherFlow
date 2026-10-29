#!/bin/bash
# /opt/AetherFlow/packages/common.sh
# Shared variables and functions for AetherFlow scripts/installers.

set -euo pipefail

export LOGFILE="${LOGFILE:-/var/log/aetherflow/install.log}"
export LOCK_DIR="${LOCK_DIR:-/install}"

mkdir -p "$LOCK_DIR" "$(dirname "$LOGFILE")"

timestamp() {
    date "+%Y-%m-%d %H:%M:%S"
}

log() {
    printf '[%s] %s\n' "$(timestamp)" "$*" >>"$LOGFILE"
}

log_info() {
    log "[INFO] $*"
}

log_warn() {
    log "[WARN] $*"
}

log_error() {
    log "[ERROR] $*"
}

print_info() {
    printf '[INFO] %s\n' "$*"
    log_info "$*"
}

print_warn() {
    printf '[WARN] %s\n' "$*" >&2
    log_warn "$*"
}

print_error() {
    printf '[ERROR] %s\n' "$*" >&2
    log_error "$*"
}

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        print_error "This command must be run as root."
        exit 1
    fi
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

lock_path() {
    local package_name="$1"
    printf '%s/.%s.lock\n' "$LOCK_DIR" "$package_name"
}

has_lock() {
    local package_name="$1"
    [[ -f "$(lock_path "$package_name")" ]]
}

write_lock() {
    local package_name="$1"
    touch "$(lock_path "$package_name")"
}

remove_lock() {
    local package_name="$1"
    rm -f "$(lock_path "$package_name")"
}

backup_file_once() {
    local target="$1"
    if [[ -f "$target" && ! -f "${target}.bak-af" ]]; then
        cp -a "$target" "${target}.bak-af"
    fi
}

rollback_file() {
    local target="$1"
    if [[ -f "${target}.bak-af" ]]; then
        mv -f "${target}.bak-af" "$target"
    fi
}

cleanup_backup_file() {
    local target="$1"
    rm -f "${target}.bak-af"
}

fetch_and_run() {
    local url="$1"
    local checksum="$2"
    shift 2

    local tmp_script
    tmp_script=$(mktemp /tmp/aetherflow-install-XXXXXX.sh)
    
    log_info "Downloading install script from $url"
    if ! curl -fsSL -o "$tmp_script" "$url"; then
        print_error "Failed to download $url"
        rm -f "$tmp_script"
        return 1
    fi

    if [[ -n "$checksum" && "$checksum" != "SKIP" ]]; then
        local computed_hash
        computed_hash=$(sha256sum "$tmp_script" | awk '{print $1}')
        if [[ "$computed_hash" != "$checksum" ]]; then
            print_error "Checksum validation failed for $url! Expected: $checksum, Got: $computed_hash"
            rm -f "$tmp_script"
            return 1
        fi
        log_info "Checksum validation passed."
    else
        log_warn "WARNING: Checksum validation skipped for $url (Hash pinned as SKIP or empty)."
    fi

    # Ensure executable and run
    chmod +x "$tmp_script"
    if ! "$tmp_script" "$@"; then
        print_error "Script execution failed for $url"
        rm -f "$tmp_script"
        return 1
    fi

    rm -f "$tmp_script"
    return 0
}

report_progress() {
    local pct="${1:-0}"
    local msg="${2:-}"
    printf '[PROGRESS:%d] %s\n' "$pct" "$msg"
    log_info "[PROGRESS:$pct] $msg"
}

ensure_node() {
    local want_major="${1:-20}"
    local have_major=0
    if command_exists node; then
        have_major=$(node -v 2>/dev/null | sed 's/^v//' | cut -d. -f1 || echo 0)
    fi
    if [[ "${have_major:-0}" -lt "$want_major" ]]; then
        fetch_and_run "https://deb.nodesource.com/setup_${want_major}.x" "SKIP"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nodejs >> "$LOGFILE" 2>&1
    fi
    if [[ ! -x /usr/bin/node && -x /usr/local/bin/node ]]; then
        ln -sf /usr/local/bin/node /usr/bin/node
    fi
    if [[ ! -x /usr/bin/npm && -x /usr/local/bin/npm ]]; then
        ln -sf /usr/local/bin/npm /usr/bin/npm
    fi
    if [[ ! -x /usr/bin/npx && -x /usr/local/bin/npx ]]; then
        ln -sf /usr/local/bin/npx /usr/bin/npx
    fi
}

purge_systemd_unit() {
    local unit="$1"
    case "$unit" in
        *.service|*.timer|*.socket) ;;
        *) unit="${unit}.service" ;;
    esac
    systemctl stop "$unit" >/dev/null 2>&1 || true
    systemctl disable "$unit" >/dev/null 2>&1 || true
    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/${unit}"
    rm -rf "/etc/systemd/system/${unit}.d"
}

purge_system_user() {
    local username="$1"
    if [[ -n "$username" && "$username" != "root" && "$username" != "www-data" ]]; then
        userdel -r "$username" >/dev/null 2>&1 || userdel "$username" >/dev/null 2>&1 || true
        groupdel "$username" >/dev/null 2>&1 || true
        rm -rf "/home/${username}"
    fi
}

