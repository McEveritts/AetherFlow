#!/bin/bash
# /opt/AetherFlow/packages/common.sh
# Shared variables and modular helper loader for AetherFlow scripts/installers.

set -euo pipefail
umask 077

if [[ "${_AF_COMMON_SH_LOADED:-0}" == "1" ]]; then
    return 0 2>/dev/null || exit 0
fi

export PATH="/usr/local/nodejs/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
if [[ -z "${LOGFILE:-}" ]]; then
    case "${0##*/}" in
        installpackage-*) export LOGFILE="/var/log/aetherflow/install-${0##*installpackage-}.log" ;;
        removepackage-*)  export LOGFILE="/var/log/aetherflow/remove-${0##*removepackage-}.log" ;;
        *)                export LOGFILE="/var/log/aetherflow/install.log" ;;
    esac
else
    export LOGFILE
fi
export LOCK_DIR="${LOCK_DIR:-/install}"
export AF_REQUIRE_DOWNLOAD_SHA256="${AF_REQUIRE_DOWNLOAD_SHA256:-1}"
export AF_CERTBOT_SYNC_BIN="${AF_CERTBOT_SYNC_BIN:-/usr/local/bin/af-certbot-sync}"
declare -ag AF_PENDING_VERSION_PATHS=() AF_PENDING_VERSION_VALUES=() AF_APT_REINSTALL_PACKAGES=() AF_APT_TRANSACTION_PACKAGES=() AF_APT_LOCKSTEP_PACKAGES=()
AF_APT_PRIMARY_PACKAGE=""
AF_APT_TARGET_VERSION=""
AF_APT_LOCAL_DEB=false

_AF_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_AF_COMMON_LIB_DIR=""
for _af_lib_candidate in \
    "${_AF_COMMON_DIR}/lib" \
    "${AF_COMMON_LIB_DIR:-}" \
    "${CARGO_MANIFEST_DIR:+${CARGO_MANIFEST_DIR}/../../../packages/lib}" \
    /opt/AetherFlow/current/packages/lib \
    /opt/AetherFlow/packages/lib \
    /usr/local/bin/AetherFlow/lib; do
    if [[ -n "$_af_lib_candidate" && -d "$_af_lib_candidate" && -f "${_af_lib_candidate}/logging_archives.sh" ]]; then
        _AF_COMMON_LIB_DIR="$_af_lib_candidate"
        break
    fi
done
unset _af_lib_candidate
if [[ -z "$_AF_COMMON_LIB_DIR" ]]; then
    printf 'Unable to locate AetherFlow packages/lib directory (searched %s/lib)\n' "$_AF_COMMON_DIR" >&2
    return 1 2>/dev/null || exit 1
fi

# shellcheck source=lib/logging_archives.sh
source "${_AF_COMMON_LIB_DIR}/logging_archives.sh"
if [[ "${AF_SKIP_COMMON_INIT:-0}" != "1" ]]; then
    af_ensure_lock_dir "$LOCK_DIR"
    af_prepare_logfile_path "$LOGFILE"
fi

for _af_lib_module in \
    versions_apt.sh \
    state_downloads.sh \
    config_database.sh \
    apache_dns_locks.sh \
    redaction_receipts.sh \
    systemd_credentials.sh; do
    # shellcheck disable=SC1090
    source "${_AF_COMMON_LIB_DIR}/${_af_lib_module}"
done
unset _af_lib_module

load_master_credentials
_AF_COMMON_SH_LOADED=1
