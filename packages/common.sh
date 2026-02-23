#!/bin/bash
# /opt/AetherFlow/packages/common.sh
# Shared variables and functions for AetherFlow install scripts

export AETHERFLOW_USER="mceveritts" 
export LOGFILE="/var/log/aetherflow/install.log"
export LOCK_DIR="/install"

mkdir -p "$LOCK_DIR" "$(dirname "$LOGFILE")"

log() { 
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOGFILE"
}
