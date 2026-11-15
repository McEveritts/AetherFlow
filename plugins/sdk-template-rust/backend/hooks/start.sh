#!/usr/bin/env bash
set -euo pipefail

# Fallback start hook for {{PLUGIN_NAME}} ({{PLUGIN_ID}}).
# Invoked automatically by backend-rs when no pre-built binary is discovered directly,
# or manually by an operator / systemd unit during standalone testing.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PLUGIN_ROOT="$(cd "${BACKEND_DIR}/.." && pwd)"
BIN_NAME="aetherflow-plugin-{{PLUGIN_ID}}"

if [[ -x "${PLUGIN_ROOT}/bin/${BIN_NAME}" ]]; then
    exec "${PLUGIN_ROOT}/bin/${BIN_NAME}"
elif [[ -x "${BACKEND_DIR}/target/release/${BIN_NAME}" ]]; then
    exec "${BACKEND_DIR}/target/release/${BIN_NAME}"
elif [[ -x "${BACKEND_DIR}/target/debug/${BIN_NAME}" ]]; then
    exec "${BACKEND_DIR}/target/debug/${BIN_NAME}"
fi

echo "Error: pre-built plugin binary '${BIN_NAME}' not found under '${PLUGIN_ROOT}/bin/' or '${BACKEND_DIR}/target/{release,debug}/'. Build it first with 'cargo build --release --manifest-path ${BACKEND_DIR}/Cargo.toml'." >&2
exit 1
