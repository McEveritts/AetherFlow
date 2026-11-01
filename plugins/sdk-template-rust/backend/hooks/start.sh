#!/usr/bin/env bash
set -euo pipefail

# Reference start hook for {{PLUGIN_NAME}} ({{PLUGIN_ID}}).
# NOTE: backend-rs (v4.0.0) does not automatically invoke plugin lifecycle_hooks yet.
# Run this script via a dedicated systemd service or operator supervisor when testing standalone.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${BACKEND_DIR}"
exec cargo run --release
