#!/usr/bin/env bash
set -euo pipefail

# Reference stop hook for {{PLUGIN_NAME}} ({{PLUGIN_ID}}).
# NOTE: backend-rs (v4.0.0) does not automatically invoke plugin lifecycle_hooks yet.

echo "Stopping standalone plugin {{PLUGIN_ID}} (managed externally by systemd/operator)"
