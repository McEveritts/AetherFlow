#!/usr/bin/env bash
set -euo pipefail

# Managed teardown hook (`lifecycle_hooks.on_stop`) for {{PLUGIN_NAME}} ({{PLUGIN_ID}}).
# Invoked by backend-rs (`af-api`) during plugin shutdown or manually by an operator.

echo "Running on_stop cleanup hook for plugin {{PLUGIN_ID}}"
