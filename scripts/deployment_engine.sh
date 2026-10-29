#!/bin/bash
###############################################################################
# AetherFlow Deployment Engine Wrapper
#
# Forwards legacy invocations to the unified pull-based atomic Release Manager
# at deploy/release-manager.sh so all update paths share a single engine.
###############################################################################
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHANNEL="${1:-stable}"

exec /bin/bash "${SCRIPT_DIR}/../deploy/release-manager.sh" deploy --channel "${CHANNEL}"
