#!/usr/bin/env bash
# Bash wrapper for AetherFlow v3.1.7 E2E Test Suite
set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${DIR}/.." && pwd)"

cd "${ROOT_DIR}"

if command -v python3 >/dev/null 2>&1; then
    exec python3 tests/run_e2e.py "$@"
elif command -v python >/dev/null 2>&1; then
    exec python tests/run_e2e.py "$@"
else
    echo "Error: Python 3 is required to run the E2E test suite." >&2
    exit 1
fi
