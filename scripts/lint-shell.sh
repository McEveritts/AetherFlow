#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGETS=("${ROOT_DIR}/packages/package" "${ROOT_DIR}/packages/system")

if ! command -v shellcheck >/dev/null 2>&1; then
    echo "shellcheck is required but not installed." >&2
    echo "Install shellcheck, then re-run: ${BASH_SOURCE[0]}" >&2
    exit 127
fi

readarray -t files < <(
    find "${TARGETS[@]}" -type f -print0 |
        while IFS= read -r -d '' file; do
            if head -n 1 "$file" | grep -Eq '^#!.*/(env[[:space:]]+)?(ba)?sh'; then
                printf '%s\n' "$file"
            fi
        done | sort
)

if [[ ${#files[@]} -eq 0 ]]; then
    echo "No shell scripts found under packages/package or packages/system."
    exit 0
fi

echo "Linting ${#files[@]} script(s) with shellcheck..."
shellcheck --external-sources --severity=style --shell=bash -o all "${files[@]}"

echo "Lint completed successfully."
