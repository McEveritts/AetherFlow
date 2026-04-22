#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

failures=0

run_check() {
    local title="$1"
    local pattern="$2"
    local exclude_regex="${3:-^$}"
    local output

    echo "==> ${title}"

    output="$(git grep -nI -E "${pattern}" -- . || true)"
    if [[ -n "${exclude_regex}" ]]; then
        output="$(printf '%s\n' "${output}" | grep -vE "${exclude_regex}" || true)"
    fi
    output="$(printf '%s\n' "${output}" | sed '/^$/d')"

    if [[ -n "${output}" ]]; then
        printf '%s\n\n' "${output}"
        failures=1
        return
    fi

    echo "No matches found."
    echo
}

run_check \
    "Known token and API key formats" \
    '(ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,}|sk-ant-[A-Za-z0-9_-]{16,}|AIza[0-9A-Za-z_-]{20,}|AKIA[0-9A-Z]{16})' \
    '^(backend/.*_test\.go:|frontend/tests/:|\.github/workflows/(ci|security)\.yml:)'

run_check \
    "Hardcoded credential-style assignments in executable or config files" \
    '\b(PASSWORD|PASSWD|API_KEY|APIKEY|TOKEN|SECRET|USERNAME|HOSTNAME)\b[[:space:]]*[:=][[:space:]]*["'\''][^"'\'']{3,}["'\'']' \
    '^(backend/.*_test\.go:|frontend/tests/:|\.github/workflows/(ci|security)\.yml:|\.env\.example:)'

run_check \
    "Inline SSH password usage" \
    'client\.connect\([^)]*password[[:space:]]*=[[:space:]]*["'\''][^"'\'']+["'\'']' \
    '^backend/.*_test\.go:'

run_check \
    "Literal sudo password piping" \
    'echo[[:space:]]+["'\'']?[^"'\'']{3,}["'\'']?[[:space:]]*\|[[:space:]]*sudo[[:space:]]+-S'

run_check \
    "Personal workstation path residue" \
    '([A-Za-z]:[/\\]+Users[/\\]+[^/\\]+[/\\]+|/Users/[^/]+/|OneDrive[/\\])' \
    '^scripts/check_privacy_hygiene\.sh:'

if [[ "${failures}" -ne 0 ]]; then
    echo "Privacy hygiene scan failed."
    exit 1
fi

echo "Privacy hygiene scan passed."
