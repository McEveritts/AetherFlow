#!/bin/bash

set -euo pipefail

if [[ "$#" -lt 3 ]]; then
    echo "Usage: bash scripts/create-plugin-sdk.sh <plugin-id> <plugin-name> <target-dir>"
    exit 1
fi

PLUGIN_ID="$1"
PLUGIN_NAME="$2"
TARGET_DIR="$3"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
TEMPLATE_DIR="${REPO_ROOT}/plugins/sdk-template"

if [[ ! -d "${TEMPLATE_DIR}" ]]; then
    echo "Template directory not found: ${TEMPLATE_DIR}"
    exit 1
fi

if [[ -e "${TARGET_DIR}" ]]; then
    echo "Target already exists: ${TARGET_DIR}"
    exit 1
fi

mkdir -p "${TARGET_DIR}"
cp -R "${TEMPLATE_DIR}/." "${TARGET_DIR}/"

ESCAPED_PLUGIN_ID="$(printf '%s' "${PLUGIN_ID}" | sed 's/[\/&]/\\&/g')"
ESCAPED_PLUGIN_NAME="$(printf '%s' "${PLUGIN_NAME}" | sed 's/[\/&]/\\&/g')"

while IFS= read -r -d '' file; do
    sed -i "s/{{PLUGIN_ID}}/${ESCAPED_PLUGIN_ID}/g; s/{{PLUGIN_NAME}}/${ESCAPED_PLUGIN_NAME}/g" "${file}"
done < <(find "${TARGET_DIR}" -type f -print0)

echo "Plugin scaffold created at ${TARGET_DIR}"
