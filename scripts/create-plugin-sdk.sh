#!/bin/bash

set -euo pipefail

if [[ "$#" -lt 3 ]]; then
    echo "Usage: bash scripts/create-plugin-sdk.sh <plugin-id> <plugin-name> <target-dir> [rust]" >&2
    exit 1
fi

PLUGIN_ID="$1"
PLUGIN_NAME="$2"
TARGET_DIR="$3"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
SDK="${4:-rust}"
case "${SDK}" in
    rust) TEMPLATE_DIR="${REPO_ROOT}/plugins/sdk-template-rust" ;;
    *)
        echo "Unsupported SDK '${SDK}' (only 'rust' is supported; legacy Go plugin SDK has been removed)" >&2
        exit 1
        ;;
esac

if [[ ! "${PLUGIN_ID}" =~ ^[a-z0-9][a-z0-9_-]{1,62}$ ]]; then
    echo "Invalid plugin-id '${PLUGIN_ID}': must match ^[a-z0-9][a-z0-9_-]{1,62}$" >&2
    exit 1
fi

UNSAFE_NAME_RE='["'\''\\/<>{}]'
if [[ -z "${PLUGIN_NAME}" || "${PLUGIN_NAME}" =~ ${UNSAFE_NAME_RE} || "${PLUGIN_NAME}" == *$'\n'* || "${PLUGIN_NAME}" == *$'\r'* ]]; then
    echo "Invalid plugin-name: must be non-empty and must not contain quotes, backslashes, angle brackets, braces, slashes, or newlines" >&2
    exit 1
fi

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
chmod -R u+w "${TARGET_DIR}"
rm -rf "${TARGET_DIR}/backend/target" "${TARGET_DIR}/bin"

python3 - "${TARGET_DIR}" "${PLUGIN_ID}" "${PLUGIN_NAME}" <<'PYEOF'
import pathlib
import sys

target_dir = pathlib.Path(sys.argv[1])
plugin_id = sys.argv[2]
plugin_name = sys.argv[3]

for path in target_dir.rglob("*"):
    if not path.is_file() or path.is_symlink():
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    updated = text.replace("{{PLUGIN_ID}}", plugin_id).replace("{{PLUGIN_NAME}}", plugin_name)
    if path.name in ("Cargo.toml", "Cargo.lock"):
        updated = updated.replace(
            'name = "aetherflow-plugin-sdk-template"',
            f'name = "aetherflow-plugin-{plugin_id}"',
        )
    if updated != text:
        path.write_text(updated, encoding="utf-8")
PYEOF

echo "Plugin scaffold created at ${TARGET_DIR}"
echo ""
echo "Plugin '${PLUGIN_NAME}' is ready. Check ${TARGET_DIR}/plugin.manifest.json to configure boundaries."
