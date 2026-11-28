#!/usr/bin/env bash
set -euo pipefail
export PATH="${WASM_TOOL_DIR:-/usr/local/lib/aetherflow-wasm-tools}/bin:${XDG_CACHE_HOME:-${HOME:-/tmp}/.cache}/aetherflow-wasm-tools/bin:${HOME:-/root}/.cargo/bin:${PATH}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE=0
case "${1:-}" in
  --stage) STAGE=1 ;;
  "") ;;
  *) echo "usage: $0 [--stage]" >&2; exit 2 ;;
esac
(
  cd "${ROOT_DIR}/frontend-rs"
  trunk build --release
)
# Publish the five lazy core catalogs as deterministic JSON with gzip/Brotli
# sidecars, including when this script stages an existing Trunk output tree.
python3 "${ROOT_DIR}/scripts/finalize_wasm_assets.py" --locales-only "${ROOT_DIR}/frontend-rs/dist"
find "${ROOT_DIR}/frontend-rs/dist" -depth -name '.trunk*' -exec rm -rf -- {} +
find "${ROOT_DIR}/frontend-rs/dist" \( -type f -o -type l \) \( -name 'EGM.md' -o -name '*_DRIFT_REPORT.md' -o -name 'goldfish_review_report.md' \) -delete
cargo run --quiet --release --locked --manifest-path "${ROOT_DIR}/frontend-rs/Cargo.toml" -p af-web-core --example compress-assets -- "${ROOT_DIR}/frontend-rs/dist"
if [[ "${STAGE}" == "1" ]]; then
  source_dist="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve(strict=True))' "${ROOT_DIR}/frontend-rs/dist")"
  FRONTEND_DIST_DIR="${FRONTEND_DIST_DIR:-${EMBED_DIST_DIR:-${ROOT_DIR}/web/dist}}"
  destination="$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).resolve())' "${FRONTEND_DIST_DIR}")"
  # A configured output may already be the Trunk distribution. Never delete
  # the source bundle, including through a symlink or ancestor directory.
  if [[ "${destination}" == "${source_dist}" ]]; then
    exit 0
  fi
  if [[ "${destination}" == "/" || "${source_dist}" == "${destination}/"* ]]; then
    echo "error: staging destination contains the source output: ${destination}" >&2
    exit 2
  fi
  if [[ "${destination}" == "${source_dist}/"* ]]; then
    echo "error: staging destination is inside the source output: ${destination}" >&2
    exit 2
  fi
  mkdir -p "${destination}"
  # Remove obsolete bundles at cutover; preserve tracked placeholders.
  find "${destination}" -mindepth 1 -maxdepth 1 ! -name .keep -exec rm -rf -- {} +
  cp -a "${source_dist}/." "${destination}/"
  touch "${destination}/.keep"
fi
