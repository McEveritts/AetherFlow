#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_DIR="${BACKEND_DIR:-${ROOT_DIR}/backend}"
BACKEND_RS_DIR="${BACKEND_RS_DIR:-${ROOT_DIR}/backend-rs}"
FRONTEND_DIR="${FRONTEND_DIR:-${ROOT_DIR}/frontend}"
VERSION_FILE="${VERSION_FILE:-${ROOT_DIR}/.version}"
VERSION="${VERSION:-$(tr -d '\r\n' < "${VERSION_FILE}")}"
RELEASE_CHANNEL="${RELEASE_CHANNEL:-Gold}"
BINARY_NAME="${BINARY_NAME:-aetherflow-api}"
CARGO_BIN_NAME="${CARGO_BIN_NAME:-aetherflow-api}"
OUTPUT_DIR="${OUTPUT_DIR:-${ROOT_DIR}/dist/gold/${VERSION}}"
BUILD_DATE="${BUILD_DATE:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"
RUN_TESTS="${RUN_TESTS:-1}"
BUILD_FRONTEND="${BUILD_FRONTEND:-1}"
PACKAGE_RELEASE="${PACKAGE_RELEASE:-1}"
TARGETS="${TARGETS:-amd64}"

if command -v git >/dev/null 2>&1; then
  GIT_COMMIT="${GIT_COMMIT:-$(git -C "${ROOT_DIR}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')}"
else
  GIT_COMMIT="${GIT_COMMIT:-unknown}"
fi

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "error: required tool '${tool}' was not found in PATH" >&2
    exit 1
  fi
}

rust_target_for_arch() {
  local arch="$1"
  case "${arch}" in
    amd64|x86_64)
      printf 'x86_64-unknown-linux-gnu'
      ;;
    arm64|aarch64)
      printf 'aarch64-unknown-linux-gnu'
      ;;
    *)
      echo "error: unsupported target architecture '${arch}' (expected amd64 or arm64)" >&2
      exit 1
      ;;
  esac
}

normalize_arch_label() {
  local arch="$1"
  case "${arch}" in
    amd64|x86_64)
      printf 'amd64'
      ;;
    arm64|aarch64)
      printf 'arm64'
      ;;
    *)
      printf '%s' "${arch}"
      ;;
  esac
}

build_target() {
  local raw_arch="$1"
  local arch
  arch="$(normalize_arch_label "${raw_arch}")"
  local rust_target
  rust_target="$(rust_target_for_arch "${arch}")"
  if [[ -n "${CARGO_BUILD_TARGET:-}" && "${CARGO_BUILD_TARGET}" != "${rust_target}" ]]; then
    echo "error: CARGO_BUILD_TARGET '${CARGO_BUILD_TARGET}' conflicts with requested target '${rust_target}'" >&2
    exit 1
  fi
  local target_dir="${OUTPUT_DIR}/linux-${arch}"
  local artifact="${target_dir}/${BINARY_NAME}"
  local archive="${OUTPUT_DIR}/aetherflow-linux-${arch}.tar.gz"
  local compiled_bin=""

  mkdir -p "${target_dir}"

  echo "==> Building single-binary ${BINARY_NAME} and af CLI (${RELEASE_CHANNEL}) for linux/${arch} [${rust_target}]"
  (
    cd "${BACKEND_RS_DIR}"
    export AETHERFLOW_VERSION="${VERSION}"
    export AETHERFLOW_GIT_COMMIT="${GIT_COMMIT}"
    export AETHERFLOW_BUILD_DATE="${BUILD_DATE}"
    export AETHERFLOW_RELEASE_CHANNEL="${RELEASE_CHANNEL}"
    cargo build --release --target "${rust_target}" --bin "${CARGO_BIN_NAME}"
    cargo build --release --target "${rust_target}" --bin af
  )

  local cargo_target_dir="${CARGO_TARGET_DIR:-${BACKEND_RS_DIR}/target}"
  if [[ "${cargo_target_dir}" != /* ]]; then
    cargo_target_dir="${BACKEND_RS_DIR}/${cargo_target_dir}"
  fi
  compiled_bin="${cargo_target_dir}/${rust_target}/release/${CARGO_BIN_NAME}"
  local compiled_cli="${cargo_target_dir}/${rust_target}/release/af"
  if [[ ! -f "${compiled_bin}" ]]; then
    echo "error: expected compiled binary '${compiled_bin}' not found" >&2
    exit 1
  fi

  cp "${compiled_bin}" "${artifact}"
  if [[ -f "${compiled_cli}" ]]; then
    cp "${compiled_cli}" "${target_dir}/af"
    chmod +x "${target_dir}/af"
  fi
  cp -R "${BACKEND_DIR}/config" "${target_dir}/config"
  cp -R "${ROOT_DIR}/packages" "${target_dir}/packages"
  cp -R "${ROOT_DIR}/deploy" "${target_dir}/deploy"
  printf '%s\n' "${VERSION}" > "${target_dir}/.version"
  chmod +x "${artifact}" "${target_dir}/deploy/release-manager.sh"

  if [[ "${PACKAGE_RELEASE}" == "1" ]] && command -v tar >/dev/null 2>&1; then
    tar -C "${target_dir}" -czf "${archive}" .
    if command -v sha256sum >/dev/null 2>&1; then
      (cd "${OUTPUT_DIR}" && sha256sum "aetherflow-linux-${arch}.tar.gz" >> SHA256SUMS)
    fi
  fi
}

require_tool cargo

if [[ ! -f "${BACKEND_RS_DIR}/Cargo.toml" ]]; then
  echo "error: Rust workspace manifest not found at ${BACKEND_RS_DIR}/Cargo.toml" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"
rm -f "${OUTPUT_DIR}/SHA256SUMS"

if [[ "${BUILD_FRONTEND}" == "1" ]]; then
  require_tool npm
  echo "==> Building Next.js static export (NEXT_STATIC_EXPORT=1)"
  (
    cd "${FRONTEND_DIR}"
    env NEXT_STATIC_EXPORT=1 npm run build
  )
  rm -rf "${BACKEND_DIR}/web/dist"
  mkdir -p "${BACKEND_DIR}/web/dist"
  cp -R "${FRONTEND_DIR}/out/." "${BACKEND_DIR}/web/dist/"
else
  # Ensure backend/web/dist exists so rust-embed in af-api compiles cleanly when BUILD_FRONTEND=0
  mkdir -p "${BACKEND_DIR}/web/dist"
fi

if [[ "${RUN_TESTS}" == "1" ]]; then
  echo "==> Running Rust workspace unit and contract tests"
  (
    cd "${BACKEND_RS_DIR}"
    export JWT_SECRET="${JWT_SECRET:-ci-test-secret-exactly-32bytes!!}"
    export AES_MASTER_KEY="${AES_MASTER_KEY:-ci-test-aes-key-exactly-32bytes!}"
    export ALLOWED_HOSTS="${ALLOWED_HOSTS:-localhost:8080,127.0.0.1:8080}"
    cargo test --workspace
  )
fi

for arch in ${TARGETS}; do
  build_target "${arch}"
done

echo "==> Single-binary Rust release artifacts and SHA256SUMS ready in ${OUTPUT_DIR}"
