#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="${BACKEND_DIR:-${ROOT_DIR}/backend}"
FRONTEND_DIR="${FRONTEND_DIR:-${ROOT_DIR}/frontend}"
VERSION_FILE="${VERSION_FILE:-${ROOT_DIR}/.version}"
VERSION="${VERSION:-$(tr -d '\r\n' < "${VERSION_FILE}")}"
RELEASE_CHANNEL="${RELEASE_CHANNEL:-Gold}"
BINARY_NAME="${BINARY_NAME:-aetherflow-api}"
OUTPUT_DIR="${OUTPUT_DIR:-${ROOT_DIR}/dist/gold/${VERSION}}"
BUILD_DATE="${BUILD_DATE:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"
RUN_TESTS="${RUN_TESTS:-1}"
BUILD_FRONTEND="${BUILD_FRONTEND:-1}"
PACKAGE_RELEASE="${PACKAGE_RELEASE:-1}"
TARGETS="${TARGETS:-amd64 arm64}"

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

build_target() {
  local arch="$1"
  local ldflags="-s -w -buildid= -X main.version=${VERSION}"
  local target_dir="${OUTPUT_DIR}/linux-${arch}"
  local artifact="${target_dir}/${BINARY_NAME}"
  local archive="${OUTPUT_DIR}/aetherflow-linux-${arch}.tar.gz"

  mkdir -p "${target_dir}"

  echo "==> Building single-binary ${BINARY_NAME} for linux/${arch} (CGO_ENABLED=0)"
  (
    cd "${BACKEND_DIR}"
    env CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" \
      go build -trimpath -buildvcs=false -ldflags "${ldflags}" -o "${artifact}" .
  )

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

require_tool go

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
fi

if [[ "${RUN_TESTS}" == "1" ]]; then
  echo "==> Running backend unit tests"
  (
    cd "${BACKEND_DIR}"
    go test ./... -count=1
  )
fi

for arch in ${TARGETS}; do
  build_target "${arch}"
done

echo "==> Single-binary release artifacts and SHA256SUMS ready in ${OUTPUT_DIR}"
