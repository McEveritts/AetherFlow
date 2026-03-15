#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="${BACKEND_DIR:-${ROOT_DIR}/backend}"
VERSION_FILE="${VERSION_FILE:-${ROOT_DIR}/.version}"
VERSION="${VERSION:-$(tr -d '\r\n' < "${VERSION_FILE}")}"
RELEASE_CHANNEL="${RELEASE_CHANNEL:-Gold}"
BINARY_NAME="${BINARY_NAME:-aetherflow-api}"
OUTPUT_DIR="${OUTPUT_DIR:-${ROOT_DIR}/dist/gold/${VERSION}}"
BUILD_DATE="${BUILD_DATE:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"
RUN_TESTS="${RUN_TESTS:-1}"
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

default_compiler_for_arch() {
  local arch="$1"
  case "${arch}" in
    amd64)
      if command -v x86_64-linux-gnu-gcc >/dev/null 2>&1; then
        printf '%s\n' "x86_64-linux-gnu-gcc"
      else
        printf '%s\n' "gcc"
      fi
      ;;
    arm64)
      printf '%s\n' "aarch64-linux-gnu-gcc"
      ;;
    *)
      echo "error: unsupported target architecture '${arch}'" >&2
      exit 1
      ;;
  esac
}

compiler_for_arch() {
  local arch="$1"
  local env_name="CC_LINUX_${arch^^}"
  local env_value="${!env_name:-}"
  if [[ -n "${env_value}" ]]; then
    printf '%s\n' "${env_value}"
    return
  fi
  default_compiler_for_arch "${arch}"
}

build_target() {
  local arch="$1"
  local cc
  local ldflags
  local target_dir
  local artifact
  local archive

  cc="$(compiler_for_arch "${arch}")"
  if ! command -v "${cc}" >/dev/null 2>&1; then
    cat >&2 <<EOF
error: compiler '${cc}' is required for linux/${arch} builds.
Install the Linux toolchain first, for example:
  amd64: sudo apt-get install build-essential
  arm64: sudo apt-get install gcc-aarch64-linux-gnu libc6-dev-arm64-cross
You can also override the compiler with CC_LINUX_${arch^^}=...
EOF
    exit 1
  fi

  target_dir="${OUTPUT_DIR}/linux-${arch}"
  artifact="${target_dir}/${BINARY_NAME}"
  archive="${OUTPUT_DIR}/${BINARY_NAME}_${VERSION}_linux_${arch}.tar.gz"
  ldflags="-s -w -buildid= -X main.version=${VERSION}"

  mkdir -p "${target_dir}"

  echo "==> Building ${BINARY_NAME} for linux/${arch} with ${cc}"
  (
    cd "${BACKEND_DIR}"
    env CGO_ENABLED=1 GOOS=linux GOARCH="${arch}" CC="${cc}" \
      go build -trimpath -buildvcs=false -ldflags "${ldflags}" -o "${artifact}" .
  )

  if command -v sha256sum >/dev/null 2>&1; then
    (cd "${target_dir}" && sha256sum "${BINARY_NAME}" > "${BINARY_NAME}.sha256")
  fi

  if [[ "${PACKAGE_RELEASE}" == "1" ]] && command -v tar >/dev/null 2>&1; then
    if [[ -f "${artifact}.sha256" ]]; then
      tar -C "${target_dir}" -czf "${archive}" "${BINARY_NAME}" "${BINARY_NAME}.sha256"
    else
      tar -C "${target_dir}" -czf "${archive}" "${BINARY_NAME}"
    fi
  fi
}

require_tool go

if [[ ! -f "${BACKEND_DIR}/go.mod" ]]; then
  echo "error: backend module not found at '${BACKEND_DIR}'" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"
cat > "${OUTPUT_DIR}/BUILD_INFO.txt" <<EOF
version=${VERSION}
release_channel=${RELEASE_CHANNEL}
build_date=${BUILD_DATE}
git_commit=${GIT_COMMIT}
targets=${TARGETS}
EOF

echo "==> Preparing AetherFlow ${VERSION} ${RELEASE_CHANNEL} release artifacts"
echo "==> Output directory: ${OUTPUT_DIR}"

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

echo "==> Release artifacts ready in ${OUTPUT_DIR}"
