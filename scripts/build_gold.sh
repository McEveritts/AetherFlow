#!/usr/bin/env bash
set -euo pipefail
umask 022
# Honor an explicitly selected toolchain (including build harnesses); fall back
# to rustup only when cargo is absent from the caller's PATH.
if ! command -v cargo >/dev/null 2>&1; then
  export PATH="$HOME/.cargo/bin:$PATH"
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND_RS_DIR="${BACKEND_RS_DIR:-${ROOT_DIR}/backend-rs}"
CONFIG_DIR="${CONFIG_DIR:-${ROOT_DIR}/config}"
FRONTEND_DIST_DIR="${FRONTEND_DIST_DIR:-${EMBED_DIST_DIR:-${ROOT_DIR}/web/dist}}"
VERSION_FILE="${VERSION_FILE:-${ROOT_DIR}/.version}"
VERSION="${VERSION:-$(tr -d '\r\n' < "${VERSION_FILE}")}"
RELEASE_CHANNEL="${RELEASE_CHANNEL:-Gold}"
BINARY_NAME="${BINARY_NAME:-aetherflow-api}"
CARGO_BIN_NAME="${CARGO_BIN_NAME:-aetherflow-api}"
CLI_BINARY_NAME="${CLI_BINARY_NAME:-af}"
CARGO_CLI_BIN_NAME="${CARGO_CLI_BIN_NAME:-af}"
BUILD_CLI="${BUILD_CLI:-1}"
SPEEDTEST_BINARY_NAME="${SPEEDTEST_BINARY_NAME:-speedtest-backend}"
CARGO_SPEEDTEST_BIN_NAME="${CARGO_SPEEDTEST_BIN_NAME:-speedtest-backend}"
BUILD_SPEEDTEST="${BUILD_SPEEDTEST:-1}"
PACKAGE_SPEEDTEST_STANDALONE="${PACKAGE_SPEEDTEST_STANDALONE:-0}"
CARGO_LOCKED="${CARGO_LOCKED:-1}"
CARGO_ALLOW_UNLOCKED_DEV="${CARGO_ALLOW_UNLOCKED_DEV:-0}"
OUTPUT_DIR="${OUTPUT_DIR:-${ROOT_DIR}/dist/gold/${VERSION}}"
RUN_TESTS="${RUN_TESTS:-1}"
BUILD_FRONTEND="${BUILD_FRONTEND:-1}"
FRONTEND_ENGINE="${FRONTEND_ENGINE:-wasm}"
PACKAGE_RELEASE="${PACKAGE_RELEASE:-1}"
TARGETS="${TARGETS:-amd64}"

if command -v git >/dev/null 2>&1; then
  GIT_COMMIT="${GIT_COMMIT:-$(git -C "${ROOT_DIR}" rev-parse --short HEAD 2>/dev/null || printf 'unknown')}"
  SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git -C "${ROOT_DIR}" show -s --format=%ct HEAD 2>/dev/null || printf '0')}"
else
  GIT_COMMIT="${GIT_COMMIT:-unknown}"
  SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
fi
if [[ ! "${SOURCE_DATE_EPOCH}" =~ ^[0-9]+$ ]]; then
  echo "error: SOURCE_DATE_EPOCH must be a non-negative integer" >&2
  exit 1
fi
if [[ -z "${BUILD_DATE:-}" ]]; then
  BUILD_DATE="$(date -u -d "@${SOURCE_DATE_EPOCH}" +"%Y-%m-%dT%H:%M:%SZ")" || {
    echo "error: SOURCE_DATE_EPOCH is outside the supported date range" >&2
    exit 1
  }
fi
export SOURCE_DATE_EPOCH

require_tool() {
  local tool="$1"
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "error: required tool '${tool}' was not found in PATH" >&2
    exit 1
  fi
}

resolve_cargo_locked_args() {
  CARGO_LOCKED_ARGS=()
  case "${CARGO_LOCKED}" in
    1|true|TRUE|yes|YES|"")
      if [[ ! -f "${BACKEND_RS_DIR}/Cargo.lock" ]]; then
        echo "error: ${BACKEND_RS_DIR}/Cargo.lock is required for reproducible locked builds (refusing unlocked fallback)" >&2
        exit 1
      fi
      CARGO_LOCKED_ARGS=(--locked)
      ;;
    0|false|FALSE|no|NO)
      if [[ "${PACKAGE_RELEASE}" == "1" || "${CARGO_ALLOW_UNLOCKED_DEV}" != "1" ]]; then
        echo "error: CARGO_LOCKED=0 is only permitted for non-release dev builds when CARGO_ALLOW_UNLOCKED_DEV=1" >&2
        exit 1
      fi
      ;;
    *)
      echo "error: invalid CARGO_LOCKED='${CARGO_LOCKED}' (expected 1 or 0 with CARGO_ALLOW_UNLOCKED_DEV=1)" >&2
      exit 1
      ;;
  esac
}

resolve_config_source_dir() {
  if [[ -d "${CONFIG_DIR}" ]]; then
    printf '%s' "${CONFIG_DIR}"
  else
    echo "error: config directory '${CONFIG_DIR}' does not exist" >&2
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
    armv7|armv7l|armhf)
      printf 'armv7-unknown-linux-gnueabihf'
      ;;
    *)
      echo "error: unsupported target architecture '${arch}' (expected amd64, arm64, or armv7)" >&2
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
    armv7|armv7l|armhf)
      printf 'armv7'
      ;;
    *)
      printf '%s' "${arch}"
      ;;
  esac
}

stage_companion_binary() {
  local compiled_path="$1"
  local target_dir="$2"
  local dest_name="$3"
  if [[ ! -f "${compiled_path}" ]]; then
    echo "error: expected compiled binary '${compiled_path}' not found" >&2
    exit 1
  fi
  cp "${compiled_path}" "${target_dir}/${dest_name}"
  mkdir -p "${target_dir}/bin"
  cp "${compiled_path}" "${target_dir}/bin/${dest_name}"
  chmod 0755 "${target_dir}/${dest_name}" "${target_dir}/bin/${dest_name}"
}

build_target() {
  local raw_arch="$1"
  local arch
  arch="$(normalize_arch_label "${raw_arch}")"
  local host_arch
  host_arch="$(normalize_arch_label "$(uname -m)")"
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
  local compiled_speedtest=""
  local cfg_src=""
  cfg_src="$(resolve_config_source_dir)"

  mkdir -p "${target_dir}"

  echo "==> Building ${BINARY_NAME} and af CLI (${RELEASE_CHANNEL}) for linux/${arch} [${rust_target}]"
  (
    cd "${BACKEND_RS_DIR}"
    export AETHERFLOW_VERSION="${VERSION}"
    export AF_BUILD_VERSION="${VERSION}"
    export AETHERFLOW_GIT_COMMIT="${GIT_COMMIT}"
    export AETHERFLOW_BUILD_DATE="${BUILD_DATE}"
    export AETHERFLOW_RELEASE_CHANNEL="${RELEASE_CHANNEL}"
    if [[ "${arch}" != "${host_arch}" ]]; then
      case "${rust_target}" in
        aarch64-unknown-linux-gnu)
          export CC_aarch64_unknown_linux_gnu="${CC_aarch64_unknown_linux_gnu:-aarch64-linux-gnu-gcc}"
          export AR_aarch64_unknown_linux_gnu="${AR_aarch64_unknown_linux_gnu:-aarch64-linux-gnu-ar}"
          export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER:-aarch64-linux-gnu-gcc}"
          export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS:--C link-arg=-Wl,--as-needed}"
          ;;
        armv7-unknown-linux-gnueabihf)
          export CC_armv7_unknown_linux_gnueabihf="${CC_armv7_unknown_linux_gnueabihf:-arm-linux-gnueabihf-gcc}"
          export AR_armv7_unknown_linux_gnueabihf="${AR_armv7_unknown_linux_gnueabihf:-arm-linux-gnueabihf-ar}"
          export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER="${CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_LINKER:-arm-linux-gnueabihf-gcc}"
          export CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_RUSTFLAGS="${CARGO_TARGET_ARMV7_UNKNOWN_LINUX_GNUEABIHF_RUSTFLAGS:--C link-arg=-Wl,--as-needed}"
          ;;
        x86_64-unknown-linux-gnu)
          export CC_x86_64_unknown_linux_gnu="${CC_x86_64_unknown_linux_gnu:-x86_64-linux-gnu-gcc}"
          export AR_x86_64_unknown_linux_gnu="${AR_x86_64_unknown_linux_gnu:-x86_64-linux-gnu-ar}"
          export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER:-x86_64-linux-gnu-gcc}"
          export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS:--C link-arg=-Wl,--as-needed}"
          ;;
      esac
    elif ! command -v mold >/dev/null 2>&1; then
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS:--C link-arg=-Wl,--as-needed}"
      export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS:--C link-arg=-Wl,--as-needed}"
    fi
    cargo build "${CARGO_LOCKED_ARGS[@]}" --release --target "${rust_target}" --bin "${CARGO_BIN_NAME}"
    if [[ "${BUILD_CLI}" == "1" && -f "${BACKEND_RS_DIR}/crates/af-cli/Cargo.toml" ]]; then
      cargo build "${CARGO_LOCKED_ARGS[@]}" --release --target "${rust_target}" --bin "${CARGO_CLI_BIN_NAME}"
    fi
    if [[ "${BUILD_SPEEDTEST}" == "1" && -f "${BACKEND_RS_DIR}/crates/af-librespeed/Cargo.toml" ]]; then
      cargo build "${CARGO_LOCKED_ARGS[@]}" --release --target "${rust_target}" --bin "${CARGO_SPEEDTEST_BIN_NAME}"
    fi
  )

  local cargo_target_dir="${CARGO_TARGET_DIR:-${BACKEND_RS_DIR}/target}"
  if [[ "${cargo_target_dir}" != /* ]]; then
    cargo_target_dir="${BACKEND_RS_DIR}/${cargo_target_dir}"
  fi
  compiled_bin="${cargo_target_dir}/${rust_target}/release/${CARGO_BIN_NAME}"
  if [[ ! -f "${compiled_bin}" ]]; then
    echo "error: expected compiled binary '${compiled_bin}' not found" >&2
    exit 1
  fi

  # Each invocation publishes a fresh tree, including when rebuilding a version.
  # Copying directories onto the previous tree nests config/config and packages/packages.
  rm -rf -- "${target_dir}"
  mkdir -p "${target_dir}"
  cp "${compiled_bin}" "${artifact}"
  chmod 0755 "${artifact}"

  if [[ "${BUILD_CLI}" == "1" && -f "${BACKEND_RS_DIR}/crates/af-cli/Cargo.toml" ]]; then
    stage_companion_binary "${cargo_target_dir}/${rust_target}/release/${CARGO_CLI_BIN_NAME}" "${target_dir}" "${CLI_BINARY_NAME}"
  fi

  if [[ "${BUILD_SPEEDTEST}" == "1" && -f "${BACKEND_RS_DIR}/crates/af-librespeed/Cargo.toml" ]]; then
    compiled_speedtest="${cargo_target_dir}/${rust_target}/release/${CARGO_SPEEDTEST_BIN_NAME}"
    stage_companion_binary "${compiled_speedtest}" "${target_dir}" "${SPEEDTEST_BINARY_NAME}"
  fi

  local -a runtime_excludes=(--exclude='node_modules' --exclude='__pycache__' \
    --exclude='*.pyc' --exclude='*.pyo' --exclude='*.tsbuildinfo' \
    --exclude='.cache' --exclude='.pytest_cache' --exclude='.mypy_cache' \
    --exclude='.ruff_cache' --exclude='.tox' --exclude='.venv' --exclude='.turbo' \
    --exclude='.next' --exclude='target')
  if frontend_assets_present "${FRONTEND_DIST_DIR}"; then
    mkdir -p "${target_dir}/web/dist"
    tar -C "${FRONTEND_DIST_DIR}" "${runtime_excludes[@]}" -cf - . | tar -C "${target_dir}/web/dist" -xpf -
  fi
  if [[ "${PACKAGE_RELEASE}" == "1" ]] && ! frontend_assets_present "${target_dir}/web/dist"; then
    echo "error: packaged web/dist requires non-empty index.html and a .wasm file" >&2
    exit 1
  fi

  mkdir -p "${target_dir}/config"
  tar -C "${cfg_src}" "${runtime_excludes[@]}" -cf - . | tar -C "${target_dir}/config" -xpf -
  tar -C "${ROOT_DIR}" "${runtime_excludes[@]}" --exclude='packages/ui' --exclude='packages/plugin' \
    --exclude='packages/README.md' -cf - packages deploy | tar -C "${target_dir}" -xpf -
  printf '%s\n' "${VERSION}" > "${target_dir}/.version"
  chmod 0755 "${target_dir}" "${target_dir}/deploy/release-manager.sh"
  for runtime_script in verify-provenance.py log-retention.py; do
    if [[ -f "${target_dir}/deploy/${runtime_script}" ]]; then
      chmod 0755 "${target_dir}/deploy/${runtime_script}"
    fi
  done

  if [[ "${PACKAGE_RELEASE}" == "1" ]]; then
    package_archive "${target_dir}" "${archive}" .
    (cd "${OUTPUT_DIR}" && sha256sum "aetherflow-linux-${arch}.tar.gz" >> SHA256SUMS)
    if [[ "${PACKAGE_SPEEDTEST_STANDALONE}" == "1" && -n "${compiled_speedtest}" && -f "${target_dir}/${SPEEDTEST_BINARY_NAME}" ]]; then
      local clean_ver="${VERSION#v}"
      local speedtest_archive_name="speedtest-backend_${clean_ver}_linux_${arch}.tar.gz"
      package_archive "${target_dir}" "${OUTPUT_DIR}/${speedtest_archive_name}" "${SPEEDTEST_BINARY_NAME}"
      (cd "${OUTPUT_DIR}" && sha256sum "${speedtest_archive_name}" >> SHA256SUMS)
    fi
  fi
}

package_archive() {
  local source_dir="$1" archive="$2" entry="$3"
  # Normalize runtime permissions and metadata for reproducible tarballs.
  tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner \
    --mode='a=rX,u+w,a-s,a-t' --format=gnu -C "${source_dir}" -cf - "${entry}" | gzip -n -c > "${archive}"
}

frontend_assets_present() {
  local dir="$1"
  [[ -f "${dir}/index.html" && ! -L "${dir}/index.html" && -s "${dir}/index.html" ]] && \
    [[ -n "$(find "${dir}" -type f -name '*.wasm' -size +0c -print -quit)" ]]
}

require_tool cargo
require_tool tar
if [[ "${PACKAGE_RELEASE}" == "1" ]]; then
  require_tool gzip
  require_tool sha256sum
fi

if [[ ! -f "${BACKEND_RS_DIR}/Cargo.toml" ]]; then
  echo "error: Rust workspace manifest not found at ${BACKEND_RS_DIR}/Cargo.toml" >&2
  exit 1
fi

resolve_cargo_locked_args

if [[ "${PACKAGE_RELEASE}" == "1" ]] && { [[ "${BUILD_CLI}" != "1" ]] || [[ ! -f "${BACKEND_RS_DIR}/crates/af-cli/Cargo.toml" ]]; }; then
  echo "error: full release requires the af CLI (BUILD_CLI=1 and af-cli manifest)" >&2
  exit 1
fi

mkdir -p "${OUTPUT_DIR}"
rm -f "${OUTPUT_DIR}/SHA256SUMS"

if [[ "${BUILD_FRONTEND}" == "1" ]]; then
  if [[ "${FRONTEND_ENGINE}" != "wasm" ]]; then
    echo "error: FRONTEND_ENGINE must be wasm; legacy frontend builds are retired" >&2
    exit 2
  fi
  FRONTEND_DIST_DIR="${FRONTEND_DIST_DIR}" bash "${ROOT_DIR}/scripts/build_wasm_frontend.sh" --stage
fi

if [[ "${PACKAGE_RELEASE}" == "1" ]] && ! frontend_assets_present "${FRONTEND_DIST_DIR}"; then
  echo "error: full release requires non-empty index.html and a .wasm file in '${FRONTEND_DIST_DIR}'" >&2
  exit 1
fi

if [[ "${RUN_TESTS}" == "1" ]]; then
  echo "==> Running Rust workspace unit and contract tests"
  (
    cd "${BACKEND_RS_DIR}"
    export JWT_SECRET="${JWT_SECRET:-ci-test-secret-exactly-32bytes!!}"
    export AES_MASTER_KEY="${AES_MASTER_KEY:-ci-test-aes-key-exactly-32bytes!}"
    export ALLOWED_HOSTS="${ALLOWED_HOSTS:-localhost:8080,127.0.0.1:8080}"
    export AETHERFLOW_DISABLE_BACKGROUND_WORKERS="${AETHERFLOW_DISABLE_BACKGROUND_WORKERS:-1}"
    export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"
    if ! command -v mold >/dev/null 2>&1; then
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="${CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS:--C link-arg=-Wl,--as-needed}"
      export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS:--C link-arg=-Wl,--as-needed}"
    fi
    cargo test "${CARGO_LOCKED_ARGS[@]}" --workspace
  )
  if [[ -f "${ROOT_DIR}/frontend-rs/Cargo.toml" ]]; then
    cargo test "${CARGO_LOCKED_ARGS[@]}" --manifest-path "${ROOT_DIR}/frontend-rs/Cargo.toml" --workspace
  fi
fi

for arch in ${TARGETS}; do
  build_target "${arch}"
done

echo "==> Rust release artifacts and external frontend assets ready in ${OUTPUT_DIR}"
