#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:---scoped}"
if [[ "$#" -gt 1 || ( "${MODE}" != "--scoped" && "${MODE}" != "--integrated" ) ]]; then
  echo "Usage: bash scripts/validate-streaming.sh [--scoped|--integrated]" >&2
  exit 2
fi

for tool in node npm cargo git timeout; do
  if ! command -v "${tool}" >/dev/null 2>&1; then
    echo "Missing prerequisite: ${tool}" >&2
    exit 2
  fi
done

node -e '
  const [major, minor] = process.versions.node.split(".").map(Number);
  if (major < 22 || (major === 22 && minor < 19)) {
    console.error("Node >=22.19.0 required by installed test dependencies; run nvm install && nvm use.");
    process.exit(2);
  }
'

mkdir -p "${ROOT_DIR}/dist"
RESULT_DIR="$(mktemp -d "${ROOT_DIR}/dist/streaming-validation.XXXXXX")"
export AF_STREAMING_CONTRACT_FIXTURE="${RESULT_DIR}/rust-dashboard.json"
export AF_STREAMING_ARCHIVE_FIXTURE="${RESULT_DIR}/rust-archive.json"
export AF_STREAMING_PORTABILITY_FIXTURE="${RESULT_DIR}/rust-portability.json"
FAILED=0
CHECK_TIMEOUT="${AF_STREAMING_CHECK_TIMEOUT:-10m}"

run_check() {
  local name="$1"
  shift
  printf '\n==> %s\n' "${name}"
  if (cd "${ROOT_DIR}" && timeout --kill-after=10s "${CHECK_TIMEOUT}" "$@") 2>&1 | tee "${RESULT_DIR}/${name}.log"; then
    printf 'PASS %s\n' "${name}" | tee -a "${RESULT_DIR}/summary.txt"
  else
    local status="$?"
    printf 'FAIL %s (exit %s)\n' "${name}" "${status}" | tee -a "${RESULT_DIR}/summary.txt"
    FAILED=1
  fi
}

{
  date -u +'%Y-%m-%dT%H:%M:%SZ'
  node --version
  npm --version
  cargo --version
  git -C "${ROOT_DIR}" rev-parse HEAD
  git -C "${ROOT_DIR}" status --short
} > "${RESULT_DIR}/environment.txt"

run_check rust-streaming cargo test --manifest-path backend-rs/Cargo.toml --locked \
  -p af-streaming-tests streaming_ext::tests -- --test-threads=1
run_check rust-canonical-streaming cargo test --manifest-path backend-rs/Cargo.toml --locked \
  -p af-streaming-tests streaming_ -- --test-threads=1
run_check rust-streaming-migration cargo test --manifest-path backend-rs/Cargo.toml --locked \
  -p af-db streaming::tests -- --test-threads=1

if [[ -s "${AF_STREAMING_CONTRACT_FIXTURE}" ]]; then
  run_check frontend-streaming npm --workspace frontend test -- --runInBand --runTestsByPath \
    src/components/tabs/StreamingTab.test.tsx \
    src/components/tabs/StreamingTab.rust-contract.test.tsx \
    src/components/streaming/StreamingHistoryExplorer.test.tsx \
    src/components/streaming/StreamingInsights.test.tsx \
    src/components/streaming/StreamingPortability.test.tsx \
    src/components/streaming/StreamingHistoryAdmin.test.tsx
else
  echo 'FAIL rust-contract-fixture (not generated; frontend contracts cannot run)' \
    | tee -a "${RESULT_DIR}/summary.txt"
  FAILED=1
fi

run_check typescript npm exec --workspace frontend -- tsc --noEmit --incremental false
run_check streaming-lint npm --workspace frontend run lint -- \
  src/components/tabs/StreamingTab.tsx \
  src/components/tabs/StreamingTab.test.tsx \
  src/components/tabs/StreamingTab.rust-contract.test.tsx src/lib/streaming.ts \
  src/components/streaming/StreamingHistoryExplorer.tsx \
  src/components/streaming/StreamingHistoryExplorer.test.tsx src/lib/streaming-history.ts \
  src/components/streaming/StreamingInsights.tsx \
  src/components/streaming/StreamingInsights.test.tsx \
  src/components/streaming/StreamingPortability.tsx \
  src/components/streaming/StreamingPortability.test.tsx \
  src/components/streaming/StreamingHistoryAdmin.tsx \
  src/components/streaming/StreamingHistoryAdmin.test.tsx

if [[ "${MODE}" == "--integrated" ]]; then
  unset AF_STREAMING_CONTRACT_FIXTURE
  run_check rust-integrated-tests cargo test --manifest-path backend-rs/Cargo.toml --locked \
    -p af-api -- --test-threads=1
  run_check rust-integrated-build cargo build --manifest-path backend-rs/Cargo.toml --locked -p af-api
  export AF_STREAMING_CONTRACT_FIXTURE="${RESULT_DIR}/rust-dashboard.json"
  if [[ -s "${AF_STREAMING_CONTRACT_FIXTURE}" ]]; then
    run_check frontend-all npm --workspace frontend test -- --runInBand
  else
    echo 'FAIL frontend-all (Rust contract fixture unavailable)' | tee -a "${RESULT_DIR}/summary.txt"
    FAILED=1
  fi
  run_check frontend-lint npm --workspace frontend run lint
  run_check frontend-build env NEXT_STATIC_EXPORT=1 npm --workspace frontend run build
fi

printf '\nResults: %s\n' "${RESULT_DIR}"
cat "${RESULT_DIR}/summary.txt"
echo 'Live Jellyfin-client, browser/privacy acceptance and deployment authorization remain separate gates.'
exit "${FAILED}"
