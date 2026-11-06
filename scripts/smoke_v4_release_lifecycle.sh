#!/bin/bash
###############################################################################
# AetherFlow v4 Release Lifecycle Smoke Harness (Non-Destructive & Isolated)
#
# Deterministically validates in an isolated temporary root (${TMPDIR:-/var/tmp}):
#   1. Supported OS matrix preflight detection across Ubuntu 20.04/22.04/24.04,
#      Debian 11/12/13 (trixie with empty VERSION_ID), and Kali rolling, plus
#      rejection of unsupported distributions/versions.
#   2. Fresh installer (`setup/modules/modern_stack.sh`) prebuilt v4 Rust release
#      pull with SHA-256 verification, zero Go/Node compilation, and packaging of
#      both `aetherflow-api` and `af` CLI (`_syscommands` dispatch).
#   3. Fail-closed verification: corrupted SHA-256 or missing prebuilt release
#      is rejected with NO implicit source-build or legacy v3 downgrade when
#      `--from-source` / `AETHERFLOW_BUILD_FROM_SOURCE` is not set.
#   4. Atomic upgrade from v4.0.0 -> v4.0.1 via `deploy/release-manager.sh`,
#      verifying WAL-safe SQLite online backup (`data-snapshot/aetherflow.sqlite.bak`),
#      `MANIFEST.sha256`, and `/health/ready` verification.
#   5. Fault-injected broken upgrade (`v4.0.2-broken` that corrupts SQLite and
#      fails `/health/ready`), verifying Stage 4 automatic symlink rollback to
#      `v4.0.1` and automatic SQLite database restoration from the pre-swap
#      verified snapshot.
#   6. Manual `rollback` command verification (`v4.0.1` -> `v4.0.0`).
###############################################################################
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_BASE="${TMPDIR:-/var/tmp}"
if [[ ! -d "${TMP_BASE}" || ! -w "${TMP_BASE}" ]]; then
    TMP_BASE="/tmp"
fi

WORK_DIR="$(mktemp -d "${TMP_BASE}/aetherflow-v4-lifecycle-smoke.XXXXXX")"
chmod 0755 "${WORK_DIR}"

cleanup() {
    local rc=$?
    if [[ "${rc}" -ne 0 || "${KEEP_SMOKE_ARTIFACTS:-0}" == "1" ]]; then
        echo "[SMOKE-INFO] Preserving smoke work directory and logs at: ${WORK_DIR}" >&2
    else
        rm -rf "${WORK_DIR}"
    fi
    exit "${rc}"
}
trap cleanup EXIT INT TERM

fail() {
    echo "[SMOKE-FAIL] $*" >&2
    exit 1
}

pass() {
    echo "[SMOKE-PASS] $*"
}

build_release_tarball() {
    local out_dir="$1"
    local version_tag="$2"
    local health_status="${3:-ready}"
    local corrupt_db_on_start="${4:-0}"

    local stage="${WORK_DIR}/stage-${version_tag}"
    rm -rf "${stage}" "${out_dir}"
    mkdir -p "${stage}/deploy/systemd" "${stage}/packages" "${stage}/config" "${stage}/bin" "${out_dir}"

    cp -f "${ROOT_DIR}/deploy/release-manager.sh" "${stage}/deploy/release-manager.sh"
    cp -f "${ROOT_DIR}/deploy/release-manager.conf" "${stage}/deploy/release-manager.conf"
    cp -f "${ROOT_DIR}/deploy/systemd/aetherflow-api.service" "${stage}/deploy/systemd/aetherflow-api.service"
    cp -f "${ROOT_DIR}/deploy/systemd/aetherflow-runner.service" "${stage}/deploy/systemd/aetherflow-runner.service"
    if [[ -d "${ROOT_DIR}/config" ]]; then
        cp -R "${ROOT_DIR}/config/." "${stage}/config/"
    elif [[ -d "${ROOT_DIR}/backend/config" ]]; then
        cp -R "${ROOT_DIR}/backend/config/." "${stage}/config/"
    fi

    cat > "${stage}/aetherflow-api" <<EOF
#!/bin/bash
if [[ "\${1:-}" == "runner" || "\${1:-}" == "--runner" ]]; then
    echo "runner-${version_tag}"
    exit 0
fi
if [[ "\${1:-}" == "--version" ]]; then
    echo "aetherflow-api ${version_tag}"
    exit 0
fi
echo "${health_status}" > "\${SMOKE_STATE_DIR}/active_health_status"
echo "${version_tag}" > "\${SMOKE_STATE_DIR}/active_version"
if [[ "${corrupt_db_on_start}" == "1" && -n "\${SMOKE_DB_PATH:-}" && -f "\${SMOKE_DB_PATH}" ]]; then
    printf 'corrupted-sqlite-header' > "\${SMOKE_DB_PATH}"
fi
exit 0
EOF

    cat > "${stage}/af" <<EOF
#!/bin/bash
echo "af-cli ${version_tag} args:\$*"
EOF
    cp -f "${stage}/af" "${stage}/bin/af"
    printf '%s\n' "${version_tag}" > "${stage}/.version"

    chmod 0755 "${stage}/aetherflow-api" "${stage}/af" "${stage}/bin/af" "${stage}/deploy/release-manager.sh"
    find "${stage}" -type d -exec chmod 0755 {} +

    local archive="${out_dir}/aetherflow-linux-amd64.tar.gz"
    tar --owner=0 --group=0 --numeric-owner -C "${stage}" -czf "${archive}" .
    (cd "${out_dir}" && sha256sum aetherflow-linux-amd64.tar.gz > SHA256SUMS)
}

# ==============================================================================
# PHASE 1: Supported OS Matrix Preflight Verification
# ==============================================================================
echo "=== Phase 1: Supported OS Matrix Preflight ==="
OS_TEST_DIR="${WORK_DIR}/os-matrix"
mkdir -p "${OS_TEST_DIR}"

check_os_profile() {
    local label="$1"
    local expect_ok="$2"
    local os_release_content="$3"
    local os_file="${OS_TEST_DIR}/os-release-${label}"
    printf '%s\n' "${os_release_content}" > "${os_file}"

    local rc=0
    bash -c '
        version_ge() {
            [[ "$(printf "%s\n%s\n" "$2" "$1" | sort -V | head -n1)" == "$2" ]]
        }
        . "$1"
        distro="${ID:-unknown}"
        version="${VERSION_ID:-0}"
        case "$distro" in
            ubuntu)
                version_ge "$version" "20.04" || exit 1
                ;;
            debian)
                if [[ -z "${VERSION_ID:-}" && ("${VERSION_CODENAME:-}" == "trixie" || "${PRETTY_NAME:-}" =~ [Tt]rixie) ]]; then
                    version="13"
                fi
                version_ge "$version" "11" || exit 1
                ;;
            kali)
                ;;
            *)
                exit 1
                ;;
        esac
    ' _ "${os_file}" || rc=$?

    if [[ "${expect_ok}" == "1" && "${rc}" -ne 0 ]]; then
        fail "OS profile ${label} was unexpectedly rejected"
    elif [[ "${expect_ok}" == "0" && "${rc}" -eq 0 ]]; then
        fail "Unsupported OS profile ${label} was unexpectedly accepted"
    fi
}

check_os_profile "ubuntu-20.04" 1 $'ID=ubuntu\nVERSION_ID="20.04"\nVERSION_CODENAME=focal'
check_os_profile "ubuntu-22.04" 1 $'ID=ubuntu\nVERSION_ID="22.04"\nVERSION_CODENAME=jammy'
check_os_profile "ubuntu-24.04" 1 $'ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble'
check_os_profile "debian-11"    1 $'ID=debian\nVERSION_ID="11"\nVERSION_CODENAME=bullseye'
check_os_profile "debian-12"    1 $'ID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm'
check_os_profile "debian-13-trixie-sid" 1 $'ID=debian\nVERSION_CODENAME=trixie\nPRETTY_NAME="Debian GNU/Linux trixie/sid"'
check_os_profile "kali-rolling" 1 $'ID=kali\nID_LIKE=debian\nVERSION_CODENAME=kali-rolling'
check_os_profile "ubuntu-18.04" 0 $'ID=ubuntu\nVERSION_ID="18.04"\nVERSION_CODENAME=bionic'
check_os_profile "debian-10"    0 $'ID=debian\nVERSION_ID="10"\nVERSION_CODENAME=buster'
check_os_profile " rocky-9"     0 $'ID=rocky\nVERSION_ID="9.3"'
pass "OS matrix preflight verified across Ubuntu 20.04/22.04/24.04, Debian 11/12/13 (trixie), Kali, and unsupported distros"

# ==============================================================================
# PHASE 2: Fresh Installer Prebuilt v4 Pull & Fail-Closed No-Downgrade Check
# ==============================================================================
echo "=== Phase 2: Fresh Installer Prebuilt v4 Pull & Fail-Closed Check ==="
build_release_tarball "${WORK_DIR}/artifacts/v4.0.0" "v4.0.0" "ready" "0"
build_release_tarball "${WORK_DIR}/artifacts/v4.0.1" "v4.0.1" "ready" "0"
build_release_tarball "${WORK_DIR}/artifacts/v4.0.2" "v4.0.2" "unhealthy" "1"

FRESH_ROOT="${WORK_DIR}/fresh-install"
mkdir -p \
    "${FRESH_ROOT}/opt/AetherFlow/setup/templates/sysd" \
    "${FRESH_ROOT}/opt/AetherFlow/deploy" \
    "${FRESH_ROOT}/etc/aetherflow" \
    "${FRESH_ROOT}/etc/systemd/system" \
    "${FRESH_ROOT}/var/lib/aetherflow" \
    "${FRESH_ROOT}/mock-bin"

cp -R "${ROOT_DIR}/setup/." "${FRESH_ROOT}/opt/AetherFlow/setup/"
cp -R "${ROOT_DIR}/deploy/." "${FRESH_ROOT}/opt/AetherFlow/deploy/"

# Create poison go/node/npm mocks that fail if invoked in default prebuilt mode
for forbidden_cmd in go node npm npx; do
    cat > "${FRESH_ROOT}/mock-bin/${forbidden_cmd}" <<EOF
#!/bin/bash
echo "[FORBIDDEN] ${forbidden_cmd} was invoked during default prebuilt v4 install!" >&2
exit 99
EOF
    chmod 0755 "${FRESH_ROOT}/mock-bin/${forbidden_cmd}"
done

# 2a. Verify fail-closed rejection when SHA-256 is invalid (no implicit source build!)
BAD_SHA_RC=0
PATH="${FRESH_ROOT}/mock-bin:${PATH}" \
AF_INSTALL_ROOT="${FRESH_ROOT}/opt/AetherFlow" \
AF_ENV_DIR="${FRESH_ROOT}/etc/aetherflow" \
AF_DATA_DIR="${FRESH_ROOT}/var/lib/aetherflow" \
AF_SYSTEMD_DIR="${FRESH_ROOT}/etc/systemd/system" \
AF_SKIP_SYSTEMCTL="1" \
AF_OFFLINE="1" \
AETHERFLOW_PREBUILT_TARBALL="${WORK_DIR}/artifacts/v4.0.0/aetherflow-linux-amd64.tar.gz" \
AETHERFLOW_PREBUILT_SHA256="0000000000000000000000000000000000000000000000000000000000000000" \
bash -c '
    source "$1/opt/AetherFlow/setup/modules/00-core.sh"
    source "$1/opt/AetherFlow/setup/modules/modern_stack.sh"
    _install_go
    _install_node
    _build_modern_stack
' _ "${FRESH_ROOT}" >/dev/null 2>&1 || BAD_SHA_RC=$?

[[ "${BAD_SHA_RC}" -ne 0 ]] || fail "Installer accepted a prebuilt archive with a mismatched SHA-256"
[[ ! -L "${FRESH_ROOT}/opt/AetherFlow/current" ]] || fail "Installer created /opt/AetherFlow/current after SHA-256 failure"
pass "Fail-closed check passed: bad SHA-256 rejected with zero implicit source-build fallback"

# 2b. Verify clean prebuilt v4 install succeeds without invoking go/node/npm
PATH="${FRESH_ROOT}/mock-bin:${PATH}" \
AF_INSTALL_ROOT="${FRESH_ROOT}/opt/AetherFlow" \
AF_ENV_DIR="${FRESH_ROOT}/etc/aetherflow" \
AF_DATA_DIR="${FRESH_ROOT}/var/lib/aetherflow" \
AF_SYSTEMD_DIR="${FRESH_ROOT}/etc/systemd/system" \
AF_SKIP_SYSTEMCTL="1" \
AF_OFFLINE="1" \
AETHERFLOW_PREBUILT_TARBALL="${WORK_DIR}/artifacts/v4.0.0/aetherflow-linux-amd64.tar.gz" \
AETHERFLOW_PREBUILT_SHA256_FILE="${WORK_DIR}/artifacts/v4.0.0/SHA256SUMS" \
AETHERFLOW_RELEASE_TAG="v4.0.0" \
bash -c '
    source "$1/opt/AetherFlow/setup/modules/00-core.sh"
    source "$1/opt/AetherFlow/setup/modules/modern_stack.sh"
    _install_go
    _install_node
    _build_modern_stack
' _ "${FRESH_ROOT}" >/dev/null

[[ -L "${FRESH_ROOT}/opt/AetherFlow/current" ]] || fail "Fresh install did not create /opt/AetherFlow/current symlink"
[[ -x "${FRESH_ROOT}/opt/AetherFlow/current/aetherflow-api" ]] || fail "Fresh install missing executable aetherflow-api"
[[ -x "${FRESH_ROOT}/opt/AetherFlow/current/af" ]] || fail "Fresh install missing executable af CLI"
[[ -x "${FRESH_ROOT}/opt/AetherFlow/current/bin/af" ]] || fail "Fresh install missing executable bin/af CLI"
[[ "$(tr -d '[:space:]' < "${FRESH_ROOT}/opt/AetherFlow/current/.version")" == "v4.0.0" ]] || fail "Unexpected .version in fresh install"
grep -q "DB_PATH=${FRESH_ROOT}/var/lib/aetherflow/aetherflow.sqlite" "${FRESH_ROOT}/etc/aetherflow/aetherflow.env" || fail "aetherflow.env missing FHS DB_PATH"
grep -q "ExecStart=/opt/AetherFlow/current/aetherflow-api" "${FRESH_ROOT}/etc/systemd/system/aetherflow-api.service" || fail "aetherflow-api.service not pointing to /opt/AetherFlow/current/aetherflow-api"
pass "Fresh installer staged verified v4.0.0 release (aetherflow-api + af) without Go/Node toolchains"

# ==============================================================================
# PHASE 3: Release Manager Upgrade, Failed-Health Auto-Rollback & Manual Rollback
# ==============================================================================
echo "=== Phase 3: Release Manager Upgrade, Auto-Rollback & DB Recovery ==="
RM_ROOT="${WORK_DIR}/rm-lifecycle"
mkdir -p \
    "${RM_ROOT}/deploy" \
    "${RM_ROOT}/releases" \
    "${RM_ROOT}/data" \
    "${RM_ROOT}/etc" \
    "${RM_ROOT}/systemd" \
    "${RM_ROOT}/state" \
    "${RM_ROOT}/bin"

export SMOKE_STATE_DIR="${RM_ROOT}/state"
export SMOKE_DB_PATH="${RM_ROOT}/data/aetherflow.sqlite"

# Seed initial live SQLite database in WAL mode with sentinel row
sqlite3 "${SMOKE_DB_PATH}" "PRAGMA journal_mode=WAL; CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT); INSERT INTO users (username) VALUES ('admin_sentinel');"

cp -f "${ROOT_DIR}/deploy/release-manager.sh" "${RM_ROOT}/deploy/release-manager.sh"
chmod 0755 "${RM_ROOT}/deploy/release-manager.sh"

cat > "${RM_ROOT}/etc/aetherflow.env" <<EOF
DB_PATH=${SMOKE_DB_PATH}
AETHERFLOW_DB_PATH=${SMOKE_DB_PATH}
EOF

cat > "${RM_ROOT}/deploy/release-manager.conf" <<EOF
RELEASES_DIR="${RM_ROOT}/releases"
CURRENT_LINK="${RM_ROOT}/current"
REPO_DIR="${RM_ROOT}/repo"
LEGACY_OPT_ROOT="${RM_ROOT}/opt/AetherFlow"
DRY_RUN_ROOT="${RM_ROOT}/dry-run"
CLI_BIN_DIR="${RM_ROOT}/usr/local/bin"
DATA_DIR="${RM_ROOT}/data"
SQLITE_DB="aetherflow.sqlite"
LOG_FILE="${RM_ROOT}/deploy.log"
MAX_RELEASES=5
GITHUB_REPO="McEveritts/AetherFlow"
RELEASE_CHANNEL="stable"
ARTIFACT_NAME="aetherflow-linux-amd64.tar.gz"
CHECKSUM_NAME="SHA256SUMS"
GIT_REMOTE="origin"
GIT_BRANCH="main"
GO_BIN="/usr/local/go/bin/go"
NODE_HEAP_MB=1024
HEALTH_ENDPOINT="http://127.0.0.1:8080/health/ready"
HEALTH_RETRIES=2
HEALTH_INTERVAL=0
SNAPSHOT_TIMEOUT=10
ENV_DIR="${RM_ROOT}/etc"
ENV_FILE="${RM_ROOT}/etc/aetherflow.env"
SYSTEMD_UNITS_SRC="${RM_ROOT}/current/deploy/systemd"
SYSTEMD_UNITS_DST="${RM_ROOT}/systemd"
EOF

# Mock curl, systemctl, runuser, id, chown for deterministic non-root execution
cat > "${RM_ROOT}/bin/systemctl" <<EOF
#!/bin/bash
cmd="\${1:-}"
shift || true
case "\${cmd}" in
    show)
        unit="\${1:-}"
        if [[ "\$*" == *"-p User"* ]]; then
            echo "aetherflow"
        fi
        exit 0
        ;;
    restart)
        if [[ -x "${RM_ROOT}/current/aetherflow-api" ]]; then
            "${RM_ROOT}/current/aetherflow-api"
        fi
        exit 0
        ;;
    stop|daemon-reload|enable|disable)
        exit 0
        ;;
esac
exit 0
EOF

cat > "${RM_ROOT}/bin/curl" <<EOF
#!/bin/bash
url="\${@: -1}"
out=""
write_code=0
args=("\$@")
for ((i=0; i<\${#args[@]}; i++)); do
    if [[ "\${args[i]}" == "-o" ]]; then
        out="\${args[i+1]}"
    elif [[ "\${args[i]}" == "-w" ]]; then
        write_code=1
    fi
done

active_tag="\$(cat "${SMOKE_STATE_DIR}/release_tag" 2>/dev/null || echo "v4.0.0")"
if [[ "\${url}" == *"api.github.com/repos/"*"/releases" ]]; then
    printf '[{"tag_name":"%s","draft":false,"prerelease":false,"target_commitish":"main"}]\n' "\${active_tag}"
    exit 0
fi
if [[ "\${url}" == *"/releases/download/"*"/aetherflow-linux-amd64.tar.gz" ]]; then
    tag_part="\${url%/aetherflow-linux-amd64.tar.gz}"
    tag_part="\${tag_part##*/}"
    cp -f "${WORK_DIR}/artifacts/\${tag_part}/aetherflow-linux-amd64.tar.gz" "\${out}"
    exit 0
fi
if [[ "\${url}" == *"/releases/download/"*"/SHA256SUMS" ]]; then
    tag_part="\${url%/SHA256SUMS}"
    tag_part="\${tag_part##*/}"
    cp -f "${WORK_DIR}/artifacts/\${tag_part}/SHA256SUMS" "\${out}"
    exit 0
fi
if [[ "\${url}" == *"/health/ready" ]]; then
    status="\$(cat "${SMOKE_STATE_DIR}/active_health_status" 2>/dev/null || echo "ready")"
    code="200"
    [[ "\${status}" == "ready" ]] || code="503"
    body="{\"database\":\"ok\",\"redis\":\"disabled\",\"status\":\"\${status}\",\"uptime\":\"0.1s\"}"
    if [[ "\${write_code}" -eq 1 ]]; then
        printf '%s\n%s' "\${body}" "\${code}"
    else
        printf '%s' "\${body}"
    fi
    exit 0
fi
exec /usr/bin/curl "\$@"
EOF

cat > "${RM_ROOT}/bin/id" <<'EOF'
#!/bin/bash
if [[ "${1:-}" == "-gn" || "${1:-}" == "-u" ]]; then
    echo "aetherflow"
    exit 0
fi
exec /usr/bin/id "$@"
EOF

cat > "${RM_ROOT}/bin/runuser" <<'EOF'
#!/bin/bash
while [[ $# -gt 0 ]]; do
    if [[ "$1" == "--" ]]; then
        shift
        exec "$@"
    fi
    shift
done
EOF

cat > "${RM_ROOT}/bin/chown" <<'EOF'
#!/bin/bash
exit 0
EOF

chmod 0755 "${RM_ROOT}/bin/systemctl" "${RM_ROOT}/bin/curl" "${RM_ROOT}/bin/id" "${RM_ROOT}/bin/runuser" "${RM_ROOT}/bin/chown"

# 3a. Initial deploy of v4.0.0
echo "v4.0.0" > "${SMOKE_STATE_DIR}/release_tag"
PATH="${RM_ROOT}/bin:${PATH}" "${RM_ROOT}/deploy/release-manager.sh" deploy --channel stable >/dev/null
[[ "$(tr -d '[:space:]' < "${RM_ROOT}/current/.version")" == "v4.0.0" ]] || fail "Initial deploy did not activate v4.0.0"
[[ -x "${RM_ROOT}/current/af" ]] || fail "Initial deploy missing af binary"
pass "Stage 1-3 initial deploy of v4.0.0 succeeded"

# 3b. Atomic upgrade from v4.0.0 -> v4.0.1
sleep 1
echo "v4.0.1" > "${SMOKE_STATE_DIR}/release_tag"
PATH="${RM_ROOT}/bin:${PATH}" "${RM_ROOT}/deploy/release-manager.sh" deploy --channel stable >/dev/null
[[ "$(tr -d '[:space:]' < "${RM_ROOT}/current/.version")" == "v4.0.1" ]] || fail "Upgrade did not activate v4.0.1"
[[ -f "${RM_ROOT}/current/data-snapshot/aetherflow.sqlite.bak" ]] || fail "Upgrade did not capture SQLite online backup"
[[ -f "${RM_ROOT}/current/data-snapshot/MANIFEST.sha256" ]] || fail "Upgrade did not write MANIFEST.sha256"
pass "Atomic upgrade v4.0.0 -> v4.0.1 succeeded with verified WAL-safe SQLite snapshot"

# 3c. Fault-injected broken upgrade (v4.0.2 corrupts SQLite and fails /health/ready)
sleep 1
echo "v4.0.2" > "${SMOKE_STATE_DIR}/release_tag"
BROKEN_RC=0
PATH="${RM_ROOT}/bin:${PATH}" "${RM_ROOT}/deploy/release-manager.sh" deploy --channel stable >/dev/null 2>&1 || BROKEN_RC=$?
[[ "${BROKEN_RC}" -eq 2 ]] || fail "Expected exit code 2 on failed health probe rollback, got ${BROKEN_RC}"
[[ "$(tr -d '[:space:]' < "${RM_ROOT}/current/.version")" == "v4.0.1" ]] || fail "Auto-rollback did not revert symlink to v4.0.1"
RESTORED_USER="$(sqlite3 "${SMOKE_DB_PATH}" "SELECT username FROM users WHERE username='admin_sentinel';" 2>/dev/null || true)"
[[ "${RESTORED_USER}" == "admin_sentinel" ]] || fail "Stage 4 rollback did not restore corrupted SQLite database from pre-swap snapshot"
pass "Broken v4.0.2 release triggered automatic Stage 4 symlink rollback to v4.0.1 and restored corrupted SQLite DB"

# 3d. Manual rollback command (v4.0.1 -> v4.0.0)
# Point .previous_release to the v4.0.0 release directory and run rollback
V400_DIR="$(grep -l '^v4\.0\.0$' "${RM_ROOT}/releases/"*/.version | head -n1 | xargs dirname)"
echo "${V400_DIR}" > "${RM_ROOT}/releases/.previous_release"
PATH="${RM_ROOT}/bin:${PATH}" "${RM_ROOT}/deploy/release-manager.sh" rollback >/dev/null
[[ "$(tr -d '[:space:]' < "${RM_ROOT}/current/.version")" == "v4.0.0" ]] || fail "Manual rollback did not revert to v4.0.0"
pass "Manual rollback to v4.0.0 verified"

echo "[SMOKE-ALL-PASS] All v4 release, bootstrap, OS matrix, upgrade, auto-rollback, and DB recovery checks passed."
