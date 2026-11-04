#!/bin/bash
set -e

_af_ensure_path_entry() {
    local path_entry="$1"
    local profile_line="$2"

    case ":${PATH}:" in
        *:"${path_entry}":*) ;;
        *) export PATH="${path_entry}:${PATH}" ;;
    esac

    grep -qxF "${profile_line}" /etc/profile 2>/dev/null || echo "${profile_line}" >> /etc/profile
}

_af_modern_from_source_enabled() {
    if type _af_build_from_source_enabled &>/dev/null; then
        _af_build_from_source_enabled
        return $?
    fi
    case "${AETHERFLOW_BUILD_FROM_SOURCE:-${BUILD_FROM_SOURCE:-${build_from_source:-}}}" in
        1|true|TRUE|yes|YES|y|Y|on|ON) return 0 ;;
        *) return 1 ;;
    esac
}

_af_resolve_release_channel() {
    local channel="${AETHERFLOW_RELEASE_CHANNEL:-${RELEASE_CHANNEL:-${release_channel:-}}}"
    if [[ -z "${channel}" ]] && type _load_config &>/dev/null; then
        channel="$(_load_config release_channel 2>/dev/null || true)"
    fi
    if [[ -z "${channel}" ]]; then
        local af_root="${AF_INSTALL_ROOT:-/opt/AetherFlow}"
        if command -v git >/dev/null 2>&1 && [[ -d "${af_root}/.git" ]]; then
            local branch
            branch="$(git -C "${af_root}" rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
            case "${branch,,}" in
                experimental) channel="nightly" ;;
                nightly) channel="nightly" ;;
            esac
        fi
    fi
    [[ -n "${channel}" ]] || channel="stable"
    printf '%s' "${channel}"
}

_af_is_v4_release_tag() {
    local tag="${1:-}"
    case "${tag,,}" in
        experimental|experimental-*|nightly|nightly-*|v4.*|4.*)
            return 0
            ;;
        v[0-9]*)
            local major="${tag#v}"
            major="${major%%.*}"
            [[ "${major}" =~ ^[0-9]+$ && "${major}" -ge 4 ]]
            return $?
            ;;
        *)
            return 1
            ;;
    esac
}

_install_go() {
    if ! _af_modern_from_source_enabled; then
        echo "Prebuilt v4 Rust release mode active; skipping Go compiler installation."
        return 0
    fi

    # Install Go Compiler (only when --from-source is explicitly requested)
    if ! command -v go >/dev/null 2>&1; then
        if [[ ! -s "${AF_GO_ARCHIVE}" ]]; then
            _af_prefetch_runtime_archives || return 1
        fi

        rm -rf /usr/local/go
        tar -C /usr/local -xzf "${AF_GO_ARCHIVE}" || return 1
        rm -f "${AF_GO_ARCHIVE}"
    fi

    _af_ensure_path_entry "/usr/local/go/bin" 'export PATH=/usr/local/go/bin:$PATH'
}

_install_node() {
    if ! _af_modern_from_source_enabled; then
        echo "Prebuilt v4 Rust release mode active; skipping Node.js compiler installation."
        return 0
    fi

    local node_install_dir="/usr/local/node-v${AF_NODE_VERSION}-linux-x64"
    local min_node_major=24

    # Enforce Node.js >= 24 for source builds (undici/eslint/Piped compatibility).
    local system_node=""
    local system_node_ver=""

    for candidate in /usr/bin/node /usr/local/bin/node; do
        if [[ -x "${candidate}" ]]; then
            local ver
            ver="$("${candidate}" --version 2>/dev/null | sed 's/^v//')"
            local major="${ver%%.*}"
            if [[ -n "${major}" ]] && [[ "${major}" -ge "${min_node_major}" ]]; then
                system_node="${candidate}"
                system_node_ver="${ver}"
                break
            fi
        fi
    done

    if [[ -n "${system_node}" ]]; then
        echo "System Node.js ${system_node_ver} at ${system_node} meets >= ${min_node_major} requirement."
        if [[ "${system_node}" != "/usr/local/bin/node" ]]; then
            ln -sfn "${system_node}" /usr/local/bin/node
            local bin_dir
            bin_dir="$(dirname "${system_node}")"
            [[ -x "${bin_dir}/npm" ]] && ln -sfn "${bin_dir}/npm" /usr/local/bin/npm
            [[ -x "${bin_dir}/npx" ]] && ln -sfn "${bin_dir}/npx" /usr/local/bin/npx
        fi
    elif ! command -v node >/dev/null 2>&1; then
        if [[ ! -s "${AF_NODE_ARCHIVE}" ]]; then
            _af_prefetch_runtime_archives || return 1
        fi

        rm -rf "${node_install_dir}" /usr/local/nodejs
        tar -xJf "${AF_NODE_ARCHIVE}" -C /usr/local || return 1
        ln -sfn "${node_install_dir}" /usr/local/nodejs
        ln -sfn /usr/local/nodejs/bin/node /usr/local/bin/node
        ln -sfn /usr/local/nodejs/bin/npm /usr/local/bin/npm
        ln -sfn /usr/local/nodejs/bin/npx /usr/local/bin/npx
        rm -f "${AF_NODE_ARCHIVE}"
    else
        local current_ver
        current_ver="$(node --version 2>/dev/null | sed 's/^v//')"
        local current_major="${current_ver%%.*}"
        if [[ -z "${current_major}" ]] || [[ "${current_major}" -lt "${min_node_major}" ]]; then
            echo "Installed Node.js v${current_ver} is below minimum v${min_node_major}. Upgrading..."
            if [[ ! -s "${AF_NODE_ARCHIVE}" ]]; then
                _af_prefetch_runtime_archives || return 1
            fi
            rm -rf "${node_install_dir}" /usr/local/nodejs
            tar -xJf "${AF_NODE_ARCHIVE}" -C /usr/local || return 1
            ln -sfn "${node_install_dir}" /usr/local/nodejs
            ln -sfn /usr/local/nodejs/bin/node /usr/local/bin/node
            ln -sfn /usr/local/nodejs/bin/npm /usr/local/bin/npm
            ln -sfn /usr/local/nodejs/bin/npx /usr/local/bin/npx
            rm -f "${AF_NODE_ARCHIVE}"
        fi
    fi

    _af_ensure_path_entry "/usr/local/nodejs/bin" 'export PATH=/usr/local/nodejs/bin:$PATH'

    _af_cleanup_runtime_cache
}

_validate_prebuilt_tarball() {
    local archive_path="$1"
    if command -v python3 >/dev/null 2>&1; then
        if ! python3 - "${archive_path}" <<'PY'
import pathlib, sys, tarfile

archive = sys.argv[1]
try:
    with tarfile.open(archive, "r:*") as tf:
        for member in tf.getmembers():
            name = member.name or ""
            if not (member.isfile() or member.isdir()):
                sys.stderr.write(f"[ERROR] Rejected non-regular/non-directory tar entry: {name}\n")
                sys.exit(1)
            if name.startswith("/") or name.startswith("\\"):
                sys.stderr.write(f"[ERROR] Rejected absolute tar entry path: {name}\n")
                sys.exit(1)
            if ".." in pathlib.PurePosixPath(name).parts:
                sys.stderr.write(f"[ERROR] Rejected path-traversal tar entry: {name}\n")
                sys.exit(1)
except SystemExit:
    raise
except Exception as exc:
    sys.stderr.write(f"[ERROR] Invalid tar archive {archive}: {exc}\n")
    sys.exit(1)
PY
        then
            return 1
        fi
        return 0
    fi

    local listing
    listing="$(tar -ztvf "${archive_path}" 2>/dev/null)" || return 1
    printf '%s\n' "${listing}" | awk '
        substr($1, 1, 1) !~ /^[-d]$/ { exit 1 }
        $NF ~ /^\// || $NF ~ /(^|\/)\.\.(\/|$)/ { exit 1 }
    '
}

_stage_prebuilt_release_archive() {
    local archive_path="$1"
    local sha256_manifest="${2:-}"
    local expected_sha256="${3:-}"
    local release_tag="${4:-v4.0.0}"
    local af_root="${AF_INSTALL_ROOT:-/opt/AetherFlow}"
    local releases_dir="${af_root}/releases"
    local current_link="${af_root}/current"
    local epoch
    epoch="$(date +%s)"
    local release_dir="${releases_dir}/${epoch}"
    while [[ -d "${release_dir}" ]]; do
        epoch=$((epoch + 1))
        release_dir="${releases_dir}/${epoch}"
    done

    if [[ ! -f "${archive_path}" ]]; then
        echo "[ERROR] Prebuilt release archive not found: ${archive_path}" >&2
        return 1
    fi

    local artifact_name
    artifact_name="$(basename "${archive_path}")"
    if [[ -z "${expected_sha256}" && -n "${sha256_manifest}" && -f "${sha256_manifest}" ]]; then
        expected_sha256="$(awk -v f="${artifact_name}" '$2 == f || $2 == "*"f {print tolower($1); exit}' "${sha256_manifest}")"
        if [[ -z "${expected_sha256}" ]]; then
            expected_sha256="$(awk 'NF >= 1 {print tolower($1); exit}' "${sha256_manifest}")"
        fi
    fi

    if [[ -z "${expected_sha256}" || "${#expected_sha256}" -ne 64 ]]; then
        echo "[ERROR] Missing or invalid SHA-256 digest for prebuilt release ${archive_path}. Refusing unverified binary." >&2
        return 1
    fi

    local actual_sha256
    actual_sha256="$(sha256sum "${archive_path}" | awk '{print tolower($1)}')"
    if [[ "${actual_sha256}" != "${expected_sha256,,}" ]]; then
        echo "[ERROR] SHA-256 mismatch for ${archive_path} (expected=${expected_sha256,,}, actual=${actual_sha256}). Refusing unverified binary." >&2
        return 1
    fi

    if ! _validate_prebuilt_tarball "${archive_path}"; then
        echo "[ERROR] Archive security validation failed for ${archive_path} (links, special entries, or path traversal detected)." >&2
        return 1
    fi

    mkdir -p "${release_dir}"
    if ! tar --no-same-owner --no-same-permissions --no-overwrite-dir -xzf "${archive_path}" -C "${release_dir}"; then
        echo "[ERROR] Failed to extract prebuilt release archive ${archive_path}" >&2
        rm -rf "${release_dir}"
        return 1
    fi

    if [[ -n "$(find "${release_dir}" -type l -print -quit 2>/dev/null)" ]]; then
        echo "[ERROR] Extracted release archive contains forbidden symbolic links." >&2
        rm -rf "${release_dir}"
        return 1
    fi

    if [[ ! -f "${release_dir}/aetherflow-api" || -L "${release_dir}/aetherflow-api" ]]; then
        echo "[ERROR] Extracted release archive missing regular aetherflow-api binary." >&2
        rm -rf "${release_dir}"
        return 1
    fi

    chmod 0755 "${release_dir}/aetherflow-api"
    if [[ -f "${release_dir}/af" && ! -L "${release_dir}/af" ]]; then
        chmod 0755 "${release_dir}/af"
        mkdir -p "${release_dir}/bin"
        if [[ ! -e "${release_dir}/bin/af" && ! -L "${release_dir}/bin/af" ]]; then
            cp -f "${release_dir}/af" "${release_dir}/bin/af"
        fi
        chmod 0755 "${release_dir}/bin/af"
    elif [[ -f "${release_dir}/bin/af" && ! -L "${release_dir}/bin/af" ]]; then
        chmod 0755 "${release_dir}/bin/af"
        rm -f "${release_dir}/af"
        cp -f "${release_dir}/bin/af" "${release_dir}/af"
        chmod 0755 "${release_dir}/af"
    fi

    if [[ ! -s "${release_dir}/.version" ]]; then
        printf '%s\n' "${release_tag}" > "${release_dir}/.version"
    fi

    if [[ -f "${af_root}/deploy/release-manager.sh" ]]; then
        if [[ -L "${release_dir}/deploy" || -L "${release_dir}/deploy/release-manager.sh" || -L "${release_dir}/deploy/release-manager.conf" ]]; then
            echo "[ERROR] Refusing to stage release-manager into symlinked deploy path." >&2
            rm -rf "${release_dir}"
            return 1
        fi
        mkdir -p "${release_dir}/deploy"
        rm -f "${release_dir}/deploy/release-manager.sh"
        cp -f "${af_root}/deploy/release-manager.sh" "${release_dir}/deploy/release-manager.sh"
        chmod 0755 "${release_dir}/deploy/release-manager.sh"
        if [[ -f "${af_root}/deploy/release-manager.conf" ]]; then
            rm -f "${release_dir}/deploy/release-manager.conf"
            cp -f "${af_root}/deploy/release-manager.conf" "${release_dir}/deploy/release-manager.conf"
        fi
    fi

    find "${release_dir}" -type d -exec chmod 0755 {} +
    find "${release_dir}" -type f -exec chmod a+r,go-w {} +
    chmod 0755 "${release_dir}/aetherflow-api"
    [[ -f "${release_dir}/af" ]] && chmod 0755 "${release_dir}/af"
    [[ -f "${release_dir}/bin/af" ]] && chmod 0755 "${release_dir}/bin/af"

    if [[ -L "${current_link}" ]]; then
        readlink -f "${current_link}" > "${releases_dir}/.previous_release" 2>/dev/null || true
    fi

    local tmp_link="${current_link}.tmp.${epoch}"
    ln -s "${release_dir}" "${tmp_link}"
    mv -Tf "${tmp_link}" "${current_link}"

    # Maintain legacy path compatibility symlink for callers expecting /opt/AetherFlow/backend/aetherflow-api
    mkdir -p "${af_root}/backend"
    ln -sfn "${current_link}/aetherflow-api" "${af_root}/backend/aetherflow-api"
    if [[ -x "${current_link}/af" ]]; then
        ln -sfn "${current_link}/af" "${af_root}/backend/af"
        if [[ "${AF_SKIP_SYSTEMCTL:-0}" != "1" && -d /usr/local/bin && ! -f /usr/local/bin/AetherFlow/system/af ]]; then
            ln -sfn "${current_link}/af" /usr/local/bin/af
        fi
    fi
    return 0
}

_pull_prebuilt_v4_release() {
    local af_root="${AF_INSTALL_ROOT:-/opt/AetherFlow}"
    local channel
    channel="$(_af_resolve_release_channel)"
    local github_repo="${GITHUB_REPO:-McEveritts/AetherFlow}"
    local artifact_name="${ARTIFACT_NAME:-aetherflow-linux-amd64.tar.gz}"
    local checksum_name="${CHECKSUM_NAME:-SHA256SUMS}"

    if [[ -n "${AETHERFLOW_PREBUILT_TARBALL:-}" ]]; then
        local staged_tag="${AETHERFLOW_RELEASE_TAG:-v4.0.0-${channel}}"
        if ! _af_is_v4_release_tag "${staged_tag}"; then
            echo "[ERROR] Refusing pre-v4 release tag '${staged_tag}' (implicit v3 downgrade is forbidden)." >&2
            return 1
        fi
        _stage_prebuilt_release_archive \
            "${AETHERFLOW_PREBUILT_TARBALL}" \
            "${AETHERFLOW_PREBUILT_SHA256_FILE:-}" \
            "${AETHERFLOW_PREBUILT_SHA256:-}" \
            "${staged_tag}"
        return $?
    fi

    local target_tag="${AETHERFLOW_RELEASE_TAG:-}"
    if [[ -n "${target_tag}" ]] && ! _af_is_v4_release_tag "${target_tag}"; then
        echo "[ERROR] Refusing pre-v4 release tag '${target_tag}' (implicit v3 downgrade is forbidden)." >&2
        return 1
    fi

    if [[ -z "${target_tag}" ]]; then
        local api_url="https://api.github.com/repos/${github_repo}/releases"
        local releases_json=""
        releases_json="$(curl -sfL --max-time 15 "${api_url}" 2>/dev/null || true)"

        if [[ "${channel}" == "nightly" ]]; then
            if [[ -n "${releases_json}" ]] && command -v python3 >/dev/null 2>&1; then
                target_tag="$(printf '%s' "${releases_json}" | python3 -c '
import json, sys
try:
    for r in json.load(sys.stdin):
        if r.get("draft"):
            continue
        tag = (r.get("tag_name") or "").strip()
        target = (r.get("target_commitish") or "").strip().lower()
        if tag and tag.lower() not in ("nightly", "experimental") and target != "experimental" and "experimental" not in tag.lower() and (target == "nightly" or r.get("prerelease") or "nightly" in tag.lower()):
            if tag.startswith("v4.") or "v4" in tag.lower():
                print(tag)
                break
except Exception:
    pass
' 2>/dev/null || true)"
            fi
            [[ -n "${target_tag}" ]] || target_tag="nightly"
        else
            if [[ -n "${releases_json}" ]] && command -v python3 >/dev/null 2>&1; then
                target_tag="$(printf '%s' "${releases_json}" | python3 -c '
import json, sys
try:
    releases = json.load(sys.stdin)
    for r in releases:
        if r.get("draft") or r.get("prerelease"):
            continue
        tag = (r.get("tag_name") or "").strip()
        target = (r.get("target_commitish") or "").strip().lower()
        if tag.startswith("v") and "-" not in tag and target not in ("nightly", "experimental"):
            major = int(tag.lstrip("v").split(".", 1)[0])
            if major >= 4:
                print(tag)
                sys.exit(0)
except Exception:
    pass
' 2>/dev/null || true)"
            fi
            if [[ -z "${target_tag}" ]]; then
                local latest_url
                latest_url="$(curl -fsSL --max-time 15 -o /dev/null -w '%{url_effective}' "https://github.com/${github_repo}/releases/latest" 2>/dev/null || true)"
                local candidate_tag="${latest_url##*/}"
                if [[ "${latest_url}" == "https://github.com/${github_repo}/releases/tag/"* ]] && _af_is_v4_release_tag "${candidate_tag}"; then
                    target_tag="${candidate_tag}"
                fi
            fi
        fi
    fi

    if [[ -z "${target_tag}" ]] || ! _af_is_v4_release_tag "${target_tag}"; then
        echo "[ERROR] Unable to resolve a verified v4 release tag for channel '${channel}' (got '${target_tag:-none}'). Refusing implicit v3 downgrade or source-build fallback." >&2
        return 1
    fi

    local base_url="${AETHERFLOW_RELEASE_BASE_URL:-https://github.com/${github_repo}/releases/download/${target_tag}}"
    local tmp_base="${TMPDIR:-/var/tmp}"
    [[ -d "${tmp_base}" && -w "${tmp_base}" ]] || tmp_base="/tmp"
    local dl_dir
    dl_dir="$(mktemp -d "${tmp_base}/af-prebuilt-XXXXXX")"

    if ! curl -fsSL --retry 3 --max-time 180 -o "${dl_dir}/${artifact_name}" "${base_url}/${artifact_name}"; then
        echo "[ERROR] Failed to download prebuilt v4 release ${base_url}/${artifact_name}. Refusing implicit source-build fallback." >&2
        rm -rf "${dl_dir}"
        return 1
    fi

    if ! curl -fsSL --retry 3 --max-time 30 -o "${dl_dir}/${checksum_name}" "${base_url}/${checksum_name}"; then
        echo "[ERROR] Failed to download SHA-256 manifest ${base_url}/${checksum_name}. Refusing unverified binary." >&2
        rm -rf "${dl_dir}"
        return 1
    fi

    if ! _stage_prebuilt_release_archive "${dl_dir}/${artifact_name}" "${dl_dir}/${checksum_name}" "${AETHERFLOW_PREBUILT_SHA256:-}" "${target_tag}"; then
        rm -rf "${dl_dir}"
        return 1
    fi

    rm -rf "${dl_dir}"
    return 0
}

_build_modern_stack_from_source() {
    local af_root="${AF_INSTALL_ROOT:-/opt/AetherFlow}"
    local have_backend=false

    # ── Build Frontend with Static Export ─────────────────────────────────
    if [ -d "${af_root}/frontend" ]; then
        local frontend_build_log="${TMPDIR:-/var/tmp}/aetherflow-frontend-build.log"
        (
            cd "${af_root}/frontend" || exit 1
            export PATH="/usr/local/nodejs/bin:${PATH}"
            export NODE_OPTIONS="${NODE_OPTIONS:+${NODE_OPTIONS} }--max-old-space-size=1024"
            export NEXT_STATIC_EXPORT=1

            echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting npm install ..." >> "${frontend_build_log}" 2>&1
            if ! npm install --no-fund --no-audit >> "${frontend_build_log}" 2>&1; then
                echo "[FAIL] npm install failed. See ${frontend_build_log}" >&2
                exit 1
            fi

            chmod 755 "${af_root}"/node_modules/.bin/* "${af_root}"/frontend/node_modules/.bin/* 2>/dev/null || true
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting Next.js static export build ..." >> "${frontend_build_log}" 2>&1
            if ! NEXT_STATIC_EXPORT=1 npm run build >> "${frontend_build_log}" 2>&1; then
                echo "[FAIL] npm run build failed. See ${frontend_build_log}" >&2
                exit 1
            fi
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] Frontend build completed successfully." >> "${frontend_build_log}" 2>&1
        ) || {
            echo ""
            echo "══════════════════════════════════════════════════════════"
            echo "  Frontend build failed. Dumping last 50 lines of log:"
            echo "══════════════════════════════════════════════════════════"
            tail -n 50 "${frontend_build_log}" 2>/dev/null || true
            echo "══════════════════════════════════════════════════════════"
            return 1
        }

        # Populate both neutral web/dist and legacy backend/web/dist for single-binary embedding
        mkdir -p "${af_root}/web/dist" "${af_root}/backend/web/dist"
        rm -rf "${af_root}/web/dist/"* "${af_root}/backend/web/dist/"*
        if [ -d "${af_root}/frontend/out" ]; then
            cp -r "${af_root}/frontend/out/"* "${af_root}/web/dist/"
            cp -r "${af_root}/frontend/out/"* "${af_root}/backend/web/dist/"
        fi
    fi

    # ── Compile Single Binary with Embedded UI Assets (Rust preferred, Go explicit fallback) ──
    local epoch
    epoch="$(date +%s)"
    local release_dir="${af_root}/releases/${epoch}"
    mkdir -p "${release_dir}"

    if [ -d "${af_root}/backend-rs" ] && command -v cargo >/dev/null 2>&1; then
        have_backend=true
        (
            cd "${af_root}/backend-rs" || exit 1
            local -a locked_args=(--locked)
            if [[ ! -f "${af_root}/backend-rs/Cargo.lock" ]]; then
                if [[ "${CARGO_ALLOW_UNLOCKED_DEV:-0}" == "1" ]]; then
                    locked_args=()
                else
                    echo "[ERROR] Missing ${af_root}/backend-rs/Cargo.lock. Refusing unlocked source build." >&2
                    exit 1
                fi
            fi
            cargo build --release "${locked_args[@]}" --bin aetherflow-api --bin af || exit 1
            cp -f "${af_root}/backend-rs/target/release/aetherflow-api" "${release_dir}/aetherflow-api"
            if [[ -f "${af_root}/backend-rs/target/release/af" ]]; then
                cp -f "${af_root}/backend-rs/target/release/af" "${release_dir}/af"
                mkdir -p "${release_dir}/bin"
                cp -f "${af_root}/backend-rs/target/release/af" "${release_dir}/bin/af"
            fi
        ) || {
            rm -rf "${release_dir}"
            echo "Rust backend compilation failed." >&2
            return 1
        }
    elif [ -d "${af_root}/backend" ]; then
        have_backend=true
        (
            cd "${af_root}/backend" || exit 1
            export PATH="/usr/local/go/bin:/usr/local/nodejs/bin:${PATH}"

            # go-sqlite3 requires CGO (gcc)
            _af_apt_install gcc build-essential || exit 1

            mkdir -p "${af_root}/backend/data"

            export GOOS=linux
            export GOARCH=amd64
            export CGO_ENABLED=1
            /usr/local/go/bin/go build -o aetherflow-api main.go || exit 1
            cp -f "${af_root}/backend/aetherflow-api" "${release_dir}/aetherflow-api"
            /usr/local/go/bin/go clean -cache -modcache -testcache >/dev/null 2>&1 || true
            rm -rf /tmp/go-build /root/.cache/go-build /root/go/pkg/mod "${AF_RUNTIME_CACHE_DIR}"
        ) || {
            rm -rf "${release_dir}"
            echo "Backend compilation failed." >&2
            return 1
        }
    fi

    if [[ "${have_backend}" != "true" ]]; then
        rm -rf "${release_dir}"
        echo "[ERROR] No backend source directory found under ${af_root}." >&2
        return 1
    fi

    [[ -d "${af_root}/config" ]] && cp -R "${af_root}/config" "${release_dir}/config"
    [[ ! -d "${release_dir}/config" && -d "${af_root}/backend/config" ]] && cp -R "${af_root}/backend/config" "${release_dir}/config"
    [[ -d "${af_root}/packages" ]] && cp -R "${af_root}/packages" "${release_dir}/packages"
    [[ -d "${af_root}/deploy" ]] && cp -R "${af_root}/deploy" "${release_dir}/deploy"
    printf 'source-%s\n' "${epoch}" > "${release_dir}/.version"
    chmod 0755 "${release_dir}/aetherflow-api"
    [[ -f "${release_dir}/af" ]] && chmod 0755 "${release_dir}/af"
    [[ -f "${release_dir}/bin/af" ]] && chmod 0755 "${release_dir}/bin/af"

    ln -sfn "${release_dir}" "${af_root}/current"
    mkdir -p "${af_root}/backend"
    ln -sfn "${af_root}/current/aetherflow-api" "${af_root}/backend/aetherflow-api"
    return 0
}

_build_modern_stack() {
    local af_root="${AF_INSTALL_ROOT:-/opt/AetherFlow}"
    local env_dir="${AF_ENV_DIR:-/etc/aetherflow}"
    local data_dir="${AF_DATA_DIR:-/var/lib/aetherflow}"
    local sysd_dst="${AF_SYSTEMD_DIR:-/etc/systemd/system}"

    if _af_modern_from_source_enabled; then
        echo "Explicit --from-source mode enabled: compiling control plane from source..."
        _build_modern_stack_from_source || return 1
    else
        echo "Pulling verified prebuilt v4 Rust release (channel: $(_af_resolve_release_channel))..."
        if ! _pull_prebuilt_v4_release; then
            echo "[FATAL] Prebuilt v4 Rust release pull failed. Refusing implicit source-build or legacy v3 downgrade (pass --from-source to explicitly compile from source)." >&2
            return 1
        fi
    fi

    # ── Create system user for systemd services ──────────────────────────
    if [[ "${AF_SKIP_SYSTEMCTL:-0}" != "1" ]]; then
        if ! id -u aetherflow >/dev/null 2>&1; then
            useradd --system --no-create-home --shell /usr/sbin/nologin aetherflow || true
        fi
        usermod -a -G systemd-journal,adm aetherflow 2>/dev/null || true
    fi

    # Enforce Least-Privilege Boundary: Remove legacy sudoers permissions
    rm -f /etc/sudoers.d/aether* 2>/dev/null || true

    # Ensure FHS data dir and legacy backend data dir exist
    mkdir -p "${data_dir}" "${af_root}/backend/data" /run/aetherflow 2>/dev/null || true
    if [[ "${AF_SKIP_SYSTEMCTL:-0}" != "1" ]]; then
        chown -R aetherflow:aetherflow "${data_dir}" "${af_root}/backend/data" 2>/dev/null || true
        chown root:aetherflow /run/aetherflow 2>/dev/null || true
    fi
    chmod 0700 "${data_dir}" 2>/dev/null || true
    chmod 1770 /run/aetherflow 2>/dev/null || true

    # ── Generate cryptographic keys ───────────────────────────────────────
    local aes_key
    aes_key="$(head -c 32 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 32)"
    while [[ ${#aes_key} -lt 32 ]]; do
        aes_key="${aes_key}$(head -c 4 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 1)"
    done

    local jwt_secret
    jwt_secret="$(head -c 64 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 64)"

    # ── Detect host IPs for ALLOWED_HOSTS / CORS ──────────────────────────
    local host_ip
    host_ip="$(ip route get 8.8.8.8 2>/dev/null | awk 'NR==1 {print $7}')"
    [[ -z "${host_ip}" ]] && host_ip="127.0.0.1"

    local public_ip=""
    if [[ "${AF_OFFLINE:-0}" != "1" ]]; then
        public_ip="$(curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    fi
    if [[ -n "${public_ip}" ]]; then
        echo "Detected public IP: ${public_ip}"
    fi
    if [[ "${public_ip}" == "${host_ip}" ]]; then
        public_ip=""
    fi

    # ── Hardened Environment File (/etc/aetherflow/aetherflow.env) ────────
    mkdir -p "${env_dir}"
    chmod 0750 "${env_dir}"
    if [[ "${AF_SKIP_SYSTEMCTL:-0}" != "1" ]]; then
        chown root:aetherflow "${env_dir}" 2>/dev/null || true
    fi

    local saved_domain=""
    if type _load_config &>/dev/null; then
        saved_domain="$(_load_config hostname_value)"
        if [[ -z "${saved_domain}" ]]; then
            saved_domain="$(_load_config domain)"
        fi
    fi
    if [[ -z "${saved_domain}" ]]; then
        saved_domain="${AETHERFLOW_BASE_DOMAIN:-${AETHERFLOW_DOMAIN:-}}"
    fi
    if [[ "${saved_domain}" == "localhost" || "${saved_domain}" == *.local ]]; then
        saved_domain=""
    fi

    local cors_origins="http://localhost:8080,http://127.0.0.1:8080,https://localhost,https://127.0.0.1"
    local allowed_hosts="localhost,localhost:8080,127.0.0.1,127.0.0.1:8080"
    if [[ -n "${host_ip}" && "${host_ip}" != "127.0.0.1" ]]; then
        cors_origins="${cors_origins},http://${host_ip}:8080,https://${host_ip},http://${host_ip}"
        allowed_hosts="${allowed_hosts},${host_ip},${host_ip}:8080"
    fi
    if [[ -n "${public_ip}" ]]; then
        cors_origins="${cors_origins},http://${public_ip}:8080,https://${public_ip},http://${public_ip}"
        allowed_hosts="${allowed_hosts},${public_ip},${public_ip}:8080"
    fi
    if [[ -n "${saved_domain}" ]]; then
        cors_origins="${cors_origins},http://${saved_domain}:8080,https://${saved_domain},http://${saved_domain}"
        allowed_hosts="${allowed_hosts},${saved_domain},${saved_domain}:8080"
    fi

    cat > "${env_dir}/aetherflow.env" <<EOF
AES_MASTER_KEY=${aes_key}
JWT_SECRET=${jwt_secret}
PORT=8080
BIND_ADDR=0.0.0.0
ALLOWED_HOSTS=${allowed_hosts}
ALLOWED_CORS_ORIGIN=${cors_origins}
AETHERFLOW_BASE_DOMAIN=${saved_domain}
DB_PATH=${data_dir}/aetherflow.sqlite
AETHERFLOW_DB_PATH=${data_dir}/aetherflow.sqlite
AETHERFLOW_RUNNER_SOCK=/run/aetherflow/runner.sock
PRIVILEGED_RUNNER_ENABLED=true
COOKIE_SECURE=false
GIN_MODE=release
EOF
    chmod 0640 "${env_dir}/aetherflow.env"
    if [[ "${AF_SKIP_SYSTEMCTL:-0}" != "1" ]]; then
        chown root:aetherflow "${env_dir}/aetherflow.env" 2>/dev/null || true
    fi

    # ── Install systemd unit files from templates ────────────────────────
    local sysd_dir="${af_root}/setup/templates/sysd"
    mkdir -p "${sysd_dst}"
    if [[ -f "${sysd_dir}/aetherflow-runner.template" ]]; then
        if type _safe_overlay_config &>/dev/null; then
            _safe_overlay_config "${sysd_dir}/aetherflow-runner.template" "${sysd_dst}/aetherflow-runner.service"
        else
            cp "${sysd_dir}/aetherflow-runner.template" "${sysd_dst}/aetherflow-runner.service"
            sha256sum "${sysd_dst}/aetherflow-runner.service" | awk '{print $1}' > "${sysd_dst}/aetherflow-runner.service.aetherflow-sha256"
        fi
    fi
    if [[ -f "${sysd_dir}/aetherflow-api.template" ]]; then
        if type _safe_overlay_config &>/dev/null; then
            _safe_overlay_config "${sysd_dir}/aetherflow-api.template" "${sysd_dst}/aetherflow-api.service"
        else
            cp "${sysd_dir}/aetherflow-api.template" "${sysd_dst}/aetherflow-api.service"
            sha256sum "${sysd_dst}/aetherflow-api.service" | awk '{print $1}' > "${sysd_dst}/aetherflow-api.service.aetherflow-sha256"
        fi
    fi
    if [[ -f "${sysd_dir}/af-certbot-sync.service" ]]; then
        cp -f "${sysd_dir}/af-certbot-sync.service" "${sysd_dst}/af-certbot-sync.service"
    fi
    if [[ -f "${sysd_dir}/af-certbot-sync.timer" ]]; then
        cp -f "${sysd_dir}/af-certbot-sync.timer" "${sysd_dst}/af-certbot-sync.timer"
    fi

    # Purge legacy frontend service unit if present
    rm -f "${sysd_dst}"/aetherflow-front*.service 2>/dev/null || true

    if [[ "${AF_SKIP_SYSTEMCTL:-0}" != "1" ]]; then
        systemctl daemon-reload 2>/dev/null || true

        # Clean up any legacy PM2 processes
        if command -v pm2 >/dev/null 2>&1; then
            pm2 delete "aetherflow-api" "aetherflow-frontend" 2>/dev/null || true
            pm2 save 2>/dev/null || true
        fi

        # Enable modern systemd units
        systemctl enable aetherflow-runner.service >/dev/null 2>&1 || true
        systemctl enable aetherflow-api.service >/dev/null 2>&1 || true
        systemctl enable --now af-certbot-sync.timer >/dev/null 2>&1 || true
    fi
}
