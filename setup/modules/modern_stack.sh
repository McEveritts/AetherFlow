#!/bin/bash

_af_ensure_path_entry() {
    local path_entry="$1"
    local profile_line="$2"

    case ":${PATH}:" in
        *:"${path_entry}":*) ;;
        *) export PATH="${path_entry}:${PATH}" ;;
    esac

    grep -qxF "${profile_line}" /etc/profile 2>/dev/null || echo "${profile_line}" >> /etc/profile
}

_install_go() {
    # Install Go Compiler (1.22 or latest available)
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
    local node_install_dir="/usr/local/node-v${AF_NODE_VERSION}-linux-x64"
    local min_node_major=22

    # Fix #2: Enforce Node.js >= 22. If a system-installed node binary meets
    # the requirement (e.g., via APT on Kali) but /usr/local/bin/node points
    # to a stale older version, prefer the system binary and update symlinks.
    local system_node=""
    local system_node_ver=""

    # Detect system-installed node (APT typically places it in /usr/bin)
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
        # Ensure /usr/local/bin symlinks point to the correct binary
        if [[ "${system_node}" != "/usr/local/bin/node" ]]; then
            ln -sfn "${system_node}" /usr/local/bin/node
            local bin_dir
            bin_dir="$(dirname "${system_node}")"
            [[ -x "${bin_dir}/npm" ]] && ln -sfn "${bin_dir}/npm" /usr/local/bin/npm
            [[ -x "${bin_dir}/npx" ]] && ln -sfn "${bin_dir}/npx" /usr/local/bin/npx
        fi
    elif ! command -v node >/dev/null 2>&1; then
        # No node at all — install from the binary tarball
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
        # node exists but is below the minimum version — reinstall
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

    if ! command -v pm2 >/dev/null 2>&1; then
        npm install -g pm2 || return 1
    fi

    _af_cleanup_runtime_cache
}

_build_modern_stack() {
    local backend_pid=""
    local frontend_pid=""
    local have_backend=false
    local have_frontend=false

    if [ -d "/opt/AetherFlow/backend" ]; then
        have_backend=true
        (
            cd /opt/AetherFlow/backend || exit 1
            export PATH="/usr/local/go/bin:/usr/local/nodejs/bin:${PATH}"

            # go-sqlite3 requires CGO (gcc)
            _af_apt_install gcc build-essential || exit 1

            # Fix #5: Ensure backend data directory exists (not dashboard/db)
            mkdir -p /opt/AetherFlow/backend/data

            export GOOS=linux
            export GOARCH=amd64
            export CGO_ENABLED=1
            /usr/local/go/bin/go build -o aetherflow-api main.go || exit 1
            /usr/local/go/bin/go clean -cache -modcache -testcache >/dev/null 2>&1 || true
            rm -rf /tmp/go-build /root/.cache/go-build /root/go/pkg/mod "${AF_RUNTIME_CACHE_DIR}"
        ) &
        backend_pid=$!
    fi

    if [ -d "/opt/AetherFlow/frontend" ]; then
        have_frontend=true
        (
            cd /opt/AetherFlow/frontend || exit 1
            export PATH="/usr/local/nodejs/bin:${PATH}"
            npm install --no-fund --no-audit
            npm run build
        ) &
        frontend_pid=$!
    fi

    if [[ "${have_backend}" == "true" && "${have_frontend}" == "true" ]]; then
        _af_parallel_wait "${backend_pid}" "${frontend_pid}" || return 1
    elif [[ "${have_backend}" == "true" ]]; then
        wait "${backend_pid}" || return 1
    elif [[ "${have_frontend}" == "true" ]]; then
        wait "${frontend_pid}" || return 1
    fi

    # ── Create system user for systemd services ──────────────────────────
    if ! id -u aetherflow >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin aetherflow || true
    fi

    # Fix #6: chown frontend/.next so the aetherflow user can start Next.js
    if [[ "${have_frontend}" == "true" ]]; then
        chown -R aetherflow:aetherflow /opt/AetherFlow/frontend/.next 2>/dev/null || true
    fi

    # Fix #5: Ensure backend data dir is owned by the service user
    if [[ "${have_backend}" == "true" ]]; then
        chown -R aetherflow:aetherflow /opt/AetherFlow/backend/data 2>/dev/null || true
    fi

    # ── Generate cryptographic keys ──────────────────────────────────────
    # Fix #5: AES_MASTER_KEY must be exactly 32 bytes of printable ASCII
    local aes_key
    aes_key="$(head -c 32 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 32)"
    # Pad if tr reduced output below 32 chars (extremely unlikely)
    while [[ ${#aes_key} -lt 32 ]]; do
        aes_key="${aes_key}$(head -c 4 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 1)"
    done

    local jwt_secret
    jwt_secret="$(head -c 64 /dev/urandom | tr -dc 'A-Za-z0-9' | head -c 64)"

    # ── Detect host IP for ALLOWED_HOSTS / CORS ──────────────────────────
    # Fix #8: Inject the host's actual IP so HostValidationMiddleware passes
    local host_ip
    host_ip="$(ip route get 8.8.8.8 2>/dev/null | awk 'NR==1 {print $7}')"
    [[ -z "${host_ip}" ]] && host_ip="127.0.0.1"

    # ── Install systemd unit files from templates ────────────────────────
    local sysd_dir="/opt/AetherFlow/setup/templates/sysd"
    if [[ -f "${sysd_dir}/aetherflow-api.template" ]]; then
        sed -e "s|__AES_MASTER_KEY__|${aes_key}|g" \
            -e "s|__JWT_SECRET__|${jwt_secret}|g" \
            -e "s|__HOST_IP__|${host_ip}|g" \
            "${sysd_dir}/aetherflow-api.template" > /etc/systemd/system/aetherflow-api.service
    fi
    if [[ -f "${sysd_dir}/aetherflow-frontend.template" ]]; then
        cp "${sysd_dir}/aetherflow-frontend.template" /etc/systemd/system/aetherflow-frontend.service
    fi
    systemctl daemon-reload 2>/dev/null || true

    # ── Legacy PM2 start (kept for backward compat) ──────────────────────
    if [[ "${have_backend}" == "true" ]]; then
        cd /opt/AetherFlow/backend || return 1
        pm2 delete "aetherflow-api" 2>/dev/null
        pm2 start ./aetherflow-api --name "aetherflow-api" || return 1
    fi

    if [[ "${have_frontend}" == "true" ]]; then
        cd /opt/AetherFlow/frontend || return 1
        pm2 delete "aetherflow-frontend" 2>/dev/null
        pm2 start npm --name "aetherflow-frontend" -- start || return 1
    fi

    pm2 save || return 1
    pm2 startup systemd -u root --hp /root || return 1
}

