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

    _af_cleanup_runtime_cache
}

_build_modern_stack() {
    local have_backend=false
    local have_frontend=false

    # ── Build Frontend with Static Export ────────────────────────────────
    if [ -d "/opt/AetherFlow/frontend" ]; then
        have_frontend=true
        local frontend_build_log="/tmp/aetherflow-frontend-build.log"
        (
            cd /opt/AetherFlow/frontend || exit 1
            export PATH="/usr/local/nodejs/bin:${PATH}"
            # Increase heap for low-memory VMs (default V8 limit can OOM on 1GB boxes)
            export NODE_OPTIONS="${NODE_OPTIONS:+${NODE_OPTIONS} }--max-old-space-size=1024"
            export NEXT_STATIC_EXPORT=1

            echo "[$(date '+%Y-%m-%d %H:%M:%S')] Starting npm install ..." >> "${frontend_build_log}" 2>&1
            if ! npm install --no-fund --no-audit >> "${frontend_build_log}" 2>&1; then
                echo "[FAIL] npm install failed. See ${frontend_build_log}" >&2
                exit 1
            fi

            chmod 755 /opt/AetherFlow/node_modules/.bin/* /opt/AetherFlow/frontend/node_modules/.bin/* 2>/dev/null || true
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

        # Populate backend/web/dist for single-binary embedding
        mkdir -p /opt/AetherFlow/backend/web/dist
        rm -rf /opt/AetherFlow/backend/web/dist/*
        if [ -d "/opt/AetherFlow/frontend/out" ]; then
            cp -r /opt/AetherFlow/frontend/out/* /opt/AetherFlow/backend/web/dist/
        fi
    fi

    # ── Compile Go Single Binary with Embedded UI Assets ─────────────────
    if [ -d "/opt/AetherFlow/backend" ]; then
        have_backend=true
        (
            cd /opt/AetherFlow/backend || exit 1
            export PATH="/usr/local/go/bin:/usr/local/nodejs/bin:${PATH}"

            # go-sqlite3 requires CGO (gcc)
            _af_apt_install gcc build-essential || exit 1

            mkdir -p /opt/AetherFlow/backend/data

            export GOOS=linux
            export GOARCH=amd64
            export CGO_ENABLED=1
            /usr/local/go/bin/go build -o aetherflow-api main.go || exit 1
            /usr/local/go/bin/go clean -cache -modcache -testcache >/dev/null 2>&1 || true
            rm -rf /tmp/go-build /root/.cache/go-build /root/go/pkg/mod "${AF_RUNTIME_CACHE_DIR}"
        ) || {
            echo "Backend compilation failed." >&2
            return 1
        }
    fi

    # ── Create system user for systemd services ──────────────────────────
    if ! id -u aetherflow >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin aetherflow || true
    fi
    usermod -a -G systemd-journal,adm aetherflow 2>/dev/null || true

    # Enforce Least-Privilege Boundary: Remove legacy sudoers permissions
    rm -f /etc/sudoers.d/aether* 2>/dev/null || true

    # Ensure backend data dir is owned by the service user
    if [[ "${have_backend}" == "true" ]]; then
        chown -R aetherflow:aetherflow /opt/AetherFlow/backend/data 2>/dev/null || true
    fi

    # ── Generate cryptographic keys ──────────────────────────────────────
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
    public_ip="$(curl -4 -s --max-time 5 https://api.ipify.org 2>/dev/null || true)"
    if [[ -n "${public_ip}" ]]; then
        echo "Detected public IP: ${public_ip}"
    fi
    if [[ "${public_ip}" == "${host_ip}" ]]; then
        public_ip=""
    fi

    # ── Hardened Environment File (/etc/aetherflow/aetherflow.env) ────────
    mkdir -p /etc/aetherflow
    chmod 0750 /etc/aetherflow
    chown root:aetherflow /etc/aetherflow 2>/dev/null || true

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

    cat > /etc/aetherflow/aetherflow.env <<EOF
AES_MASTER_KEY=${aes_key}
JWT_SECRET=${jwt_secret}
PORT=8080
BIND_ADDR=0.0.0.0
ALLOWED_HOSTS=${allowed_hosts}
ALLOWED_CORS_ORIGIN=${cors_origins}
AETHERFLOW_BASE_DOMAIN=${saved_domain}
DB_PATH=/opt/AetherFlow/backend/data/aetherflow.sqlite
AETHERFLOW_DB_PATH=/opt/AetherFlow/backend/data/aetherflow.sqlite
AETHERFLOW_RUNNER_SOCK=/run/aetherflow/runner.sock
PRIVILEGED_RUNNER_ENABLED=true
COOKIE_SECURE=false
GIN_MODE=release
EOF
    chmod 0640 /etc/aetherflow/aetherflow.env
    chown root:aetherflow /etc/aetherflow/aetherflow.env 2>/dev/null || true

    # ── Install systemd unit files from templates ────────────────────────
    local sysd_dir="/opt/AetherFlow/setup/templates/sysd"
    if [[ -f "${sysd_dir}/aetherflow-runner.template" ]]; then
        if type _safe_overlay_config &>/dev/null; then
            _safe_overlay_config "${sysd_dir}/aetherflow-runner.template" /etc/systemd/system/aetherflow-runner.service
        else
            cp "${sysd_dir}/aetherflow-runner.template" /etc/systemd/system/aetherflow-runner.service
            sha256sum /etc/systemd/system/aetherflow-runner.service | awk '{print $1}' > /etc/systemd/system/aetherflow-runner.service.aetherflow-sha256
        fi
    fi
    if [[ -f "${sysd_dir}/aetherflow-api.template" ]]; then
        if type _safe_overlay_config &>/dev/null; then
            _safe_overlay_config "${sysd_dir}/aetherflow-api.template" /etc/systemd/system/aetherflow-api.service
        else
            cp "${sysd_dir}/aetherflow-api.template" /etc/systemd/system/aetherflow-api.service
            sha256sum /etc/systemd/system/aetherflow-api.service | awk '{print $1}' > /etc/systemd/system/aetherflow-api.service.aetherflow-sha256
        fi
    fi
    if [[ -f "${sysd_dir}/af-certbot-sync.service" ]]; then
        cp -f "${sysd_dir}/af-certbot-sync.service" /etc/systemd/system/af-certbot-sync.service
    fi
    if [[ -f "${sysd_dir}/af-certbot-sync.timer" ]]; then
        cp -f "${sysd_dir}/af-certbot-sync.timer" /etc/systemd/system/af-certbot-sync.timer
    fi

    # Purge legacy frontend service unit if present
    rm -f /etc/systemd/system/aetherflow-front*.service 2>/dev/null || true
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
}

