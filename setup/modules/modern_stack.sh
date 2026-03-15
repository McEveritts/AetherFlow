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

    # Install Node.js from the official Linux binary tarball.
    if ! command -v node >/dev/null 2>&1; then
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

            # Ensure database directory exists
            mkdir -p /opt/AetherFlow/dashboard/db

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
