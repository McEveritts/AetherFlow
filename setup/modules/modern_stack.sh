#!/bin/bash

_install_go() {
    # Install Go Compiler (1.22 or latest available)
    if ! command -v go &> /dev/null; then
        wget -q https://go.dev/dl/go1.25.0.linux-amd64.tar.gz || return 1
        rm -rf /usr/local/go && tar -C /usr/local -xzf go1.25.0.linux-amd64.tar.gz || return 1
        export PATH=$PATH:/usr/local/go/bin
        echo "export PATH=\$PATH:/usr/local/go/bin" >> /etc/profile
        rm go1.25.0.linux-amd64.tar.gz
    fi
}

_install_node() {
    # Install Node.js (v20 LTS via NodeSource)
    if ! command -v node &> /dev/null; then
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash - || return 1
        apt-get install -y nodejs || return 1
    fi
    if ! command -v pm2 &> /dev/null; then
        npm install -g pm2 || return 1
    fi
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

            # go-sqlite3 requires CGO (gcc)
            apt-get install -y gcc build-essential >>/dev/null 2>&1

            # Ensure database directory exists
            mkdir -p /opt/AetherFlow/dashboard/db

            export GOOS=linux
            export GOARCH=amd64
            export CGO_ENABLED=1
            /usr/local/go/bin/go build -o aetherflow-api main.go
        ) &
        backend_pid=$!
    fi

    if [ -d "/opt/AetherFlow/frontend" ]; then
        have_frontend=true
        (
            cd /opt/AetherFlow/frontend || exit 1
            npm install
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
    pm2 startup systemd -u root --hp /root
}
