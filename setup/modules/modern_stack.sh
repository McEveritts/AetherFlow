#!/bin/bash

_install_go() {
    # Install Go Compiler (1.22 or latest available)
    if ! command -v go &> /dev/null; then
        wget -q https://go.dev/dl/go1.25.0.linux-amd64.tar.gz
        rm -rf /usr/local/go && tar -C /usr/local -xzf go1.25.0.linux-amd64.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo "export PATH=\$PATH:/usr/local/go/bin" >> /etc/profile
        rm go1.25.0.linux-amd64.tar.gz
    fi
}

_install_node() {
    # Install Node.js (v20 LTS via NodeSource)
    if ! command -v node &> /dev/null; then
        curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
        apt-get install -y nodejs
    fi
    if ! command -v pm2 &> /dev/null; then
        npm install -g pm2
    fi
}

_build_modern_stack() {
    # Compile Go API
    if [ -d "/opt/AetherFlow/backend" ]; then
        cd /opt/AetherFlow/backend
        export GOOS=linux
        export GOARCH=amd64
        /usr/local/go/bin/go build -o aetherflow-api main.go
        
        # Start Go API via PM2
        pm2 start ./aetherflow-api --name "aetherflow-api"
    fi

    # Build Next.js Frontend
    if [ -d "/opt/AetherFlow/frontend" ]; then
        cd /opt/AetherFlow/frontend
        npm install
        npm run build
        
        # Start Next.js via PM2
        pm2 start npm --name "aetherflow-frontend" -- start
    fi

    pm2 save
    pm2 startup systemd -u root --hp /root
}
