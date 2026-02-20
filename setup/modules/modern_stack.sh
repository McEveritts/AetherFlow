#!/bin/bash

_install_go() {
    # Install Go Compiler (1.21 or latest available)
    if ! command -v go &> /dev/null; then
        wget -q https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
        rm -rf /usr/local/go && tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
        export PATH=$PATH:/usr/local/go/bin
        echo "export PATH=$PATH:/usr/local/go/bin" >> /etc/profile
        rm go1.21.6.linux-amd64.tar.gz
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
    if [ -d "/opt/MediaNexus/backend" ]; then
        cd /opt/MediaNexus/backend
        export GOOS=linux
        export GOARCH=amd64
        /usr/local/go/bin/go build -o medianexus-api main.go
        
        # Start Go API via PM2
        pm2 start ./medianexus-api --name "medianexus-api"
    fi

    # Build Next.js Frontend
    if [ -d "/opt/MediaNexus/frontend" ]; then
        cd /opt/MediaNexus/frontend
        npm install
        npm run build
        
        # Start Next.js via PM2
        pm2 start npm --name "medianexus-frontend" -- start
    fi

    pm2 save
    pm2 startup systemd -u root --hp /root
}
