#!/usr/bin/env bash
set -euo pipefail

# This script provisions a Debian WSL environment for building and testing AetherFlow.
# Usage: ./scripts/setup_wsl_dev.sh

echo "==> Updating APT repositories..."
sudo apt-get update

echo "==> Installing build dependencies..."
sudo apt-get install -y build-essential curl wget git bash jq sqlite3

echo "==> Installing Go 1.22.4..."
# We use Go 1.22.4 as a stable reliable version for build.
if ! command -v go >/dev/null 2>&1 || ! go version | grep -q '1.22'; then
    echo "Downloading Go 1.22.4..."
    wget -qO- https://go.dev/dl/go1.22.4.linux-amd64.tar.gz | sudo tar -C /usr/local -xzf -
    
    if [ ! -L /usr/local/bin/go ]; then
      sudo ln -s /usr/local/go/bin/go /usr/local/bin/go
    fi
    if [ ! -L /usr/local/bin/gofmt ]; then
      sudo ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt
    fi
fi

echo "==> Installing Node.js v20..."
if ! command -v node >/dev/null 2>&1 || ! node -v | grep -q '^v20'; then
    echo "Downloading Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

echo "==> Environment Provisioned Successfully!"
echo "Go version: $(go version)"
echo "Node version: $(node -v)"
echo "NPM version: $(npm -v)"
echo ""
echo "To build the project, run:"
echo "  ./build_gold.sh"
echo "Or build manually:"
echo "  cd backend && go build -o aetherflow-api"
echo "  cd frontend && npm install && npm run build"
