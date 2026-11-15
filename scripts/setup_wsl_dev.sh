#!/usr/bin/env bash
set -euo pipefail

# This script provisions a Debian WSL environment for building and testing AetherFlow.
# Usage: ./scripts/setup_wsl_dev.sh

echo "==> Updating APT repositories..."
sudo apt-get update

echo "==> Installing build dependencies..."
sudo apt-get install -y build-essential curl git bash jq pkg-config libssl-dev sqlite3

echo "==> Installing Rust toolchain (rustup / cargo)..."
if ! command -v cargo >/dev/null 2>&1; then
    echo "Installing rustup..."
    curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    export PATH="${HOME}/.cargo/bin:${PATH}"
fi

echo "==> Installing Node.js v24..."
if ! command -v node >/dev/null 2>&1 || ! node -v | grep -q '^v24'; then
    echo "Downloading Node.js..."
    curl -fsSL https://deb.nodesource.com/setup_24.x | sudo -E bash -
    sudo apt-get install -y nodejs
fi

echo "==> Environment Provisioned Successfully!"
echo "Rustc version: $(rustc --version)"
echo "Cargo version: $(cargo --version)"
echo "Node version: $(node -v)"
echo "NPM version: $(npm -v)"
echo ""
echo "To build the project, run:"
echo "  ./scripts/build_gold.sh"
echo "Or build manually:"
echo "  npm ci && NEXT_STATIC_EXPORT=1 npm run build --workspace frontend && rm -rf web/dist && mkdir -p web/dist && cp -R frontend/out/. web/dist/"
echo "  cd backend-rs && cargo build --release --locked --bin aetherflow-api --bin af --bin speedtest-backend"
