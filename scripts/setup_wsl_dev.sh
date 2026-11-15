#!/usr/bin/env bash
set -euo pipefail

# This script provisions a Debian WSL environment for building and testing AetherFlow.
# Usage: ./scripts/setup_wsl_dev.sh

echo "==> Updating APT repositories..."
sudo apt-get update

echo "==> Installing build dependencies..."
sudo apt-get install -y build-essential clang mold curl git bash jq pkg-config libssl-dev sqlite3 xz-utils ca-certificates

echo "==> Installing Rust toolchain (pinned rustup-init + SHA-256 verification)..."
if ! command -v cargo >/dev/null 2>&1; then
    AF_RUSTUP_VERSION="${AF_RUSTUP_VERSION:-1.28.1}"
    AF_RUST_TOOLCHAIN="${AF_RUST_TOOLCHAIN:-stable}"
    case "$(uname -m)" in
        x86_64|amd64)
            RUSTUP_ARCH="x86_64-unknown-linux-gnu"
            RUSTUP_SHA256="${AF_RUSTUP_SHA256:-a3339fb004c3d0bb9862ba0bce001861fe5cbde9c10d16591eb3f39ee6cd3e7f}"
            ;;
        aarch64|arm64)
            RUSTUP_ARCH="aarch64-unknown-linux-gnu"
            RUSTUP_SHA256="${AF_RUSTUP_SHA256:-c64b33db2c6b9385817ec0e49a84bcfe018ed6e328fe755c3c809580cc70ce7a}"
            ;;
        armv7l|armhf)
            RUSTUP_ARCH="armv7-unknown-linux-gnueabihf"
            RUSTUP_SHA256="${AF_RUSTUP_SHA256:-62cfed758140f94a75074fb350e287dd26d1b6c9a4d6a18616757fb344720bcb}"
            ;;
        *)
            echo "error: unsupported architecture '$(uname -m)' for automatic rustup bootstrap" >&2
            exit 1
            ;;
    esac
    RUSTUP_BIN="$(mktemp /tmp/af-rustup-init.XXXXXX)"
    trap 'rm -f "${RUSTUP_BIN:-}" "${NODE_TAR:-}"' EXIT
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
        "https://static.rust-lang.org/rustup/archive/${AF_RUSTUP_VERSION}/${RUSTUP_ARCH}/rustup-init" \
        -o "${RUSTUP_BIN}"
    printf '%s  %s\n' "${RUSTUP_SHA256}" "${RUSTUP_BIN}" | sha256sum -c -
    chmod 0700 "${RUSTUP_BIN}"
    "${RUSTUP_BIN}" -y --profile minimal --default-toolchain "${AF_RUST_TOOLCHAIN}"
    rm -f "${RUSTUP_BIN}"
    export PATH="${HOME}/.cargo/bin:${PATH}"
fi

echo "==> Installing Node.js v24 (official release tarball + SHA-256 verification)..."
if ! command -v node >/dev/null 2>&1 || ! node -v | grep -q '^v24'; then
    AF_NODE_VERSION="${AF_NODE_VERSION:-24.22.2}"
    case "$(uname -m)" in
        x86_64|amd64)
            NODE_ARCH="x64"
            NODE_SHA256="${AF_NODE_SHA256:-48cc0e21e048790e54c0cf5749c2725005313d652651c40b7a21feb9697aaf75}"
            ;;
        *)
            echo "error: set AF_NODE_SHA256 and install official Node.js v${AF_NODE_VERSION} manually on '$(uname -m)'" >&2
            exit 1
            ;;
    esac
    NODE_TAR="$(mktemp /tmp/af-node-dist.XXXXXX.tar.xz)"
    trap 'rm -f "${RUSTUP_BIN:-}" "${NODE_TAR:-}"' EXIT
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL \
        "https://nodejs.org/dist/v${AF_NODE_VERSION}/node-v${AF_NODE_VERSION}-linux-${NODE_ARCH}.tar.xz" \
        -o "${NODE_TAR}"
    printf '%s  %s\n' "${NODE_SHA256}" "${NODE_TAR}" | sha256sum -c -
    sudo tar -xJf "${NODE_TAR}" -C /usr/local
    sudo ln -sfn "/usr/local/node-v${AF_NODE_VERSION}-linux-${NODE_ARCH}/bin/node" /usr/local/bin/node
    sudo ln -sfn "/usr/local/node-v${AF_NODE_VERSION}-linux-${NODE_ARCH}/bin/npm" /usr/local/bin/npm
    sudo ln -sfn "/usr/local/node-v${AF_NODE_VERSION}-linux-${NODE_ARCH}/bin/npx" /usr/local/bin/npx
    rm -f "${NODE_TAR}"
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
