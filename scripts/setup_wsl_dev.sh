#!/usr/bin/env bash
set -euo pipefail

# This script provisions a Debian WSL environment for building and testing AetherFlow.
# Usage: ./scripts/setup_wsl_dev.sh

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"
export PATH="${HOME}/.cargo/bin:${PATH}"
export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-${AF_RUST_TOOLCHAIN:-1.99.1}}"
sudo_command=()
if [[ "${EUID}" -ne 0 ]]; then
    sudo_command=(sudo)
fi

echo "==> Updating APT repositories..."
"${sudo_command[@]}" apt-get update

echo "==> Installing build dependencies..."
"${sudo_command[@]}" apt-get install -y build-essential clang mold pkg-config libssl-dev libsqlite3-dev curl ca-certificates git bash jq sqlite3 python3

echo "==> Ensuring Rust and pinned WASM build tools..."
bash scripts/install_wasm_build_tools.sh --ensure

echo "==> Environment Provisioned Successfully!"
echo "Rust version: $(rustc --version)"
echo "Cargo version: $(cargo --version)"
echo ""
echo "To build the project, run:"
echo "  ./scripts/build_gold.sh"
echo "Or build manually:"
echo "  bash scripts/install_wasm_build_tools.sh --ensure"
echo '  FRONTEND_DIST_DIR="$PWD/web/dist" bash scripts/build_wasm_frontend.sh --stage'
echo '  target_dir="${CARGO_TARGET_DIR:-$PWD/backend-rs/target}"'
echo '  [[ "$target_dir" = /* ]] || target_dir="$PWD/backend-rs/$target_dir"'
echo '  CARGO_TARGET_DIR="$target_dir" cargo build --release --locked --manifest-path backend-rs/Cargo.toml --bin aetherflow-api --bin af --bin speedtest-backend --config backend-rs/.cargo/config.toml'
echo '  rm -rf "$target_dir/release/web/dist" "$target_dir/release/config"'
echo '  mkdir -p "$target_dir/release/web/dist" "$target_dir/release/bin"'
echo '  cp -a web/dist/. "$target_dir/release/web/dist/"'
echo '  cp -a config "$target_dir/release/config"'
echo '  install -m 0755 "$target_dir/release/af" "$target_dir/release/speedtest-backend" "$target_dir/release/bin/"'
echo '  # Run "$target_dir/release/aetherflow-api"; it serves "$target_dir/release/web/dist".'
