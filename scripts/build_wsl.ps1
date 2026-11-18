# Helper script to build and test AetherFlow using WSL Debian

$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

function Invoke-WslBuild {
    param([string]$Command)
    wsl -d Debian -- bash -lc ('export PATH="$HOME/.cargo/bin:$PATH"; export RUSTUP_TOOLCHAIN="${RUSTUP_TOOLCHAIN:-${AF_RUST_TOOLCHAIN:-1.99.1}}"; ' + $Command)
    if ($LASTEXITCODE -ne 0) {
        throw "WSL build step failed with exit code $LASTEXITCODE"
    }
}

Write-Host "============================================="
Write-Host "    AetherFlow WSL Debian Build Helper      "
Write-Host "============================================="
Write-Host ""

# Check if WSL Debian is available
$wslList = wsl -l -v
if ($wslList -notmatch "Debian") {
    Write-Error "WSL Debian distribution not found! Please install it first using: wsl --install -d Debian"
    exit 1
}

Write-Host "1. Provisioning WSL Debian Environment (if needed)..."
Invoke-WslBuild 'bash scripts/setup_wsl_dev.sh'

Write-Host ""
Write-Host "2. Building and Staging Rust WASM Frontend..."
Invoke-WslBuild 'bash scripts/install_wasm_build_tools.sh --ensure && FRONTEND_DIST_DIR="$PWD/web/dist" bash scripts/build_wasm_frontend.sh --stage'

Write-Host ""
Write-Host "3. Running Rust Tests..."
Invoke-WslBuild '(cd backend-rs && cargo test --locked --workspace) && (cd frontend-rs && cargo test --locked --workspace)'

Write-Host ""
Write-Host "4. Building Rust Backend and Staging External Frontend..."
Invoke-WslBuild @'
set -euo pipefail
target_dir="${CARGO_TARGET_DIR:-$PWD/backend-rs/target}"
[[ "$target_dir" = /* ]] || target_dir="$PWD/backend-rs/$target_dir"
CARGO_TARGET_DIR="$target_dir" cargo build --release --locked --manifest-path backend-rs/Cargo.toml --bin aetherflow-api --bin af --bin speedtest-backend --config backend-rs/.cargo/config.toml
test -x "$target_dir/release/speedtest-backend"
test -s web/dist/index.html
test -n "$(find web/dist -type f -name '*.wasm' -size +0c -print -quit)"
rm -rf "$target_dir/release/web/dist" "$target_dir/release/config"
mkdir -p "$target_dir/release/web/dist" "$target_dir/release/bin"
install -m 0755 "$target_dir/release/af" "$target_dir/release/speedtest-backend" "$target_dir/release/bin/"
cp -a web/dist/. "$target_dir/release/web/dist/"
cp -a config "$target_dir/release/config"
test -s "$target_dir/release/web/dist/index.html"
test -n "$(find "$target_dir/release/web/dist" -type f -name '*.wasm' -size +0c -print -quit)"
'@

Write-Host ""
Write-Host "============================================="
Write-Host "              Build Completed!               "
Write-Host "============================================="
