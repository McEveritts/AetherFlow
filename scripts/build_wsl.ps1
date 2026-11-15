# Helper script to build and test AetherFlow using WSL Debian

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
wsl -d Debian -u root -- bash -c "chmod +x scripts/setup_wsl_dev.sh && ./scripts/setup_wsl_dev.sh"

Write-Host ""
Write-Host "2. Building Frontend Static Export..."
wsl -d Debian -- bash -c "npm ci --no-audit --no-fund && NEXT_STATIC_EXPORT=1 npm run build --workspace frontend && rm -rf web/dist && mkdir -p web/dist && cp -R frontend/out/. web/dist/"

Write-Host ""
Write-Host "3. Running Rust Backend Tests (backend-rs)..."
wsl -d Debian -- bash -c "cd backend-rs && cargo test --locked --workspace"

Write-Host ""
Write-Host "4. Building Rust Backend Release Binaries (backend-rs)..."
wsl -d Debian -- bash -c "cd backend-rs && cargo build --release --locked --bin aetherflow-api --bin af --bin speedtest-backend"

Write-Host ""
Write-Host "============================================="
Write-Host "              Build Completed!               "
Write-Host "============================================="
