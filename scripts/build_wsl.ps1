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
Write-Host "2. Running Backend Tests..."
wsl -d Debian -- bash -c "cd backend && go test ./... -v"

Write-Host ""
Write-Host "3. Building Backend..."
wsl -d Debian -- bash -c "cd backend && go build -v -o aetherflow-api"

Write-Host ""
Write-Host "4. Building Frontend..."
wsl -d Debian -- bash -c "cd frontend && npm install --no-audit --no-fund && npm run build"

Write-Host ""
Write-Host "============================================="
Write-Host "              Build Completed!               "
Write-Host "============================================="
