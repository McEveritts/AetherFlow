#!/bin/bash

# AetherFlow Automated Updater Script
# This runs detached from the main Go process so it can restart the backend and frontend

LOG_FILE="/var/log/aetherflow_update.log"
exec > >(tee -a ${LOG_FILE}) 2>&1

echo "========================================"
echo "Starting AetherFlow Update Sequence"
echo "Date: $(date)"
echo "========================================"

# 1. Pull latest code from GitHub (preserve local changes)
echo "Pulling latest code from master branch..."
cd /opt/AetherFlow || exit 1
git fetch --all

# Stash any local changes before updating
LOCAL_CHANGES=$(git status --porcelain)
if [ -n "$LOCAL_CHANGES" ]; then
    echo "Stashing local changes..."
    git stash save "auto-stash-before-update-$(date +%Y%m%d%H%M%S)"
fi

# Try fast-forward merge first; fall back to rebase if needed
if ! git pull --ff-only origin master 2>/dev/null; then
    echo "Fast-forward not possible, attempting rebase..."
    if ! git pull --rebase origin master; then
        echo "ERROR: Merge conflicts detected. Aborting update."
        git rebase --abort 2>/dev/null
        # Restore stashed changes
        if [ -n "$LOCAL_CHANGES" ]; then
            git stash pop 2>/dev/null
        fi
        exit 1
    fi
fi

# Restore stashed changes if any
if [ -n "$LOCAL_CHANGES" ]; then
    echo "Restoring local changes..."
    git stash pop 2>/dev/null || echo "Warning: Could not restore stashed changes (may have conflicts)"
fi

# 2. Rebuild Go API Binary
echo "Rebuilding Go API Binary..."
cd /opt/AetherFlow/backend || exit 1
export CGO_ENABLED=1
/usr/local/go/bin/go mod tidy
/usr/local/go/bin/go build -o aetherflow-api main.go

echo "Restarting API via PM2..."
pm2 restart aetherflow-api || pm2 start ./aetherflow-api --name "aetherflow-api"

# 3. Rebuild Next.js Frontend
echo "Rebuilding Next.js Frontend Bundle..."
cd /opt/AetherFlow/frontend || exit 1
npm install
npm run build

echo "Restarting Frontend via PM2..."
pm2 restart aetherflow-frontend || pm2 start npm --name "aetherflow-frontend" -- start

pm2 save

# 4. Reload Apache
# Ensure DocumentRoot exists
mkdir -p /srv/aetherflow

# Remove any stale SCGIMount directives from Apache configs
sed -i '/SCGIMount/d' /etc/apache2/sites-enabled/*.conf 2>/dev/null || true

systemctl restart apache2

echo "Update complete! All systems are back up."
echo "========================================"
