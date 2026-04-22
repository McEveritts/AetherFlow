#!/bin/bash

# AetherFlow Atomic Blue/Green Deployment Engine

CHANNEL=${1:-stable}
LOG_FILE="/var/log/aetherflow_deployment.log"
exec > >(tee -a ${LOG_FILE}) 2>&1

echo "========================================"
echo "Starting AetherFlow Atomic Deployment"
echo "Date: $(date)"
echo "Channel: ${CHANNEL}"
echo "========================================"

ACTIVE_ROOT="/opt/AetherFlow"
RELEASE_BASE="/opt/AetherFlow_releases"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
TARGET_DIR="${RELEASE_BASE}/${TIMESTAMP}"

mkdir -p ${RELEASE_BASE}

echo "[1/7] Cloning bare repository payload..."
git clone https://github.com/McEveritts/AetherFlow.git ${TARGET_DIR}
if [ $? -ne 0 ]; then
    echo "ERROR: Failed to clone repository."
    exit 1
fi

cd ${TARGET_DIR}

echo "[2/7] Binding target branch/tag for channel: ${CHANNEL}..."
if [ "$CHANNEL" == "stable" ]; then
    # Fetch latest stable tag from git directly, filtering out prereleases
    LATEST_TAG=$(git tag -l | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n 1)
    
    if [ -n "$LATEST_TAG" ]; then
        git checkout ${LATEST_TAG}
        echo ${LATEST_TAG} > ${TARGET_DIR}/.version
    else
        echo "ERROR: Could not resolve latest stable tag."
        rm -rf ${TARGET_DIR}
        exit 1
    fi
elif [ "$CHANNEL" == "beta" ]; then
    # Get the absolute most recent tag from git (includes prereleases/betas)
    LATEST_TAG=$(git describe --tags $(git rev-list --tags --max-count=1))
    git checkout ${LATEST_TAG}
    echo ${LATEST_TAG} > ${TARGET_DIR}/.version
else
    # nightly explicitly maps to the bleeding edge master branch
    echo "Using bleeding edge master branch for nightly..."
    SHORT_SHA=$(git rev-parse --short HEAD)
    echo "nightly-${SHORT_SHA}" > ${TARGET_DIR}/.version
fi

echo "[3/7] Ghost Build: Compiling Go Backend in isolated environment..."
cd ${TARGET_DIR}/backend
export CGO_ENABLED=1
/usr/local/go/bin/go mod tidy
if ! /usr/local/go/bin/go build -o aetherflow-api main.go; then
    echo "ERROR: Go backend compilation failed. Aborting deployment."
    rm -rf ${TARGET_DIR}
    exit 1
fi

echo "[4/7] Ghost Build: Compiling Next.js Frontend in isolated environment..."
cd ${TARGET_DIR}/frontend
export NODE_OPTIONS="${NODE_OPTIONS:+${NODE_OPTIONS} }--max-old-space-size=1024"
if ! npm install --no-fund --no-audit; then
    echo "ERROR: npm install failed. Aborting deployment."
    rm -rf ${TARGET_DIR}
    exit 1
fi
if ! npm run build; then
    echo "ERROR: Next.js build failed. Aborting deployment."
    rm -rf ${TARGET_DIR}
    exit 1
fi

echo "[5/7] Migrating Persistent Configuration States..."
if [ -L ${ACTIVE_ROOT} ] || [ -d ${ACTIVE_ROOT} ]; then
    OLD_ROOT=$(readlink -f ${ACTIVE_ROOT})
    echo "Cloning persistent database and static assets from ${OLD_ROOT}..."
    if [ -d "${OLD_ROOT}/backend/data" ]; then
        cp -Rpf "${OLD_ROOT}/backend/data" "${TARGET_DIR}/backend/"
    fi
    # Migrate backend .env
    if [ -f "${OLD_ROOT}/backend/.env" ]; then
        cp -pf "${OLD_ROOT}/backend/.env" "${TARGET_DIR}/backend/.env"
    fi
    # Migrate sqlite database
    if [ -f "${OLD_ROOT}/backend/aetherflow.sqlite" ]; then
        cp -pf "${OLD_ROOT}/backend/aetherflow.sqlite" "${TARGET_DIR}/backend/aetherflow.sqlite"
    fi
    # If using .env.local in frontend, migrate it
    if [ -f "${OLD_ROOT}/frontend/.env.local" ]; then
        cp -pf "${OLD_ROOT}/frontend/.env.local" "${TARGET_DIR}/frontend/.env.local"
    fi
fi

echo "[6/7] Securing Atomic Symlink Swap..."
# Transition point. We force the symbolic link of /opt/AetherFlow to immediately point
# to the healthy verified TARGET_DIR.
rm -rf ${ACTIVE_ROOT} # Removes old dir or old symlink
ln -sfn ${TARGET_DIR} ${ACTIVE_ROOT}

echo "[7/7] Gracefully Reloading Daemons..."
systemctl daemon-reload
systemctl restart aetherflow-api aetherflow-frontend || true

mkdir -p /srv/aetherflow
sed -i '/SCGIMount/d' /etc/apache2/sites-enabled/*.conf 2>/dev/null || true
systemctl reload apache2 || systemctl restart apache2

echo "Deployment successful! Pruning legacy snapshots..."
# Automated Retain Pipeline: Retain the last 3 release snapshots to prevent disk exhaustion
ls -dt ${RELEASE_BASE}/*/ | tail -n +4 | xargs rm -rf 2>/dev/null || true

echo "========================================"
echo "Atomic Deployment Finished Successfully"
echo "========================================"
