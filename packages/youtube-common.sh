#!/bin/bash
set -euo pipefail

youtube_init() {
    require_root
    umask 027
    APP_NAME="$1"
    APP_PORT="${AF_APP_PORT:-$2}"
    if [[ ! "$APP_PORT" =~ ^[0-9]{4,5}$ ]] || (( 10#$APP_PORT < 1024 || 10#$APP_PORT > 65535 )); then
        print_error "Invalid ${APP_NAME} port: ${APP_PORT}"
        exit 1
    fi
    APP_DOMAIN="${AF_APP_DOMAIN:-${APP_NAME}.$(get_base_domain)}"
    if [[ ! "$APP_DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$ ]]; then
        print_error "Configure AetherFlow's base domain or AF_APP_DOMAIN before installing ${APP_NAME}."
        exit 1
    fi
    INSTALL_DIR="/opt/${APP_NAME}"
    DATA_DIR="/var/lib/${APP_NAME}"
    CONFIG_DIR="/etc/${APP_NAME}"
    export LOGFILE="/var/log/aetherflow/install-${APP_NAME}.log"
    export DEBIAN_FRONTEND=noninteractive
    trap 'print_error "Installation failed; see ${LOGFILE}."' ERR
    if ! id "$APP_NAME" >/dev/null 2>&1; then
        useradd --system --user-group --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$APP_NAME"
    fi
    install -d -m 755 "$INSTALL_DIR" "$DATA_DIR"
    install -d -m 750 -o root -g "$APP_NAME" "$CONFIG_DIR"
    chown "$APP_NAME:$APP_NAME" "$INSTALL_DIR" "$DATA_DIR"
    apt-get update -qq >> "$LOGFILE" 2>&1
    apt-get install --no-remove -y -qq ca-certificates curl git jq openssl python3 postgresql >> "$LOGFILE" 2>&1
}

youtube_source() {
    local repo="$1" destination="$2"
    if [[ -d "$destination/.git" ]]; then
        runuser -u "$APP_NAME" -- git -C "$destination" pull --ff-only >> "$LOGFILE" 2>&1
    else
        runuser -u "$APP_NAME" -- git clone --depth 1 "https://github.com/${repo}.git" "$destination" >> "$LOGFILE" 2>&1
    fi
}

youtube_secret() {
    local path="${CONFIG_DIR}/$1"
    if [[ ! -s "$path" ]]; then
        (umask 077; openssl rand -hex "${2:-32}" > "$path")
    fi
    chown "root:$APP_NAME" "$path"
    chmod 640 "$path"
    cat "$path"
}

youtube_private_port() {
    local path="${CONFIG_DIR}/$1-port"
    if [[ ! -s "$path" ]]; then
        python3 - "$APP_PORT" "$CONFIG_DIR" > "$path" <<'PY'
import pathlib
import socket
import sys

used = {int(sys.argv[1])}
used.update(int(path.read_text()) for path in pathlib.Path(sys.argv[2]).glob('*-port') if path.stat().st_size)
for port in range(20000, 30000):
    if port in used:
        continue
    with socket.socket() as probe:
        try:
            probe.bind(('127.0.0.1', port))
        except OSError:
            continue
        print(port)
        break
else:
    sys.exit('No available private service port')
PY
    fi
    cat "$path"
}

youtube_database() {
    DB_PASSWORD="$(youtube_secret database-password)"
    systemctl enable --now postgresql.service
    runuser -u postgres -- psql -v ON_ERROR_STOP=1 --set="app=$APP_NAME" --set="password=$DB_PASSWORD" >> "$LOGFILE" 2>&1 <<'SQL'
SELECT format('CREATE ROLE %I LOGIN', :'app') WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'app') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'app', :'password') \gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'app', :'app') WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'app') \gexec
SQL
}

youtube_asset() {
    local repo="$1" tag="$2" asset="$3" output="$4" metadata url digest
    metadata="$(curl --fail --silent --show-error --location "https://api.github.com/repos/${repo}/releases/tags/${tag}")"
    url="$(jq -er --arg name "$asset" '.assets[] | select(.name == $name) | .browser_download_url' <<< "$metadata")"
    digest="$(jq -er --arg name "$asset" '.assets[] | select(.name == $name) | .digest' <<< "$metadata")"
    [[ "$url" == "https://github.com/${repo}/releases/download/"* && "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || {
        print_error "Missing trusted download URL or SHA-256 digest for ${asset}."
        return 1
    }
    curl --fail --silent --show-error --location "$url" -o "$output"
    printf '%s  %s\n' "${digest#sha256:}" "$output" | sha256sum --check --status
}

youtube_unit() {
    local unit="$1" command="$2" dependencies="${3:-}"
    cat > "/etc/systemd/system/${unit}.service" <<EOF
[Unit]
Description=AetherFlow ${unit}
After=network-online.target postgresql.service ${dependencies}
Wants=network-online.target postgresql.service
PartOf=af-${APP_NAME}.service
${dependencies:+Requires=${dependencies}}

[Service]
Type=simple
User=${APP_NAME}
Group=${APP_NAME}
WorkingDirectory=${DATA_DIR}
Environment=HOME=${DATA_DIR}
EnvironmentFile=-${CONFIG_DIR}/runtime.env
ExecStart=${command}
Restart=on-failure
RestartSec=5
UMask=0027
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR}

[Install]
WantedBy=multi-user.target
EOF
    if [[ "$unit" == "af-${APP_NAME}" ]]; then
        sed -i '/^PartOf=/d' "/etc/systemd/system/${unit}.service"
    fi
}

youtube_ready() {
    local url="$1" attempt
    for attempt in {1..30}; do
        if curl --fail --silent --max-time 3 "$url" >/dev/null; then
            return 0
        fi
        sleep 2
    done
    print_error "${APP_NAME} did not become ready at ${url} after ${attempt} attempts; installation was not marked complete."
    return 1
}

youtube_remove() {
    require_root
    local app="$1"
    shift
    case "$app" in piped|invidious) ;; *) return 1 ;; esac
    export LOGFILE="/var/log/aetherflow/remove-${app}.log"
    mkdir -p "$(dirname "$LOGFILE")" || return 1
    purge_systemd_unit "af-${app}" "$@" || return 1
    if [[ "${DELETE_DATA:-false}" == true ]]; then
        runuser -u postgres -- psql --dbname=postgres -v ON_ERROR_STOP=1 --set="app=$app" >> "$LOGFILE" 2>&1 <<'SQL' || return 1
SELECT format('DROP DATABASE IF EXISTS %I', :'app') \gexec
SELECT format('DROP ROLE IF EXISTS %I', :'app') \gexec
SQL
        rm -rf "/opt/${app}" "/etc/${app}" "/var/lib/${app}" || return 1
        purge_system_user "$app" || return 1
        remove_lock "$app" || return 1
        print_info "${app} purged, including its sources, configuration, PostgreSQL database and user data."
    else
        remove_lock "$app" || return 1
        print_info "${app} removed. Sources, configuration, PostgreSQL database and user data are preserved for reinstall."
    fi
}
