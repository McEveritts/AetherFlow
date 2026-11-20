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
    validate_config_paths "$INSTALL_DIR/.af-version" "$DATA_DIR/.af-version" "$CONFIG_DIR/runtime.env" "$CONFIG_DIR/companion.env" "$CONFIG_DIR/config.yml" "$CONFIG_DIR/config.properties" "$CONFIG_DIR/httpd.conf"
    export LOGFILE="/var/log/aetherflow/install-${APP_NAME}.log"
    if declare -F af_prepare_logfile_path >/dev/null 2>&1; then
        af_prepare_logfile_path "$LOGFILE"
    else
        local _log_dir
        _log_dir="${LOGFILE%/*}"
        if [[ -L "$_log_dir" || -L "$LOGFILE" || ( -e "$LOGFILE" && ! -f "$LOGFILE" ) ]]; then
            echo "ERROR: Unsafe logfile path: $LOGFILE" >&2
            return 1
        fi
        mkdir -p -m 0750 "$_log_dir" 2>/dev/null || true
    fi
    export DEBIAN_FRONTEND=noninteractive
    trap 'youtube_abort_install "Installation failed; see ${LOGFILE}."' ERR
    if ! id "$APP_NAME" >/dev/null 2>&1; then
        useradd --system --user-group --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$APP_NAME"
    fi
    install -d -m 755 "$INSTALL_DIR" "$DATA_DIR"
    install -d -m 750 -o root -g "$APP_NAME" "$CONFIG_DIR"
    chown "$APP_NAME:$APP_NAME" "$INSTALL_DIR" "$DATA_DIR"
    af_logged apt-get update -qq
    af_logged apt-get install --no-remove -y -qq ca-certificates curl git jq openssl python3 postgresql
}

youtube_abort_install() {
    local rc="$?"
    local msg="${1:-Installation failed; see ${LOGFILE:-/var/log/aetherflow/install.log}.}"
    if [[ "$1" =~ ^[0-9]+$ && -n "${2:-}" ]]; then
        rc="$1"
        msg="$2"
    fi
    [[ "$rc" -ne 0 ]] || rc=1
    af_write_failure_receipt "$rc" "${AF_CURRENT_STAGE:-build}" "installer" "$msg"
    print_error "$msg"
}

youtube_source() {
    local repo="$1" destination="$2" dir="$2"
    if [[ $# -ge 3 ]]; then
        local target_ref="$3"
    else
        local target_ref="${AF_TARGET_VERSION:-}"
        case "$repo" in
            iv-org/invidious|TeamPiped/*)
                if [[ "$target_ref" == *","* || "$target_ref" == *":"* ]]; then
                    target_ref=""
                fi
                ;;
            *)
                target_ref=""
                ;;
        esac
    fi
    if [[ -d "${dir}/.git" ]]; then
        if [[ -z "$target_ref" ]]; then
            if [[ -n "${APP_NAME:-}" ]] && id "$APP_NAME" >/dev/null 2>&1; then
                af_logged runuser -u "$APP_NAME" -- git -C "$dir" fetch --depth 1 origin HEAD && \
                af_logged runuser -u "$APP_NAME" -- git -C "$dir" checkout --detach FETCH_HEAD && \
                af_logged runuser -u "$APP_NAME" -- git -C "$dir" reset --hard FETCH_HEAD
            else
                af_logged git -C "$dir" fetch --depth 1 origin HEAD && af_logged git -C "$dir" checkout --detach FETCH_HEAD && af_logged git -C "$dir" reset --hard FETCH_HEAD
            fi
        fi
    else
        af_logged runuser -u "$APP_NAME" -- git clone --depth 1 "https://github.com/${repo}.git" "$destination"
    fi
    if [[ -n "$target_ref" ]]; then
        if ! af_logged runuser -u "$APP_NAME" -- git -C "$destination" fetch --depth 1 origin "$target_ref" || \
           ! af_logged runuser -u "$APP_NAME" -- git -C "$destination" checkout --detach FETCH_HEAD; then
            if ! af_logged runuser -u "$APP_NAME" -- git -C "$destination" checkout "$target_ref"; then
                youtube_abort_install "Failed to check out requested target ref ${target_ref} for ${repo}"
                exit 1
            fi
        fi
    fi
}

youtube_secret() {
    local path="${CONFIG_DIR}/$1"
    validate_config_paths "$path"
    if [[ ! -s "$path" ]]; then
        (umask 077; openssl rand -hex "${2:-32}" > "$path")
    fi
    chown "root:$APP_NAME" "$path"
    chmod 640 "$path"
    cat "$path"
}

youtube_private_port() {
    local path="${CONFIG_DIR}/$1-port"
    validate_config_paths "$path"
    if [[ ! -s "$path" ]]; then
        python3 - "$APP_PORT" "$CONFIG_DIR" > "$path" <<'PY'
import pathlib
import socket
import sys

used = {int(sys.argv[1])}
config_dir = pathlib.Path(sys.argv[2])
etc_dir = config_dir.parent
search_dirs = [config_dir]
for sibling in ("piped", "invidious", "aetherflow"):
    candidate = etc_dir / sibling
    if candidate not in search_dirs:
        search_dirs.append(candidate)
if etc_dir.name == "etc":
    opt_dir = etc_dir.parent / "opt"
    for sibling in ("piped", "invidious"):
        search_dirs.append(opt_dir / sibling)
for directory in search_dirs:
    if not directory.is_dir():
        continue
    for port_file in directory.glob("*-port"):
        if not port_file.is_file() or not port_file.stat().st_size:
            continue
        raw = port_file.read_text().strip()
        if raw.isdecimal():
            used.add(int(raw))
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
    (
    export AF_YOUTUBE_DB_PASSWORD="$DB_PASSWORD"
    af_logged runuser --preserve-environment -u postgres -- psql -v ON_ERROR_STOP=1 --set="app=$APP_NAME" <<'SQL'
\getenv password AF_YOUTUBE_DB_PASSWORD
SELECT format('CREATE ROLE %I LOGIN', :'app') WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = :'app') \gexec
SELECT format('ALTER ROLE %I PASSWORD %L', :'app', :'password') \gexec
SELECT format('CREATE DATABASE %I OWNER %I', :'app', :'app') WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = :'app') \gexec
SQL
    )
}

youtube_asset() {
    local repo="$1" tag="$2" asset="$3" output="$4" metadata="" url="" digest=""
    if [[ -n "${AF_TARGET_VERSION:-}" && "$tag" != "release-master" ]]; then
        case "$repo" in
            iv-org/invidious|TeamPiped/*)
                tag="${AF_TARGET_VERSION}"
                ;;
        esac
    fi
    metadata="$(af_github_curl --fail --silent --show-error --location "https://api.github.com/repos/${repo}/releases/tags/${tag}" 2>/dev/null || true)"
    if [[ -n "$metadata" ]]; then
        url="$(jq -er --arg name "$asset" '.assets[] | select(.name == $name) | .browser_download_url' <<< "$metadata" 2>/dev/null || true)"
        digest="$(jq -r --arg name "$asset" '.assets[] | select(.name == $name) | .digest // empty' <<< "$metadata" 2>/dev/null || true)"
    fi
    if [[ -z "$url" ]]; then
        url="https://github.com/${repo}/releases/download/${tag}/${asset}"
        digest=""
    fi
    [[ "$url" == "https://github.com/${repo}/releases/download/"* && ( -z "$digest" || "$digest" =~ ^sha256:[a-fA-F0-9]{64}$ ) ]] || {
        print_error "Missing trusted download URL or SHA-256 digest for ${asset}."
        return 1
    }
    RELEASE_JSON="${metadata:-}" download_file "$url" "$output" "${APP_NAME:-${PACKAGE_NAME:-youtube}}" "${digest#sha256:}"
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
    if declare -F af_prepare_logfile_path >/dev/null 2>&1; then
        af_prepare_logfile_path "$LOGFILE" || return 1
    else
        mkdir -p "$(dirname "$LOGFILE")" || return 1
    fi
    purge_systemd_unit "af-${app}" "$@" || return 1
    if [[ "${DELETE_DATA:-false}" == true ]]; then
        if command -v systemctl >/dev/null 2>&1; then
            if ! systemctl is-active --quiet postgresql.service 2>/dev/null; then
                if systemctl list-unit-files postgresql.service >/dev/null 2>&1 || [[ -e /lib/systemd/system/postgresql.service || -e /usr/lib/systemd/system/postgresql.service || -e /etc/systemd/system/postgresql.service ]] || command -v psql >/dev/null 2>&1 || id -u postgres >/dev/null 2>&1; then
                    if ! af_logged systemctl start postgresql.service; then
                        print_error "Failed to start PostgreSQL (postgresql.service) for ${app} database purge."
                        return 1
                    fi
                fi
            fi
        fi
        local pg_active=false
        if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet postgresql.service 2>/dev/null; then
            pg_active=true
        fi
        if [[ "$pg_active" != true ]]; then
            print_error "PostgreSQL service is not active; refusing ${app} purge while database/role teardown cannot run."
            return 1
        fi
        if ! af_logged runuser -u postgres -- psql --dbname=postgres -v ON_ERROR_STOP=1 --set="app=$app" <<'SQL'
SELECT format('DROP DATABASE IF EXISTS %I', :'app') \gexec
SELECT format('DROP ROLE IF EXISTS %I', :'app') \gexec
SQL
        then
            print_error "Failed to drop PostgreSQL database/role for ${app}."
            return 1
        fi
        local remaining_pg=""
        if ! remaining_pg="$(runuser -u postgres -- psql --dbname=postgres -v ON_ERROR_STOP=1 -X -q -tA --set="app=$app" <<'SQL'
SELECT (SELECT count(*) FROM pg_database WHERE datname = :'app') + (SELECT count(*) FROM pg_roles WHERE rolname = :'app');
SQL
        )"; then
            print_error "Failed to verify PostgreSQL database/role removal for ${app}."
            return 1
        fi
        remaining_pg="${remaining_pg//[[:space:]]/}"
        if [[ "$remaining_pg" != "0" ]]; then
            print_error "PostgreSQL database or role verification failed for ${app} (remaining=${remaining_pg:-empty})."
            return 1
        fi
        safe_rm_rf "/opt/${app}" || return 1
        safe_rm_rf "/etc/${app}" || return 1
        safe_rm_rf "/var/lib/${app}" || return 1
        purge_system_user "$app" || return 1
        remove_lock "$app" || return 1
        print_info "${app} purged, including its sources, configuration, PostgreSQL database and user data."
    else
        rm -f "/opt/${app}/.af-version" "/var/lib/${app}/.af-version" "/etc/${app}/.af-version"
        remove_lock "$app" || return 1
        print_info "${app} removed. Sources, configuration, PostgreSQL database and user data are preserved for reinstall."
    fi
}
