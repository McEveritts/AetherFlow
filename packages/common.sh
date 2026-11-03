#!/bin/bash
# /opt/AetherFlow/packages/common.sh
# Shared variables and functions for AetherFlow scripts/installers.

set -euo pipefail

export PATH="/usr/local/nodejs/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${PATH:-}"
export LOGFILE="${LOGFILE:-/var/log/aetherflow/install.log}"
export LOCK_DIR="${LOCK_DIR:-/install}"

mkdir -p "$LOCK_DIR" "$(dirname "$LOGFILE")"

timestamp() {
    date "+%Y-%m-%d %H:%M:%S"
}

log() {
    printf '[%s] %s\n' "$(timestamp)" "$*" >>"$LOGFILE"
}

log_info() {
    log "[INFO] $*"
}

log_warn() {
    log "[WARN] $*"
}

log_error() {
    log "[ERROR] $*"
}

print_info() {
    printf '[INFO] %s\n' "$*"
    log_info "$*"
}

print_warn() {
    printf '[WARN] %s\n' "$*" >&2
    log_warn "$*"
}

print_error() {
    printf '[ERROR] %s\n' "$*" >&2
    log_error "$*"
}

require_root() {
    if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
        print_error "This command must be run as root."
        exit 1
    fi
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Keep build dependencies and lifecycle scripts enabled even when the host or
# calling service has production-only npm settings. In particular, global=true
# leaks into npm's Git preparation subprocess and skips its local devDependencies.
# Run in a subshell so application runtime settings and the caller stay intact.
node_build() (
    unset npm_config_production NPM_CONFIG_PRODUCTION npm_config_only NPM_CONFIG_ONLY
    export npm_config_global=false NPM_CONFIG_GLOBAL=false
    export npm_config_omit= NPM_CONFIG_OMIT=
    # npm serializes array-valued configuration with double newlines.
    export npm_config_include=$'dev\n\npeer\n\noptional'
    export NPM_CONFIG_INCLUDE="$npm_config_include"
    export npm_config_ignore_scripts=false NPM_CONFIG_IGNORE_SCRIPTS=false
    export YARN_PRODUCTION=false
    "$@"
)

# Install npm applications locally so Git dependencies can prepare with their
# own complete toolchains. Build before replacing any existing application and
# expose only the application's executable, rather than global build tools.
install_npm_app() (
    set -e
    umask 022
    local package="$1" destination="$2" executable="$3" staged="" bin_name
    bin_name="$(basename "$executable")"
    mkdir -p "$(dirname "$destination")" "$(dirname "$executable")"
    staged="$(mktemp -d "${destination}.af-build.XXXXXX")"
    trap '[[ -z "$staged" ]] || rm -rf -- "$staged"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    # mktemp creates a private directory; the service user must traverse it.
    chmod 755 "$staged"
    node_build npm install --prefix "$staged" --no-audit --no-fund "$package" >> "$LOGFILE" 2>&1 || return $?
    if [[ ! -x "$staged/node_modules/.bin/$bin_name" ]]; then
        print_error "npm package $package did not provide executable $bin_name"
        return 1
    fi
    replace_app_tree "$staged" "$destination" || return $?
    staged=""
    ln -sfn -- "$destination/node_modules/.bin/$bin_name" "$executable"
)

# Stage on the destination filesystem so replacement uses rename(), including
# when /tmp lives on a different mount. Never truncate an executing inode.
install_binary_atomic() {
    local source="$1" destination="$2" staged
    if [[ ! -s "$source" ]]; then
        print_error "Downloaded binary is empty: $source"
        return 1
    fi
    mkdir -p "$(dirname "$destination")"
    staged="$(mktemp "${destination}.af-new.XXXXXX")"
    if ! install -m 0755 "$source" "$staged" || ! mv -fT "$staged" "$destination"; then
        rm -f "$staged"
        return 1
    fi
}

# Change one listen setting without rebuilding the user's application config.
# Supported formats use only Python's standard library on the Debian host.
set_config_value() {
    python3 - "$@" <<'PYEOF'
import json, pathlib, re, sys, xml.etree.ElementTree as ET
filename, kind, key, value, *options = sys.argv[1:]
path = pathlib.Path(filename)
path.parent.mkdir(parents=True, exist_ok=True)
text = path.read_text() if path.exists() else ''
section = options[0] if options else ''
if kind == 'xml':
    root = ET.fromstring(text) if text.strip() else ET.Element(section or 'Config')
    node = root.find(key)
    if node is None:
        node = ET.SubElement(root, key)
    node.text = value
    text = ET.tostring(root, encoding='unicode') + '\n'
elif kind == 'json':
    data = json.loads(text) if text.strip() else {}
    parent = data
    parts = key.split('.')
    for part in parts[:-1]:
        parent = parent.setdefault(part, {})
    parent[parts[-1]] = int(value) if value.isdecimal() else value
    text = json.dumps(data, indent=2) + '\n'
else:
    if kind == 'yaml':
        header = re.compile(r'(?m)^' + re.escape(section) + r':\s*(?:#.*)?$') if section else None
        pattern = re.compile(r'(?m)^' + ('  ' if section else '') + re.escape(key) + r'\s*:.*$')
        setting = ('  ' if section else '') + key + ': ' + value + '\n'
        next_section = re.compile(r'(?m)^\S[^\n]*:')
    elif kind == 'ini':
        header = re.compile(r'(?m)^\[' + re.escape(section) + r'\]\s*$') if section else None
        pattern = re.compile(r'(?im)^\s*' + re.escape(key) + r'\s*=.*$')
        setting = key + ' = ' + value + '\n'
        next_section = re.compile(r'(?m)^\[')
    elif kind == 'js':
        header = None
        pattern = re.compile(r'(?m)^\s*' + re.escape(key) + r'\s*:\s*\d+\s*,?\s*$')
        setting = '    ' + key + ': ' + value + ',\n'
        next_section = None
        if not pattern.search(text):
            raise ValueError('Cannot locate existing JavaScript port setting')
    else:
        raise ValueError('Unsupported config format: ' + kind)
    start, end = 0, len(text)
    if header:
        match = header.search(text)
        if match is None:
            text += ('\n' if text and not text.endswith('\n') else '') + (section + ':\n' if kind == 'yaml' else '[' + section + ']\n')
            start = end = len(text)
        else:
            start = match.end() + 1
            following = next_section.search(text, start)
            end = following.start() if following else len(text)
    block = text[start:end]
    if pattern.search(block):
        block = pattern.sub(lambda _: setting.rstrip('\n'), block)
    else:
        block = block.rstrip('\n') + ('\n' if block else '') + setting
    text = text[:start] + block + text[end:]
path.write_text(text)
PYEOF
}

# Activate prepared application code while retaining persistent paths and a
# private copy of the previous installation for recovery after migrations.
replace_app_tree() {
    local staged="$1" destination="$2" relative backup
    shift 2
    for relative in "$@"; do
        if [[ "$relative" == /* || "$relative" == *..* ]]; then
            print_error "Invalid application data path: $relative"
            return 1
        fi
        if [[ -e "$destination/$relative" || -L "$destination/$relative" ]]; then
            mkdir -p "$(dirname "$staged/$relative")"
            rm -rf -- "$staged/$relative"
            cp -a -- "$destination/$relative" "$staged/$relative"
        fi
    done
    if [[ -e "$destination" ]]; then
        backup="$(mktemp -d "${destination}.af-backup.XXXXXX")"
        chmod 700 "$backup"
        mv -T "$destination" "$backup/app"
        if ! mv -T "$staged" "$destination"; then
            mv -T "$backup/app" "$destination"
            return 1
        fi
        log_info "Previous application files retained in $backup/app"
    else
        mv -T "$staged" "$destination"
    fi
}

configure_apache_app_listener() {
    local package_name="$1" port="$2" apache_root="${AETHERFLOW_APACHE_ROOT:-/etc/apache2}" config staged
    [[ "$package_name" =~ ^[a-z0-9][a-z0-9-]*$ && "$port" =~ ^[0-9]+$ ]] || return 1
    (( port >= 1024 && port <= 65535 )) || return 1
    config="aetherflow-${package_name}-listen.conf"
    mkdir -p "$apache_root/conf-available" "$apache_root/conf-enabled"
    if grep -Eq "^[[:space:]]*Listen[[:space:]]+${port}([[:space:]]|$)" "$apache_root/ports.conf" 2>/dev/null; then
        rm -f -- "$apache_root/conf-enabled/$config" "$apache_root/conf-available/$config"
        log_info "Reusing existing shared Apache listener on $port"
        return 0
    fi
    staged="$(mktemp "$apache_root/conf-available/.${config}.XXXXXX")"
    if ! printf 'Listen %s\n' "$port" > "$staged" || ! chmod 644 "$staged" || ! mv -f -- "$staged" "$apache_root/conf-available/$config"; then
        rm -f -- "$staged"
        return 1
    fi
    ln -sfn -- "../conf-available/$config" "$apache_root/conf-enabled/$config"
}

remove_apache_app_listener() {
    local package_name="$1" apache_root="${AETHERFLOW_APACHE_ROOT:-/etc/apache2}" config
    [[ "$package_name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
    config="aetherflow-${package_name}-listen.conf"
    rm -f -- "$apache_root/conf-enabled/$config" "$apache_root/conf-available/$config"
}

lock_path() {
    local package_name="$1"
    printf '%s/.%s.lock\n' "$LOCK_DIR" "$package_name"
}

has_lock() {
    local package_name="$1"
    [[ -f "$(lock_path "$package_name")" ]]
}

write_lock() {
    local package_name="$1"
    touch "$(lock_path "$package_name")"
    if [[ -x /usr/local/bin/af-certbot-sync ]]; then
        /usr/local/bin/af-certbot-sync >/dev/null 2>&1 &
    fi
}

get_base_domain() {
    local dom=""
    if command -v sqlite3 >/dev/null 2>&1 && [[ -f /opt/AetherFlow/backend/data/aetherflow.sqlite ]]; then
        dom="$(sqlite3 /opt/AetherFlow/backend/data/aetherflow.sqlite "SELECT base_domain FROM settings WHERE id = 1;" 2>/dev/null | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's/^\*\.//' | tr -d '[:space:]' || true)"
    fi
    if [[ -z "$dom" && -f /etc/aetherflow/aetherflow.env ]]; then
        dom="$(grep -oP '^AETHERFLOW_BASE_DOMAIN=\K.*' /etc/aetherflow/aetherflow.env 2>/dev/null | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's/^\*\.//' | tr -d '[:space:]' || true)"
    fi
    local domain_regex='^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'
    if [[ "$dom" == "localhost" || "$dom" == *.local ]] || { [[ -n "$dom" ]] && [[ ! "$dom" =~ $domain_regex ]]; }; then
        dom=""
    fi
    printf '%s\n' "$dom"
}

remove_lock() {
    local package_name="$1"
    rm -f "$(lock_path "$package_name")"
}

backup_file_once() {
    local target="$1"
    if [[ -f "$target" && ! -f "${target}.bak-af" ]]; then
        cp -a "$target" "${target}.bak-af"
    fi
}

rollback_file() {
    local target="$1"
    if [[ -f "${target}.bak-af" ]]; then
        mv -f "${target}.bak-af" "$target"
    fi
}

cleanup_backup_file() {
    local target="$1"
    rm -f "${target}.bak-af"
}

fetch_and_run() {
    local url="$1"
    local checksum="$2"
    shift 2

    local tmp_script
    tmp_script=$(mktemp /tmp/aetherflow-install-XXXXXX.sh)
    
    log_info "Downloading install script from $url"
    if ! curl -fsSL -o "$tmp_script" "$url"; then
        print_error "Failed to download $url"
        rm -f "$tmp_script"
        return 1
    fi

    if [[ -n "$checksum" && "$checksum" != "SKIP" ]]; then
        local computed_hash
        computed_hash=$(sha256sum "$tmp_script" | awk '{print $1}')
        if [[ "$computed_hash" != "$checksum" ]]; then
            print_error "Checksum validation failed for $url! Expected: $checksum, Got: $computed_hash"
            rm -f "$tmp_script"
            return 1
        fi
        log_info "Checksum validation passed."
    else
        log_warn "WARNING: Checksum validation skipped for $url (Hash pinned as SKIP or empty)."
    fi

    # Ensure executable and run
    chmod +x "$tmp_script"
    if ! "$tmp_script" "$@"; then
        print_error "Script execution failed for $url"
        rm -f "$tmp_script"
        return 1
    fi

    rm -f "$tmp_script"
    return 0
}

report_progress() {
    local pct="${1:-0}"
    local msg="${2:-}"
    printf '[PROGRESS:%d] %s\n' "$pct" "$msg"
    log_info "[PROGRESS:$pct] $msg"
}

github_latest_tag() {
    local repo="$1"
    local fallback="${2:-}"
    local strip_v="${3:-true}"
    local tag=""
    local eff_url=""

    eff_url="$(curl -fsSL -o /dev/null -w '%{url_effective}' "https://github.com/${repo}/releases/latest" 2>/dev/null || true)"
    if [[ "$eff_url" == *"/releases/tag/"* ]]; then
        tag="${eff_url##*/releases/tag/}"
        tag="${tag%%\?*}"
        tag="${tag%%#*}"
    fi

    if [[ -z "$tag" ]]; then
        tag="$(curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" 2>/dev/null \
            | grep -oP '"tag_name":\s*"\K[^"]+' | head -n1 || true)"
    fi

    if [[ -z "$tag" ]]; then
        tag="$fallback"
    fi

    if [[ "$strip_v" == "true" ]]; then
        tag="${tag#v}"
    fi

    printf '%s\n' "$tag"
}

sync_node_global_bins() {
    local npm_prefix=""
    if command_exists npm; then
        npm_prefix="$(npm config get prefix 2>/dev/null || true)"
    fi
    local bin_dir
    for bin_dir in "/usr/local/nodejs/bin" "${npm_prefix:+${npm_prefix}/bin}" "/usr/local/bin"; do
        [[ -n "$bin_dir" && -d "$bin_dir" ]] || continue
        case ":$PATH:" in
            *":${bin_dir}:"*) ;;
            *) export PATH="${bin_dir}:$PATH" ;;
        esac
        local bin_path bin_name
        for bin_path in "$bin_dir"/*; do
            [[ -e "$bin_path" && -x "$bin_path" && ! -d "$bin_path" ]] || continue
            bin_name="$(basename "$bin_path")"
            if [[ "$bin_dir" != "/usr/local/bin" && ! -e "/usr/local/bin/${bin_name}" ]]; then
                ln -sf "$bin_path" "/usr/local/bin/${bin_name}" 2>/dev/null || true
            fi
        done
    done
    local core_bin
    for core_bin in node npm npx yarn yarnpkg pnpm corepack; do
        if [[ ! -x "/usr/bin/${core_bin}" ]]; then
            if [[ -x "/usr/local/bin/${core_bin}" ]]; then
                ln -sf "/usr/local/bin/${core_bin}" "/usr/bin/${core_bin}" 2>/dev/null || true
            elif [[ -x "/usr/local/nodejs/bin/${core_bin}" ]]; then
                ln -sf "/usr/local/nodejs/bin/${core_bin}" "/usr/bin/${core_bin}" 2>/dev/null || true
            fi
        fi
    done
}

ensure_node() {
    local want_major="${1:-20}"
    local have_major=0
    # Native addons and Git prepare scripts need these on already-provisioned
    # Node hosts too, not just when Node itself is first installed.
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        ca-certificates git build-essential python3 python3-setuptools pkg-config >> "$LOGFILE" 2>&1
    if command_exists node; then
        have_major=$(node -v 2>/dev/null | sed 's/^v//' | cut -d. -f1 || echo 0)
    fi
    if [[ "${have_major:-0}" -lt "$want_major" ]]; then
        fetch_and_run "https://deb.nodesource.com/setup_${want_major}.x" "SKIP"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nodejs >> "$LOGFILE" 2>&1
    fi
    sync_node_global_bins
}

purge_systemd_unit() {
    local unit="$1"
    case "$unit" in
        *.service|*.timer|*.socket) ;;
        *) unit="${unit}.service" ;;
    esac
    systemctl stop "$unit" >/dev/null 2>&1 || true
    systemctl disable "$unit" >/dev/null 2>&1 || true
    systemctl reset-failed "$unit" >/dev/null 2>&1 || true
    rm -f "/etc/systemd/system/${unit}"
    rm -rf "/etc/systemd/system/${unit}.d"
}

purge_system_user() {
    local username="$1"
    if [[ "${DELETE_DATA:-false}" != true ]]; then
        log_info "Retaining ${username} account and home directory with application data"
        return 0
    fi
    if [[ -n "$username" && "$username" != "root" && "$username" != "www-data" ]]; then
        userdel -r "$username" >/dev/null 2>&1 || userdel "$username" >/dev/null 2>&1 || true
        groupdel "$username" >/dev/null 2>&1 || true
        rm -rf "/home/${username}"
    fi
}

load_master_credentials() {
    local u="" p="" h=""
    for creds_json in /var/lib/aetherflow/.master.creds /opt/AetherFlow/backend/data/.master.creds; do
        if [[ -f "$creds_json" ]]; then
            u="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("username",""))' "$creds_json" 2>/dev/null || true)"
            p="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("password",""))' "$creds_json" 2>/dev/null || true)"
            h="$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d.get("ha1",""))' "$creds_json" 2>/dev/null || true)"
            [[ -n "$u" && -n "$p" ]] && break
        fi
    done
    if [[ -z "$u" || -z "$p" ]] && [[ -f /install/.aetherflow.conf ]]; then
        u="$(bash -c 'source /install/.aetherflow.conf >/dev/null 2>&1; printf "%s" "${username:-}"' 2>/dev/null || true)"
        p="$(bash -c 'source /install/.aetherflow.conf >/dev/null 2>&1; printf "%s" "${passwd:-}"' 2>/dev/null || true)"
        h="$(bash -c 'source /install/.aetherflow.conf >/dev/null 2>&1; printf "%s" "${ha1pass:-}"' 2>/dev/null || true)"
    fi
    if [[ -z "$u" && -f /etc/apache2/master.txt ]]; then
        u="$(awk -F: 'NR==1 {print $1}' /etc/apache2/master.txt 2>/dev/null | tr -d '[:space:]' || true)"
    fi
    if [[ -z "$u" ]] && command -v sqlite3 >/dev/null 2>&1 && [[ -f /opt/AetherFlow/backend/data/aetherflow.sqlite ]]; then
        u="$(sqlite3 /opt/AetherFlow/backend/data/aetherflow.sqlite "SELECT username FROM users ORDER BY id ASC LIMIT 1;" 2>/dev/null | tr -d '[:space:]' || true)"
    fi
    if [[ -z "$p" && -n "$u" && -f "/root/${u}.info.db" ]]; then
        p="$(cut -d: -f2- "/root/${u}.info.db" 2>/dev/null | head -n1 | tr -d '\r\n' || true)"
    fi
    if [[ -z "$p" ]]; then
        local info_file
        info_file="$(ls -1 /root/*.info.db 2>/dev/null | head -n1 || true)"
        if [[ -n "$info_file" && -f "$info_file" ]]; then
            [[ -z "$u" ]] && u="$(cut -d: -f1 "$info_file" 2>/dev/null | head -n1 | tr -d '\r\n' || true)"
            p="$(cut -d: -f2- "$info_file" 2>/dev/null | head -n1 | tr -d '\r\n' || true)"
        fi
    fi
    export MASTER_USER="${u:-admin}"
    export MASTER_PASS="${p:-adminadmin}"
    if [[ -z "$h" ]]; then
        h="$(printf '%s' "$MASTER_PASS" | md5sum | awk '{print $1}')"
    fi
    export MASTER_HA1="$h"
}

generate_qbittorrent_pbkdf2() {
    local pass="${1:-${MASTER_PASS:-adminadmin}}"
    python3 -c '
import sys, os, hashlib, base64
pw = sys.argv[1].encode("utf-8")
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac("sha512", pw, salt, 100000, 64)
print(f"@ByteArray({base64.b64encode(salt).decode()}:{base64.b64encode(dk).decode()})")
' "$pass"
}

seed_servarr_master_user() {
    local app="$1"
    local port="$2"
    local api_ver="${3:-v3}"
    local cfg_xml="/var/lib/${app}/config.xml"
    python3 - "$app" "$port" "$api_ver" "$cfg_xml" "${MASTER_USER}" "${MASTER_PASS}" >> "$LOGFILE" 2>&1 <<'PYEOF' || log_warn "Non-fatal warning seeding Servarr master user for ${app}"
import sys, os, re, time, json, urllib.request

app, port, api_ver, cfg_xml, user, pw = sys.argv[1:7]
api_key = ""
for _ in range(45):
    if os.path.exists(cfg_xml):
        raw = open(cfg_xml, "r", encoding="utf-8", errors="ignore").read()
        m = re.search(r"<ApiKey>([^<]+)</ApiKey>", raw)
        if m and m.group(1).strip():
            api_key = m.group(1).strip()
            break
    time.sleep(1)

if not api_key:
    raise RuntimeError(f"Timed out waiting for {cfg_xml} ApiKey")

url = f"http://127.0.0.1:{port}/api/{api_ver}/config/host"
headers = {"X-Api-Key": api_key, "Content-Type": "application/json"}
cfg = None
for _ in range(45):
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=5) as resp:
            cfg = json.loads(resp.read().decode("utf-8"))
            break
    except Exception:
        time.sleep(1)

if not cfg:
    raise RuntimeError(f"Timed out waiting for {url}")

cfg["authenticationMethod"] = "forms"
cfg["authenticationRequired"] = "enabled"
cfg["username"] = user
cfg["password"] = pw
cfg["passwordConfirmation"] = pw
cfg["analyticsEnabled"] = False

put_url = f"{url}/{cfg.get('id', 1)}"
req2 = urllib.request.Request(put_url, data=json.dumps(cfg).encode("utf-8"), headers=headers, method="PUT")
with urllib.request.urlopen(req2, timeout=10) as resp2:
    resp2.read()
PYEOF
}

seed_jellyfin_master_user() {
    local port="${1:-8096}"
    python3 - "$port" "${MASTER_USER}" "${MASTER_PASS}" >> "$LOGFILE" 2>&1 <<'PYEOF' || log_warn "Non-fatal warning seeding Jellyfin master user"
import sys, time, json, urllib.request

port, user, pw = sys.argv[1:4]
base = f"http://127.0.0.1:{port}"
headers = {
    "Content-Type": "application/json",
    "X-Emby-Authorization": 'MediaBrowser Client="AetherFlow", Device="Server", DeviceId="aetherflow-setup", Version="1.0.0"'
}

pub = None
for _ in range(45):
    try:
        req = urllib.request.Request(f"{base}/System/Info/Public", headers=headers)
        with urllib.request.urlopen(req, timeout=5) as r:
            pub = json.loads(r.read().decode("utf-8"))
            break
    except Exception:
        time.sleep(1)

if not pub or pub.get("StartupWizardCompleted") is True:
    sys.exit(0)

def call(path, method="GET", body=None):
    data = json.dumps(body).encode("utf-8") if body is not None else (b"" if method == "POST" else None)
    req = urllib.request.Request(f"{base}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=10) as r:
        raw = r.read().decode("utf-8")
        return json.loads(raw) if raw else None

cfg = call("/Startup/Configuration", "GET") or {
    "UICulture": "en-US",
    "MetadataCountryCode": "US",
    "PreferredMetadataLanguage": "en"
}
call("/Startup/Configuration", "POST", cfg)
call("/Startup/User", "GET")
call("/Startup/User", "POST", {"Name": user, "Password": pw})
call("/Startup/RemoteAccess", "POST", {"EnableRemoteAccess": True, "EnableAutomaticPortMapping": False})
call("/Startup/Complete", "POST")
PYEOF
}

load_master_credentials
