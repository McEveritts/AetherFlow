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
    if [[ "${1:-}" =~ ^[0-9]+$ && -n "${2:-}" ]]; then
        rc="$1"
        msg="$2"
    fi
    [[ "$rc" -ne 0 ]] || rc=1
    if declare -F af_write_failure_receipt >/dev/null 2>&1; then
        af_write_failure_receipt "$rc" "${AF_CURRENT_STAGE:-build}" "installer" "$msg"
    fi
    if declare -F print_error >/dev/null 2>&1; then
        print_error "$msg"
    else
        printf 'ERROR: %s\n' "$msg" >&2
    fi
}

_youtube_git() {
    if [[ -n "${APP_NAME:-}" ]] && id "$APP_NAME" >/dev/null 2>&1; then
        local _app_home
        _app_home="$(getent passwd "$APP_NAME" | cut -d: -f6 2>/dev/null || true)"
        [[ -n "$_app_home" ]] || _app_home="/tmp"
        runuser -u "$APP_NAME" -- env -i \
            PATH="/usr/local/bin:/usr/bin:/bin" \
            HOME="$_app_home" \
            USER="$APP_NAME" \
            LOGNAME="$APP_NAME" \
            LANG="C.UTF-8" \
            git "$@"
    else
        git "$@"
    fi
}

youtube_source() {
    local repo="$1" destination="$2" dir="$2"
    local repo_url="https://github.com/${repo}.git"
    local target_ref=""
    if [[ $# -ge 3 ]]; then
        target_ref="$3"
    else
        target_ref="${AF_TARGET_VERSION:-}"
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
    if [[ -z "$target_ref" ]]; then
        if [[ -d "${dir}/.git" ]]; then
            af_logged _youtube_git -C "$dir" fetch --depth 1 origin HEAD && \
            af_logged _youtube_git -C "$dir" checkout --detach FETCH_HEAD && \
            af_logged _youtube_git -C "$dir" reset --hard FETCH_HEAD
        else
            af_logged _youtube_git clone --depth 1 "$repo_url" "$destination"
        fi
        return 0
    fi

    if ! target_ref="$(python3 -I -c '
import sys

raw = sys.argv[1]
trimmed = raw.strip()
forbidden = frozenset((
    "latest", "unknown", "none", "null", "undefined", "error", "n/a", "na",
    "current", "installed", "pending", "default", "auto", "true", "false",
    "head", "main", "master", "stable", "beta", "nightly", "edge", "dev",
    "devel", "alpha", "rc", "release",
))
bad_chars = frozenset(";&|`$()<>\"'\''*?!{}[]^~:\\")

if (
    not trimmed
    or trimmed != raw
    or len(trimmed) > 256
    or trimmed.startswith("-")
    or ".." in trimmed
    or "@{" in trimmed
    or "/" in trimmed
    or any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F or ch in bad_chars for ch in trimmed)
    or trimmed.lower() in forbidden
):
    sys.exit(1)
print(trimmed)
' "$target_ref")"; then
        youtube_abort_install "Invalid requested target ref ${target_ref} for ${repo}"
        exit 1
    fi

    local remote_tags="" resolved_output="" selected_kind="" selected_tag="" expected_commit=""
    if ! remote_tags="$(_youtube_git ls-remote --tags "$repo_url")"; then
        youtube_abort_install "Failed to query remote tags from ${repo_url}"
        exit 1
    fi

    if ! resolved_output="$(python3 -I -c '
import re, sys

target = sys.argv[1]
repo_url = sys.argv[2]

direct = {}
peeled = {}
for line in sys.stdin.read().splitlines():
    line = line.strip()
    if not line:
        continue
    parts = line.split()
    if len(parts) < 2:
        continue
    sha, ref = parts[0].lower(), parts[1]
    if not re.fullmatch(r"[0-9a-f]{7,64}", sha):
        continue
    if not ref.startswith("refs/tags/"):
        continue
    if ref.endswith("^{}"):
        name = ref[len("refs/tags/"):-3]
        if name:
            peeled[name] = sha
    else:
        name = ref[len("refs/tags/"):]
        if name:
            direct[name] = sha

resolved = {name: peeled.get(name, sha) for name, sha in direct.items()}

def strip_prefix(value):
    clean = re.sub(r"^(?:[rR]elease-)", "", value)
    clean = re.sub(r"^[vV]", "", clean)
    return clean

def valid_tag_name(name):
    return (
        bool(name)
        and not name.startswith("-")
        and ".." not in name
        and "@{" not in name
        and "/" not in name
        and not any(ch.isspace() or ord(ch) < 0x20 or ord(ch) == 0x7F for ch in name)
    )

if target in resolved and valid_tag_name(target):
    print("tag")
    print(target)
    print(resolved[target])
    sys.exit(0)

clean = strip_prefix(target)
candidates = []
for candidate in (
    f"v{clean}",
    clean,
    f"V{clean}",
    f"release-{clean}",
    f"release-v{clean}",
    f"Release-{clean}",
    f"Release-v{clean}",
):
    if candidate and candidate not in candidates and candidate in resolved and valid_tag_name(candidate):
        candidates.append(candidate)

if candidates:
    commits = {resolved[c] for c in candidates}
    if len(commits) > 1:
        sys.stderr.write(f"Ambiguous remote tags for requested target {target!r} in {repo_url}: {candidates}\n")
        sys.exit(2)
    chosen = candidates[0]
    print("tag")
    print(chosen)
    print(resolved[chosen])
    sys.exit(0)

is_hex = bool(re.fullmatch(r"[0-9a-fA-F]{7,64}", target))
if is_hex and (not target.isdecimal() or len(target) in (40, 64)):
    lower_sha = target.lower()
    print("commit")
    print("")
    print(lower_sha)
    sys.exit(0)

sys.stderr.write(f"Requested target ref {target!r} was not found as a tag or commit SHA for {repo_url}\n")
sys.exit(3)
' "$target_ref" "$repo_url" <<< "$remote_tags")"; then
        youtube_abort_install "Failed to resolve requested target ref ${target_ref} for ${repo}"
        exit 1
    fi

    {
        IFS= read -r selected_kind
        IFS= read -r selected_tag
        IFS= read -r expected_commit
    } <<< "$resolved_output"

    if [[ -z "$selected_kind" || -z "$expected_commit" || ! "$expected_commit" =~ ^[0-9a-f]{7,64}$ ]]; then
        youtube_abort_install "Resolved Git revision metadata is invalid for ${repo} (${target_ref})"
        exit 1
    fi

    local local_tag_commit="" resolved_commit="" actual_commit=""
    if [[ "$selected_kind" == "tag" ]]; then
        if [[ -z "$selected_tag" || "$selected_tag" == -* ]]; then
            youtube_abort_install "Invalid resolved tag name ${selected_tag} for ${repo}"
            exit 1
        fi
        if [[ ! -d "${destination}/.git" ]]; then
            if ! af_logged _youtube_git clone --no-checkout --depth 1 --branch "$selected_tag" "$repo_url" "$destination"; then
                youtube_abort_install "Failed to clone ${repo} at tag ${selected_tag}"
                exit 1
            fi
        fi
        local_tag_commit="$(_youtube_git -C "$destination" rev-parse --verify --quiet "refs/tags/${selected_tag}^{commit}" 2>/dev/null || true)"
        if [[ "${local_tag_commit,,}" != "$expected_commit" ]]; then
            if ! af_logged _youtube_git -C "$destination" fetch --force --depth 1 origin "refs/tags/${selected_tag}:refs/tags/${selected_tag}"; then
                youtube_abort_install "Failed to fetch exact tag refs/tags/${selected_tag} for ${repo}"
                exit 1
            fi
            local_tag_commit="$(_youtube_git -C "$destination" rev-parse --verify --quiet "refs/tags/${selected_tag}^{commit}" 2>/dev/null || true)"
        fi
        if [[ -z "$local_tag_commit" || "${local_tag_commit,,}" != "$expected_commit" ]]; then
            youtube_abort_install "Fetched tag refs/tags/${selected_tag} resolved to ${local_tag_commit:-unknown} instead of ${expected_commit} for ${repo}"
            exit 1
        fi
    elif [[ "$selected_kind" == "commit" ]]; then
        if [[ ! -d "${destination}/.git" ]]; then
            if ! af_logged _youtube_git clone --no-checkout "$repo_url" "$destination"; then
                youtube_abort_install "Failed to clone ${repo} for commit ${expected_commit}"
                exit 1
            fi
        fi
        resolved_commit="$(_youtube_git -C "$destination" rev-parse --verify --quiet "${expected_commit}^{commit}" 2>/dev/null || true)"
        if [[ -z "$resolved_commit" || "${resolved_commit,,}" != "${expected_commit}"* ]]; then
            if (( ${#expected_commit} == 40 || ${#expected_commit} == 64 )); then
                af_logged _youtube_git -C "$destination" fetch --depth 1 origin "$expected_commit" || true
                resolved_commit="$(_youtube_git -C "$destination" rev-parse --verify --quiet "${expected_commit}^{commit}" 2>/dev/null || true)"
            fi
            if [[ -z "$resolved_commit" || "${resolved_commit,,}" != "${expected_commit}"* ]]; then
                if [[ -f "${destination}/.git/shallow" ]]; then
                    af_logged _youtube_git -C "$destination" fetch --unshallow origin || af_logged _youtube_git -C "$destination" fetch origin || true
                else
                    af_logged _youtube_git -C "$destination" fetch origin || true
                fi
                resolved_commit="$(_youtube_git -C "$destination" rev-parse --verify --quiet "${expected_commit}^{commit}" 2>/dev/null || true)"
            fi
        fi
        if [[ -z "$resolved_commit" || ! "$resolved_commit" =~ ^[0-9a-fA-F]{7,64}$ || "${resolved_commit,,}" != "${expected_commit}"* ]]; then
            youtube_abort_install "Requested commit ${target_ref} was not found in ${repo}"
            exit 1
        fi
        expected_commit="${resolved_commit,,}"
    else
        youtube_abort_install "Unsupported resolved Git revision kind ${selected_kind} for ${repo}"
        exit 1
    fi

    if ! af_logged _youtube_git -C "$destination" checkout --detach "$expected_commit" || \
       ! af_logged _youtube_git -C "$destination" reset --hard "$expected_commit"; then
        youtube_abort_install "Failed to check out requested target ref ${target_ref} for ${repo}"
        exit 1
    fi

    actual_commit="$(_youtube_git -C "$destination" rev-parse --verify --quiet "HEAD^{commit}" 2>/dev/null || _youtube_git -C "$destination" rev-parse HEAD 2>/dev/null || true)"
    if [[ -z "$actual_commit" || "${actual_commit,,}" != "$expected_commit" ]]; then
        youtube_abort_install "Checked-out HEAD (${actual_commit:-unknown}) does not match expected commit (${expected_commit}) for ${repo} (${target_ref})"
        exit 1
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
    local existing_port="" allocated_port="" needs_alloc=false
    validate_config_paths "$path"
    if [[ ! -s "$path" ]]; then
        needs_alloc=true
    else
        existing_port="$(tr -d '[:space:]' < "$path")"
        if [[ ! "$existing_port" =~ ^[0-9]{4,5}$ ]] || (( 10#$existing_port < 1024 || 10#$existing_port > 65535 )) || (( 10#$existing_port == 10#$APP_PORT )); then
            needs_alloc=true
        fi
    fi
    if [[ "$needs_alloc" == true ]]; then
        allocated_port="$(python3 -I - "$APP_PORT" "$CONFIG_DIR" "$path" <<'PY'
import os
import pathlib
import socket
import stat
import sys

used = {int(sys.argv[1])}
config_dir = pathlib.Path(sys.argv[2])
self_port_file = pathlib.Path(sys.argv[3]).resolve()
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
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)

def open_dir_nofollow(dir_path):
    p = pathlib.PurePosixPath(os.path.abspath(str(dir_path)))
    if ".." in p.parts:
        return -1
    cur = os.open("/", os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    try:
        for part in p.parts[1:]:
            nxt = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur)
            os.close(cur)
            cur = nxt
        return cur
    except OSError:
        os.close(cur)
        return -1

for directory in search_dirs:
    dfd = open_dir_nofollow(directory)
    if dfd < 0:
        continue
    try:
        for name in os.listdir(dfd):
            if not name.endswith("-port"):
                continue
            cand_path = directory / name
            if cand_path == self_port_file:
                continue
            try:
                pfd = os.open(name, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=dfd)
            except OSError:
                continue
            try:
                pst = os.fstat(pfd)
                if not stat.S_ISREG(pst.st_mode) or pst.st_size <= 0 or pst.st_size > 64:
                    continue
                raw_bytes = os.read(pfd, 65)
                if len(raw_bytes) > 64:
                    continue
                raw = raw_bytes.decode("utf-8", errors="ignore").strip()
                if raw.isdecimal():
                    used.add(int(raw))
            finally:
                os.close(pfd)
    finally:
        os.close(dfd)
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
)"
        printf '%s\n' "$allocated_port" > "$path"
    fi
    cat "$path"
}

youtube_database() {
    DB_PASSWORD="$(youtube_secret database-password)"
    systemctl enable --now postgresql.service
    (
    # Scrub parent environment via os.execvpe without placing DB_PASSWORD on process argv.
    AF_YOUTUBE_DB_PASSWORD="$DB_PASSWORD" af_logged python3 -I -c '
import os, sys
app_name = sys.argv[1]
clean_env = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "AF_YOUTUBE_DB_PASSWORD": os.environ["AF_YOUTUBE_DB_PASSWORD"],
}
os.execvpe(
    "runuser",
    ["runuser", "-u", "postgres", "--", "psql", "-v", "ON_ERROR_STOP=1", f"--set=app={app_name}"],
    clean_env,
)
' "$APP_NAME" <<'SQL'
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
        if ! af_logged runuser -u postgres -- env -i PATH="/usr/local/bin:/usr/bin:/bin" LANG="C.UTF-8" psql --dbname=postgres -v ON_ERROR_STOP=1 --set="app=$app" <<'SQL'
SELECT format('DROP DATABASE IF EXISTS %I', :'app') \gexec
SELECT format('DROP ROLE IF EXISTS %I', :'app') \gexec
SQL
        then
            print_error "Failed to drop PostgreSQL database/role for ${app}."
            return 1
        fi
        local remaining_pg=""
        if ! remaining_pg="$(runuser -u postgres -- env -i PATH="/usr/local/bin:/usr/bin:/bin" LANG="C.UTF-8" psql --dbname=postgres -v ON_ERROR_STOP=1 -X -q -tA --set="app=$app" <<'SQL'
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
