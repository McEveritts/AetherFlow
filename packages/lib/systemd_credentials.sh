# AetherFlow shared helpers: systemd quiesce/purge, readiness probes, user purge, and master/app credential seeding.
# Sourced by packages/common.sh; do not execute directly.

systemd_unit_inactive() {
    local unit="$1" require_disabled="${2:-false}" state line load_state="" active_state="" main_pid="" unit_file_state=""
    state="$(systemctl show --property=LoadState --property=ActiveState --property=MainPID --property=UnitFileState -- "$unit" 2>/dev/null)" || return 1
    while IFS= read -r line; do
        case "$line" in
            LoadState=*) load_state="${line#LoadState=}" ;;
            ActiveState=*) active_state="${line#ActiveState=}" ;;
            MainPID=*) main_pid="${line#MainPID=}" ;;
            UnitFileState=*) unit_file_state="${line#UnitFileState=}" ;;
        esac
    done <<< "$state"
    case "$active_state" in
        inactive) [[ -z "$main_pid" || "$main_pid" == 0 ]] || return 1 ;;
        failed) [[ "$main_pid" == 0 ]] || return 1 ;;
        *) return 1 ;;
    esac
    [[ "$load_state" == loaded || "$load_state" == masked || "$load_state" == not-found ]] || return 1
    if [[ "$require_disabled" == true ]]; then
        case "$unit_file_state:$load_state" in
            disabled:*|static:*|indirect:*|generated:*|masked:*|not-found:*|:not-found) ;;
            *) return 1 ;;
        esac
    fi
}

prepare_rtorrent_scoped_stop() {
    local unit_file=/etc/systemd/system/rtorrent.service policy
    # systemctl show omits empty ExecStop and ExecStopPost command arrays.
    local line load_state="" kill_mode="" exec_stop="" exec_stop_post=""
    if [[ -e "$unit_file" || -L "$unit_file" ]]; then
        # Migrate the exact stop hook written by older Marketplace installs.
        safe_config_python "$unit_file" <<'PYEOF' || return 1
import re, sys

path = sys.argv[1]
with ManagedConfig(path, create_parents=False) as config:
    previous = config.read_text()
    updated = re.sub(r'^ExecStop=/usr/bin/killall -w -s 2 /usr/bin/rtorrent[ \t]*$',
                     'KillSignal=SIGINT', previous, flags=re.MULTILINE)
    if updated != previous:
        config.write_text(updated)
PYEOF
        af_logged systemctl daemon-reload || { print_error "Failed to reload systemd before stopping rtorrent.service."; return 1; }
    fi

    if policy="$(systemctl show --property=LoadState --property=KillMode --property=ExecStop --property=ExecStopPost -- rtorrent.service)"; then
        while IFS= read -r line; do
            case "$line" in
                LoadState=*) load_state="${line#LoadState=}" ;;
                KillMode=*) kill_mode="${line#KillMode=}" ;;
                ExecStop=*) exec_stop="${line#ExecStop=}" ;;
                ExecStopPost=*) exec_stop_post="${line#ExecStopPost=}" ;;
            esac
        done <<< "$policy"
        if [[ "$load_state" == not-found ]] && systemd_unit_inactive rtorrent.service; then
            return 0
        fi
        if [[ ( "$load_state" == loaded || "$load_state" == masked ) && "$kill_mode" == control-group && -z "$exec_stop" && -z "$exec_stop_post" ]]; then
            return 0
        fi
    fi
    print_error "Cannot verify a scoped stop for rtorrent.service. Check that its systemd unit and drop-ins use KillMode=control-group with no ExecStop or ExecStopPost hooks."
    return 1
}

quiesce_services_for_rollback() {
    local unit stop_status failed=false
    local backup="${AF_ROLLBACK_BACKUP:-${BACKUP_DIR:-${RUNTIME_BACKUP:-${ABS_BACKUP_DIR:-${AF_STATE_BACKUP:-${AF_ARCHIVE_BACKUP:-unknown}}}}}}"
    local -a triggers=() workers=() ordered=()
    for unit in "$@"; do
        case "$unit" in
            *.timer|*.socket) triggers+=("$unit") ;;
            *) workers+=("$unit") ;;
        esac
    done
    ordered=("${triggers[@]}" "${workers[@]}")
    for unit in "${ordered[@]}"; do
        stop_status=0
        af_logged systemctl stop -- "$unit" || stop_status=$?
        if [[ "$stop_status" -ne 0 ]]; then
            local _unit_load_state=""
            _unit_load_state="$(systemctl show --property=LoadState -- "$unit" 2>/dev/null || true)"
            if [[ "$stop_status" -eq 5 && "$_unit_load_state" == "LoadState=not-found" ]] && systemd_unit_inactive "$unit"; then
                continue
            fi
            print_error "Incomplete rollback: failed to stop $unit; recovery backup preserved at $backup"
            failed=true
            continue
        fi

        if systemctl is-active --quiet "$unit" 2>/dev/null; then
            print_error "Incomplete rollback: failed to stop $unit; recovery backup preserved at $backup"
            failed=true
            continue
        fi

        local is_active_rc=0 is_active_output=""
        is_active_output="$(systemctl is-active "$unit" 2>/dev/null)" || is_active_rc=$?

        if [[ "$is_active_rc" -eq 0 ]]; then
            print_error "Incomplete rollback: failed to stop $unit; recovery backup preserved at $backup"
            failed=true
            continue
        fi

        case "$is_active_output" in
            active|activating|deactivating|reloading|maintenance)
                print_error "Incomplete rollback: failed to stop $unit; recovery backup preserved at $backup"
                failed=true
                continue
                ;;
        esac

        local show_raw=""
        show_raw="$(systemctl show --property=ActiveState -- "$unit" 2>/dev/null || true)"

        if [[ "$show_raw" =~ ActiveState= ]]; then
            if ! systemd_unit_inactive "$unit"; then
                print_error "Incomplete rollback: failed to stop $unit; recovery backup preserved at $backup"
                failed=true
                continue
            fi
            if [[ "$is_active_rc" -ne 3 && "$is_active_output" != "inactive" && "$is_active_output" != "failed" ]]; then
                print_error "Incomplete rollback: failed to stop $unit; recovery backup preserved at $backup"
                failed=true
                continue
            fi
        else
            if [[ "$is_active_rc" -ne 3 || ( "$is_active_output" != "inactive" && "$is_active_output" != "failed" ) ]]; then
                print_error "Incomplete rollback: failed to stop $unit; recovery backup preserved at $backup"
                failed=true
                continue
            fi
        fi
    done
    [[ "$failed" == false ]]
}

stop_systemd_unit() {
    local unit stop_status
    local -a triggers=() workers=() ordered=()
    for unit in "$@"; do
        case "$unit" in
            *.timer|*.socket) triggers+=("$unit") ;;
            *) workers+=("$unit") ;;
        esac
    done
    ordered=("${triggers[@]}" "${workers[@]}")
    for unit in "${ordered[@]}"; do
        stop_status=0
        af_logged systemctl stop -- "$unit" || stop_status=$?
        af_logged systemctl reset-failed -- "$unit" || true
        if [[ "$stop_status" == 0 ]]; then
            continue
        fi
        if systemd_unit_inactive "$unit"; then
            continue
        fi
        print_error "Cannot prove ${unit} is stopped; refusing teardown and data deletion."
        return 1
    done
}

purge_systemd_unit() {
    local unit
    local -a units=() triggers=()
    for unit in "$@"; do
        [[ "$unit" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.@:-]*$ && "$unit" != *..* ]] || return 1
        case "$unit" in
            *.service|*.timer|*.socket) ;;
            *) unit="${unit}.service" ;;
        esac
        case "$unit" in
            *.timer|*.socket) triggers+=("$unit") ;;
            *) units+=("$unit") ;;
        esac
    done
    units=("${triggers[@]}" "${units[@]}")
    for unit in "${units[@]}"; do
        stop_systemd_unit "$unit" || return 1
    done
    for unit in "${units[@]}"; do
        if ! systemctl disable -- "$unit" >/dev/null 2>&1; then
            systemd_unit_inactive "$unit" true || return 1
        fi
    done
    for unit in "${units[@]}"; do
        if ! af_logged systemctl reset-failed -- "$unit"; then
            systemd_unit_inactive "$unit" true || return 1
        fi
        rm -f "/etc/systemd/system/${unit}" || return 1
        rm -rf "/etc/systemd/system/${unit}.d" || return 1
    done
    systemctl daemon-reload
}

verify_systemd_service_active() {
    local unit="$1"
    if ! systemctl is-active --quiet "$unit"; then
        print_error "Service ${unit} is not active."
        return 1
    fi
}

resolve_app_readiness_path() {
    local app_name="${1,,}" explicit_path="${2:-}"
    app_name="${app_name%.service}"
    app_name="${app_name#af-}"
    case "$app_name:$explicit_path" in
        transmission*:/transmission/web/|transmission*:/transmission/web) printf '%s\n' /transmission/rpc; return 0 ;;
    esac
    if [[ -n "$explicit_path" && "$explicit_path" != / && "$explicit_path" != /ping ]]; then
        printf '%s\n' "$explicit_path"
        return 0
    fi
    case "$app_name" in
        gitea*|autobrr*) printf '%s\n' /api/healthz ;;
        nzbget*) printf '%s\n' /jsonrpc/version ;;
        transmission*) printf '%s\n' /transmission/rpc ;;
        filebrowser*) printf '%s\n' /health ;;
        kavita*|grafana*) printf '%s\n' /api/health ;;
        autoscan*) printf '%s\n' /health ;;
        sonarr*|radarr*|lidarr*|readarr*|prowlarr*|navidrome*|audiobookshelf*) printf '%s\n' /ping ;;
        prometheus*) printf '%s\n' /-/healthy ;;
        syncthing*) printf '%s\n' /rest/noauth/health ;;
        netdata*) printf '%s\n' /api/v1/info ;;
        jellyfin*|emby*) printf '%s\n' /System/Ping ;;
        plex*) printf '%s\n' /identity ;;
        sabnzbd*) printf '%s\n' '/api?mode=version' ;;
        bazarr*) printf '%s\n' /api/system/health ;;
        tautulli*) printf '%s\n' /status ;;
        overseerr*|jellyseerr*) printf '%s\n' /api/v1/status ;;
        vaultwarden*) printf '%s\n' /alive ;;
        n8n*) printf '%s\n' /healthz ;;
        nextcloud*) printf '%s\n' /status.php ;;
        *) printf '%s\n' "${explicit_path:-/}" ;;
    esac
}

application_readiness_url() {
    safe_config_python "$@" <<'PYEOF'
import os, re, sys, xml.etree.ElementTree as ET
app, port = sys.argv[1:]
host, base, endpoint = '127.0.0.1', '', '/'
def read_optional(filename):
    return safe_read_text(filename) if os.path.lexists(filename) else ''
if app in ('sonarr', 'radarr', 'lidarr', 'readarr', 'prowlarr'):
    raw = read_optional('/var/lib/' + app + '/config.xml')
    if raw:
        config = ET.fromstring(raw)
        host, base = config.findtext('BindAddress', host), config.findtext('UrlBase', '')
    endpoint = '/ping'
elif app in ('bazarr', 'tautulli', 'sabnzbd'):
    filename, section, host_key, base_key, endpoint = {
        'bazarr': ('/var/lib/bazarr/config/config.ini', 'general', 'ip', 'base_url', '/api/system/health'),
        'tautulli': ('/var/lib/tautulli/config.ini', 'General', 'http_host', 'http_root', '/status'),
        'sabnzbd': ('/var/lib/sabnzbd/sabnzbd.ini', 'misc', 'host', 'url_base', '/api?mode=version'),
    }[app]
    raw = read_optional(filename)
    if raw:
        values, selected = {}, False
        for line in raw.splitlines():
            if line.lstrip().startswith('['):
                selected = line.strip().lower() == '[' + section.lower() + ']'
            elif selected:
                match = re.match(r'\s*([A-Za-z_]+)\s*=\s*(.*)', line)
                if match:
                    values[match.group(1).lower()] = match.group(2).strip().strip('\'"')
        host, base = values.get(host_key, host), values.get(base_key, '')
    elif app == 'bazarr':
        raw = read_optional('/var/lib/bazarr/config/config.yaml')
        if raw:
            general = None
            try:
                import yaml
                loaded = yaml.safe_load(raw)
                if isinstance(loaded, dict) and isinstance(loaded.get('general'), dict):
                    general = loaded['general']
            except ImportError:
                general = {}
                in_general = False
                general_indent = None
                child_indent = None
                for line in raw.splitlines():
                    stripped = line.strip()
                    if not stripped or stripped.startswith('#'):
                        continue
                    indent = len(line) - len(line.lstrip(' \t'))
                    if not in_general:
                        if indent == 0 and re.match(r'^general\s*:\s*(?:#.*)?$', stripped):
                            in_general = True
                            general_indent = indent
                        continue
                    if indent <= general_indent:
                        break
                    if child_indent is None:
                        if stripped.startswith('-'):
                            continue
                        child_indent = indent
                    if indent != child_indent:
                        continue
                    match = re.match(r'^([A-Za-z0-9_]+)\s*:\s*(.*)$', stripped)
                    if match:
                        k, v = match.group(1), match.group(2).strip()
                        if v and v[0] in ('"', "'"):
                            q = v[0]
                            end_q = v.find(q, 1)
                            v = v[1:end_q] if end_q != -1 else v.strip(q)
                        else:
                            v = v.split('#', 1)[0].strip()
                        general[k] = v
            if isinstance(general, dict):
                if general.get('ip') not in (None, ''):
                    host = str(general['ip'])
                if general.get('port') not in (None, ''):
                    yaml_port = str(general['port']).strip()
                    if not yaml_port.isdecimal() or not 1 <= int(yaml_port) <= 65535:
                        raise ValueError('Unsafe retained application port')
                    port = yaml_port
                if general.get('base_url') not in (None, ''):
                    base = str(general['base_url'])
elif app == 'autoscan':
    endpoint = '/health'
    raw = read_optional('/etc/autoscan/config.yml')
    if raw:
        parsed_hosts = []
        yaml_port = None
        try:
            import yaml
            loaded = yaml.safe_load(raw)
            if isinstance(loaded, dict):
                if loaded.get('port') not in (None, ''):
                    yaml_port = str(loaded['port']).strip()
                raw_hosts = loaded.get('host')
                if isinstance(raw_hosts, list):
                    parsed_hosts = [str(item) if item is not None else '' for item in raw_hosts]
                elif isinstance(raw_hosts, str):
                    parsed_hosts = [raw_hosts]
        except ImportError:
            def strip_yaml_scalar(raw_val):
                val = raw_val.strip()
                if not val:
                    return ''
                if val[0] in ('"', "'"):
                    q = val[0]
                    end_q = val.find(q, 1)
                    return val[1:end_q] if end_q != -1 else val.strip(q)
                return val.split('#', 1)[0].strip()

            in_host = False
            for line in raw.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    continue
                indent = len(line) - len(line.lstrip(' \t'))
                if in_host:
                    if indent == 0:
                        in_host = False
                    elif stripped.startswith('-'):
                        parsed_hosts.append(strip_yaml_scalar(stripped[1:]))
                        continue
                if indent == 0:
                    m_port = re.match(r'^port\s*:\s*(.*)$', stripped)
                    if m_port:
                        val = strip_yaml_scalar(m_port.group(1))
                        if val:
                            yaml_port = val
                        continue
                    m_host = re.match(r'^host\s*:\s*(.*)$', stripped)
                    if m_host:
                        val = m_host.group(1).strip()
                        if val.startswith('['):
                            end_bracket = val.find(']')
                            inner = val[1:end_bracket] if end_bracket != -1 else val[1:]
                            if inner.strip():
                                parsed_hosts = [strip_yaml_scalar(part) for part in inner.split(',')]
                            in_host = False
                        elif val and not val.startswith('#'):
                            parsed_hosts = [strip_yaml_scalar(val)]
                            in_host = False
                        else:
                            in_host = True
        if yaml_port is not None:
            if not yaml_port.isdecimal() or not 1 <= int(yaml_port) <= 65535:
                raise ValueError('Unsafe retained application port')
            port = str(int(yaml_port))
        if parsed_hosts:
            candidates = []
            for raw_entry in parsed_hosts:
                entry = raw_entry.strip().strip('\'"')
                entry_host = entry
                entry_port = None
                if entry.startswith('['):
                    m_v6 = re.fullmatch(r'(\[[^\]]+\])(?::([0-9]+))?', entry)
                    if not m_v6:
                        raise ValueError('Unsafe retained application listener')
                    entry_host = m_v6.group(1)
                    entry_port = m_v6.group(2)
                elif ':' in entry:
                    h_part, p_part = entry.rsplit(':', 1)
                    if not p_part.isdecimal():
                        raise ValueError('Unsafe retained application port')
                    entry_host = h_part
                    entry_port = p_part
                if entry_port is not None:
                    if not entry_port.isdecimal() or not 1 <= int(entry_port) <= 65535:
                        raise ValueError('Unsafe retained application port')
                    entry_port = str(int(entry_port))
                norm_host = {'': '127.0.0.1', '*': '127.0.0.1', '0.0.0.0': '127.0.0.1', '::': '[::1]', '[::]': '[::1]'}.get(entry_host, entry_host)
                candidates.append((norm_host, entry_port))
            chosen = next((c for c in candidates if c[0] in ('127.0.0.1', 'localhost', '[::1]')), candidates[0])
            host = chosen[0]
            if chosen[1] is not None:
                port = chosen[1]
elif app == 'overseerr':
    endpoint = '/api/v1/status'
base = (base or '').strip()
if base and not base.startswith('/'):
    base = '/' + base
if base and not re.fullmatch(r'/[A-Za-z0-9._/-]*', base):
    raise ValueError('Unsafe retained application URL base')
base = base.rstrip('/')
if any(part in ('.', '..') for part in base.split('/')) or '//' in base:
    raise ValueError('Unsafe retained application URL base')
host = (host or '127.0.0.1').strip().strip('\'"')
host = {'*': '127.0.0.1', '0.0.0.0': '127.0.0.1', '::': '[::1]', '[::]': '[::1]'}.get(host, host)
if not re.fullmatch(r'[A-Za-z0-9_.:\[\]-]+', host):
    raise ValueError('Unsafe retained application listener')
if ':' in host and not host.startswith('['):
    host = '[' + host + ']'
print(f'http://{host}:{port}{base}{endpoint}')
PYEOF
}

af_local_readiness_python() {
    {
        cat <<'PYEOF'
import ipaddress
import socket


def is_local_interface_ip(target_ip):
    proc_root = pathlib.Path(os.environ.get("AF_PROC_ROOT") or "/proc")
    if target_ip.version == 4:
        fib = proc_root / "net" / "fib_trie"
        if not fib.is_file():
            return False
        try:
            lines = fib.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            return False
        in_local = False
        prev_ip = None
        for line in lines:
            if line.startswith("Local:"):
                in_local = True
                prev_ip = None
                continue
            if line and not line[0].isspace():
                in_local = False
                prev_ip = None
                continue
            if not in_local:
                continue
            stripped = line.strip()
            if stripped.startswith("|-- "):
                try:
                    prev_ip = ipaddress.IPv4Address(stripped[4:].strip())
                except ValueError:
                    prev_ip = None
            elif stripped.startswith("+-- "):
                prev_ip = None
            elif prev_ip is not None and "/32 host LOCAL" in stripped and prev_ip == target_ip:
                return True
        return False

    if6 = proc_root / "net" / "if_inet6"
    if not if6.is_file():
        return False
    try:
        lines = if6.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return False
    for line in lines:
        parts = line.split()
        if parts and len(parts[0]) == 32:
            try:
                if ipaddress.IPv6Address(bytes.fromhex(parts[0])) == target_ip:
                    return True
            except ValueError:
                continue
    return False


def resolve_localhost_loopback_ips(port):
    try:
        infos = socket.getaddrinfo("localhost", int(port), type=socket.SOCK_STREAM)
    except OSError:
        return None
    ips = set()
    for info in infos:
        addr = info[4][0].split("%", 1)[0]
        try:
            ip_obj = ipaddress.ip_address(addr)
        except ValueError:
            return None
        mapped = getattr(ip_obj, "ipv4_mapped", None) or ip_obj
        if not mapped.is_loopback:
            return None
        ips.add(mapped)
    return ips if ips else None
PYEOF
        cat
    } | safe_config_python "$@"
}

# The caller has proved the listener is local. Emit only the URL that answered.
af_wait_local_web_services() {
    local url="$1" fallback="$2" insecure_tls="$3" host_header="$4"
    shift 4
    local attempts="${AF_READINESS_ATTEMPTS:-30}" attempt unit active rc
    local -a curl_args=(--disable --noproxy '*' -fsS --connect-timeout 2 --max-time 5)
    if [[ ! "$attempts" =~ ^[1-9][0-9]{0,2}$ ]] || (( attempts > 300 )); then
        attempts=30
    fi
    if [[ -n "$url" ]]; then
        [[ "$url" == http://* || "$url" == https://* ]] || return 1
        [[ -z "$fallback" || "${fallback%%:*}" == "${url%%:*}" ]] || return 1
        curl_args+=(--proto "=${url%%:*}")
        [[ "$insecure_tls" != 1 ]] || curl_args+=(-k)
        [[ -z "$host_header" ]] || curl_args+=(-H "Host: $host_header")
    fi
    for ((attempt = 1; attempt <= attempts; attempt++)); do
        active=true
        for unit in "$@"; do
            if ! systemctl is-active --quiet "$unit"; then
                active=false
                break
            fi
        done
        if [[ "$active" == true ]]; then
            [[ -n "$url" ]] || return 0
            rc=0
            curl "${curl_args[@]}" "$url" >/dev/null 2>&1 || rc=$?
            if (( rc == 0 )); then
                printf '%s\n' "$url"
                return 0
            fi
            if (( rc == 7 )) && [[ -n "$fallback" ]] &&
                curl "${curl_args[@]}" "$fallback" >/dev/null 2>&1; then
                printf '%s\n' "$fallback"
                return 0
            fi
        fi
        if (( attempt < attempts )); then
            sleep 1
        fi
    done
    return 1
}

af_emit_readiness_record() {
    [[ "${AF_EMIT_READINESS_RECORD:-0}" == "1" ]] || return 0
    local raw_unit="${1:-}" probe_url="${2:-}" accept_auth="${3:-false}" accept_409="${4:-false}"
    local emit_unit="$raw_unit" authority="" query=""
    case "$emit_unit" in
        *.service|*.timer|*.socket) ;;
        *) emit_unit="${emit_unit}.service" ;;
    esac
    [[ "$emit_unit" =~ ^[A-Za-z0-9@._-]+\.service$ ]] || return 0
    probe_url="${probe_url%%#*}"
    [[ "$probe_url" =~ ^https?://[^[:space:][:cntrl:]\"\\]+$ ]] || return 0
    authority="${probe_url#*://}"
    authority="${authority%%[/?#]*}"
    [[ -n "$authority" && "$authority" != *@* ]] || return 0
    if [[ "$probe_url" == *\?* ]]; then
        query="${probe_url#*\?}"
        if [[ "${query,,}" =~ (^|&)(password|passwd|pass|secret|token|apikey|api_key|access_token|auth)= ]]; then
            return 0
        fi
    fi
    [[ "$accept_auth" == "true" ]] || accept_auth="false"
    [[ "$accept_409" == "true" ]] || accept_409="false"
    printf '__AF_READINESS_PROBE__={"unit":"%s","url":"%s","accept_auth":%s,"accept_409":%s}\n' \
        "$emit_unit" "$probe_url" "$accept_auth" "$accept_409" >&2
}

af_syncthing_listener_owned_by_unit() {
    local unit="$1" port="$2" show_out="" main_pid="" cgroup="" line=""
    systemctl is-active --quiet "$unit" || return 1
    show_out="$(systemctl show --property=MainPID --property=ControlGroup -- "$unit" 2>/dev/null || true)"
    while IFS= read -r line; do
        case "$line" in
            MainPID=*) main_pid="${line#MainPID=}" ;;
            ControlGroup=*) cgroup="${line#ControlGroup=}" ;;
        esac
    done <<< "$show_out"
    python3 - "$port" "$main_pid" "$cgroup" <<'PYEOF'
import os
import pathlib
import sys

port_str, main_pid_str, cgroup = sys.argv[1:4]
try:
    port = int(port_str)
except ValueError:
    raise SystemExit(1)
if not (1 <= port <= 65535):
    raise SystemExit(1)

proc_root = pathlib.Path(os.environ.get("AF_PROC_ROOT") or "/proc")
allowed_pids = set()

if cgroup and cgroup.startswith("/") and ".." not in pathlib.PurePosixPath(cgroup).parts:
    cg_procs = pathlib.Path("/sys/fs/cgroup") / cgroup.lstrip("/") / "cgroup.procs"
    try:
        for raw in cg_procs.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = raw.strip()
            if s.isdigit() and int(s) > 1:
                allowed_pids.add(int(s))
    except OSError:
        pass

if main_pid_str.isdigit() and int(main_pid_str) > 1:
    root_pid = int(main_pid_str)
    if (proc_root / str(root_pid)).is_dir():
        allowed_pids.add(root_pid)
        children_by_ppid = {}
        try:
            for entry in proc_root.iterdir():
                if not entry.name.isdigit():
                    continue
                pid_val = int(entry.name)
                try:
                    stat_text = (entry / "stat").read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                rparen = stat_text.rfind(")")
                if rparen == -1:
                    continue
                fields = stat_text[rparen + 2:].split()
                if len(fields) >= 2 and fields[1].isdigit():
                    children_by_ppid.setdefault(int(fields[1]), []).append(pid_val)
        except OSError:
            pass
        stack = [root_pid]
        while stack:
            cur = stack.pop()
            for child in children_by_ppid.get(cur, ()):
                if child not in allowed_pids:
                    allowed_pids.add(child)
                    stack.append(child)

if not allowed_pids:
    raise SystemExit(1)

port_hex = f"{port:04X}"
allowed_v4_hex = {"0100007F", "00000000"}
allowed_v6_hex = (
    "00000000000000000000000001000000",
    "00000000000000000000000000000000",
    "0000000000000000FFFF00000100007F",
    "0000000000000000FFFF000000000000",
)

def _is_loopback_or_wildcard(ip_hex, is_v6):
    upper = ip_hex.upper()
    if is_v6:
        if upper in allowed_v6_hex:
            return True
        if upper.startswith("0000000000000000FFFF0000") and upper.endswith("7F"):
            return True
        return False
    if upper in allowed_v4_hex:
        return True
    # Little-endian 127.0.0.0/8 on x86/arm64 Linux (/proc/net/tcp)
    return len(upper) == 8 and (upper.endswith("7F") or upper.startswith("7F"))

listener_inodes = set()
for table_name, is_v6 in (("tcp", False), ("tcp6", True)):
    table_path = proc_root / "net" / table_name
    try:
        lines = table_path.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]
    except OSError:
        continue
    for line in lines:
        parts = line.split()
        if len(parts) < 10 or parts[3].upper() != "0A":
            continue
        if ":" not in parts[1]:
            continue
        ip_hex, local_port_hex = parts[1].rsplit(":", 1)
        if local_port_hex.upper() != port_hex:
            continue
        if not _is_loopback_or_wildcard(ip_hex, is_v6):
            continue
        inode = parts[9]
        if inode.isdigit() and inode != "0":
            listener_inodes.add(inode)

if not listener_inodes:
    raise SystemExit(1)

expected_targets = {f"socket:[{inode}]" for inode in listener_inodes}
for pid in allowed_pids:
    fd_dir = proc_root / str(pid) / "fd"
    try:
        entries = list(fd_dir.iterdir())
    except OSError:
        continue
    for fd_entry in entries:
        try:
            target = os.readlink(fd_entry)
        except OSError:
            continue
        if target in expected_targets:
            raise SystemExit(0)

raise SystemExit(1)
PYEOF
}

wait_for_service_ready() {
    local unit="$1" port="$2" readiness_path="${3:-/}" attempts="${4:-30}" attempt app_name credentials="" http_status ready_url
    local auth_apps_re='^(bazarr|overseerr|tautulli|flaresolverr|sabnzbd|listenarr|filebot|pihole-ftl)$'
    app_name="${unit,,}"
    app_name="${app_name%.service}"
    app_name="${app_name#af-}"
    if declare -F resolve_app_readiness_path >/dev/null; then
        readiness_path="$(resolve_app_readiness_path "$app_name" "${3:-}")"
    fi
    case "$app_name:$readiness_path" in
        sonarr:/ping|radarr:/ping|lidarr:/ping|readarr:/ping|prowlarr:/ping|autoscan:/health)
            readiness_path="$(application_readiness_url "$app_name" "$port")" || return 1 ;;
    esac
    case "$app_name" in
        transmission*) credentials="${TRANSMISSION_USER:-admin}:${TRANSMISSION_PASS:-${PASS:-}}" ;;
        nzbget*) credentials="${NZBGET_USER:-admin}:${NZBGET_PASS:-${PASS:-}}" ;;
    esac
    credentials="${credentials//\\/\\\\}"
    credentials="${credentials//\"/\\\"}"
    [[ "$credentials" != *$'\n'* && "$credentials" != *$'\r'* ]] || return 1
    [[ "$port" =~ ^[0-9]{1,5}$ && "$attempts" =~ ^[1-9][0-9]*$ ]] || return 1
    (( 10#$port > 0 && 10#$port <= 65535 )) || return 1
    local -a curl_tls_args=()
    local loopback_https_re='^https://(127(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}|\[::1\]|localhost)(:[0-9]{1,5})?(/.*)?$'
    if [[ "$readiness_path" =~ $loopback_https_re ]]; then
        ready_url="$readiness_path"
        curl_tls_args=(-k)
    elif [[ "$readiness_path" == http://* || "$readiness_path" == https://* ]]; then
        ready_url="$readiness_path"
    elif [[ "$readiness_path" == /* ]]; then
        ready_url="http://127.0.0.1:${port}${readiness_path}"
    else
        return 1
    fi
    for ((attempt = 1; attempt <= attempts; attempt++)); do
        if systemctl is-active --quiet "$unit"; then
            if [[ -n "$credentials" ]]; then
                if printf 'user = "%s"\n' "$credentials" | curl "${curl_tls_args[@]}" --noproxy '*' -K - -fsS --connect-timeout 2 --max-time 5 "$ready_url" >/dev/null 2>&1; then
                    local emit_accept_409=false
                    if [[ "$app_name" == transmission* ]]; then
                        emit_accept_409=true
                    fi
                    if declare -F af_emit_readiness_record >/dev/null 2>&1; then
                        af_emit_readiness_record "$unit" "$ready_url" true "$emit_accept_409"
                    fi
                    return 0
                fi
                if [[ "$app_name" == transmission* && "$readiness_path" == /transmission/rpc ]]; then
                    if http_status="$(printf 'user = "%s"\n' "$credentials" | curl --noproxy '*' -K - -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${port}${readiness_path}" 2>/dev/null)"; then
                        case "$http_status" in
                            200|401|409)
                                if declare -F af_emit_readiness_record >/dev/null 2>&1; then
                                    af_emit_readiness_record "$unit" "http://127.0.0.1:${port}${readiness_path}" true true
                                fi
                                return 0
                                ;;
                        esac
                    fi
                fi
            elif curl "${curl_tls_args[@]}" --noproxy '*' -fsS --connect-timeout 2 --max-time 5 "$ready_url" >/dev/null 2>&1; then
                local emit_accept_auth=false
                if [[ "$app_name" =~ $auth_apps_re ]]; then
                    emit_accept_auth=true
                fi
                if declare -F af_emit_readiness_record >/dev/null 2>&1; then
                    af_emit_readiness_record "$unit" "$ready_url" "$emit_accept_auth" false
                fi
                return 0
            elif [[ "$app_name" == syncthing* && "$readiness_path" == /rest/noauth/health ]]; then
                # Syncthing < v1.22.0 (e.g. Debian 12's 1.19.2~ds1-1+deb12u1) lacks /rest/noauth/health
                # and returns HTTP 404. Only fall back to / on 127.0.0.1:<port> when the primary endpoint
                # explicitly answered 404 AND the bound TCP listener is proven owned by the active unit.
                if http_status="$(curl "${curl_tls_args[@]}" --noproxy '*' -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' "$ready_url" 2>/dev/null)" && [[ "$http_status" == "404" ]]; then
                    local syncthing_fallback_url="http://127.0.0.1:${port}/"
                    local fallback_status=""
                    if af_syncthing_listener_owned_by_unit "$unit" "$port" && \
                        fallback_status="$(curl "${curl_tls_args[@]}" --noproxy '*' -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' "$syncthing_fallback_url" 2>/dev/null)"; then
                        case "$fallback_status" in
                            200|302|401)
                                if systemctl is-active --quiet "$unit"; then
                                    if declare -F af_emit_readiness_record >/dev/null 2>&1; then
                                        local emit_syncthing_auth=false
                                        if [[ "$fallback_status" == "401" ]]; then
                                            emit_syncthing_auth=true
                                        fi
                                        af_emit_readiness_record "$unit" "$syncthing_fallback_url" "$emit_syncthing_auth" false
                                    fi
                                    return 0
                                fi
                                ;;
                        esac
                    fi
                fi
            elif [[ "$app_name" =~ $auth_apps_re ]]; then
                if http_status="$(curl "${curl_tls_args[@]}" --noproxy '*' -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' "$ready_url" 2>/dev/null)"; then
                    case "$http_status" in
                        200|204|401|403)
                            if declare -F af_emit_readiness_record >/dev/null 2>&1; then
                                af_emit_readiness_record "$unit" "$ready_url" true false
                            fi
                            return 0
                            ;;
                    esac
                fi
            fi
        fi
        if (( attempt < attempts )); then sleep 1; fi
    done
    print_error "Service ${unit} did not become ready on port ${port}."
    return 1
}

purge_system_user() {
    local username="$1" database program status
    if [[ "${DELETE_DATA:-false}" != true && "${2:-}" != --force ]]; then
        log_info "Retaining system account ${username} because DELETE_DATA is false"
        return 0
    fi
    [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ && "$username" != root && "$username" != www-data ]] || return 1
    for database in passwd group; do
        if getent "$database" "$username" >/dev/null 2>&1; then
            if [[ "$database" == passwd ]]; then program=userdel; else program=groupdel; fi
            "$program" "$username" >/dev/null 2>&1 || return 1
        else
            status=$?
            [[ "$status" == 2 ]] || return 1
        fi
    done
    [[ "${2:-}" == --keep-home ]] || safe_rm_rf "/home/${username}"
}

load_master_credentials() {
    local u="" p="" h="" creds_json generated=false primary_creds_file="/var/lib/aetherflow/.master.creds"
    primary_creds_file="${AETHERFLOW_MASTER_CREDS_FILE:-$primary_creds_file}"
    if [[ -n "${MASTER_USER:-}" && -n "${MASTER_PASS:-}" && "$MASTER_PASS" != adminadmin ]]; then
        export MASTER_USER MASTER_PASS
        export MASTER_HA1="${MASTER_HA1:-$(printf '%s:Welcome to AetherFlow:%s' "$MASTER_USER" "$MASTER_PASS" | md5sum | awk '{print $1}')}"
        return 0
    fi
    local -a _creds_files=("$primary_creds_file")
    if [[ "${AETHERFLOW_SKIP_ENV_FILES:-0}" != "1" ]]; then
        _creds_files+=(/opt/AetherFlow/backend/data/.master.creds)
    fi
    for creds_json in "${_creds_files[@]}"; do
        if [[ -f "$creds_json" && ! -L "$creds_json" ]]; then
            local parsed_creds=""
            parsed_creds="$(python3 - "$creds_json" "$primary_creds_file" 2>/dev/null <<'PYEOF' || true
import base64, ctypes, ctypes.util, json, os, stat, sys

def _read_regular_file_nofollow(target):
    parent = os.path.dirname(os.path.abspath(target)) or "."
    pst = os.lstat(parent)
    if stat.S_ISLNK(pst.st_mode) or not stat.S_ISDIR(pst.st_mode):
        raise OSError(f"Unsafe parent directory for {target}")
    lst = os.lstat(target)
    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
        raise OSError(f"Refusing non-regular or symlinked file {target}")
    fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or (lst.st_dev, lst.st_ino) != (fst.st_dev, fst.st_ino):
            raise OSError(f"File identity changed during open for {target}")
        with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as fh:
            return fh.read()
    finally:
        os.close(fd)

def load_aes_key():
    raw = os.environ.get("AES_MASTER_KEY", "").strip()
    if not raw:
        explicit_env = os.environ.get("AETHERFLOW_ENV_FILE", "").strip()
        env_path = explicit_env if explicit_env else (
            "/etc/aetherflow/aetherflow.env" if os.environ.get("AETHERFLOW_SKIP_ENV_FILES") != "1" else ""
        )
        if env_path:
            try:
                for line in _read_regular_file_nofollow(env_path).splitlines():
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    if s.startswith("export "):
                        s = s[7:].strip()
                    if s.startswith("AES_MASTER_KEY="):
                        candidate = s.split("=", 1)[1].strip().strip("\"'")
                        if candidate:
                            raw = candidate
            except FileNotFoundError:
                raw = ""
            except OSError as exc:
                sys.stderr.write(f"Skipping unreadable env file {env_path}: {exc}\n")
    if not raw:
        return "", None
    if len(raw) == 64:
        try:
            dec_hex = bytes.fromhex(raw)
            if len(dec_hex) == 32:
                return raw, dec_hex
        except ValueError:
            pass
    try:
        dec = base64.b64decode(raw, validate=True)
        if len(dec) == 32:
            return raw, dec
    except Exception:
        pass
    raw_bytes = raw.encode("utf-8")
    return raw, (raw_bytes if len(raw_bytes) == 32 else None)

def _load_libcrypto():
    candidates = []
    found = ctypes.util.find_library("crypto")
    if found:
        candidates.append(found)
    candidates.extend(("libcrypto.so.3", "libcrypto.so.1.1"))
    for name in candidates:
        try:
            lib = ctypes.CDLL(name)
            lib.EVP_CIPHER_CTX_new.argtypes = []
            lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
            lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
            lib.EVP_CIPHER_CTX_free.restype = None
            lib.EVP_aes_256_gcm.argtypes = []
            lib.EVP_aes_256_gcm.restype = ctypes.c_void_p
            lib.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
            lib.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int
            lib.EVP_DecryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
            lib.EVP_DecryptInit_ex.restype = ctypes.c_int
            lib.EVP_DecryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_void_p, ctypes.c_int]
            lib.EVP_DecryptUpdate.restype = ctypes.c_int
            lib.EVP_DecryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
            lib.EVP_DecryptFinal_ex.restype = ctypes.c_int
            return lib
        except OSError:
            continue
    raise RuntimeError("OpenSSL libcrypto unavailable")

def aes_gcm_decrypt(key, nonce, ct_and_tag):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).decrypt(nonce, ct_and_tag, None)
    except ImportError:
        pass
    if len(nonce) != 12 or len(ct_and_tag) < 16:
        raise ValueError("invalid AES-GCM payload length")
    ct, tag = ct_and_tag[:-16], ct_and_tag[-16:]
    lib = _load_libcrypto()
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError("EVP_CIPHER_CTX_new failed")
    try:
        key_buf = (ctypes.c_ubyte * 32).from_buffer_copy(key)
        iv_buf = (ctypes.c_ubyte * 12).from_buffer_copy(nonce)
        tag_buf = (ctypes.c_ubyte * 16).from_buffer_copy(tag)
        if lib.EVP_DecryptInit_ex(ctx, lib.EVP_aes_256_gcm(), None, None, None) != 1:
            raise ValueError("EVP_DecryptInit_ex cipher failed")
        if lib.EVP_CIPHER_CTX_ctrl(ctx, 0x9, 12, None) != 1:
            raise ValueError("EVP_CTRL_GCM_SET_IVLEN failed")
        if lib.EVP_DecryptInit_ex(ctx, None, None, ctypes.byref(key_buf), ctypes.byref(iv_buf)) != 1:
            raise ValueError("EVP_DecryptInit_ex key/iv failed")
        out_buf = (ctypes.c_ubyte * max(1, len(ct) + 16))()
        out_len = ctypes.c_int(0)
        if ct:
            ct_buf = (ctypes.c_ubyte * len(ct)).from_buffer_copy(ct)
            if lib.EVP_DecryptUpdate(ctx, ctypes.byref(out_buf), ctypes.byref(out_len), ctypes.byref(ct_buf), len(ct)) != 1:
                raise ValueError("EVP_DecryptUpdate failed")
        if lib.EVP_CIPHER_CTX_ctrl(ctx, 0x11, 16, ctypes.byref(tag_buf)) != 1:
            raise ValueError("EVP_CTRL_GCM_SET_TAG failed")
        final_len = ctypes.c_int(0)
        tail_ptr = ctypes.cast(ctypes.addressof(out_buf) + out_len.value, ctypes.c_void_p)
        if lib.EVP_DecryptFinal_ex(ctx, tail_ptr, ctypes.byref(final_len)) != 1:
            raise ValueError("AES-GCM authentication failed")
        return bytes(out_buf[:out_len.value + final_len.value])
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)

def decrypt_field(val, key):
    if not isinstance(val, str):
        return ""
    val = val.strip()
    if not val.startswith("enc:v1:"):
        return val
    if key is None:
        raise ValueError("AES_MASTER_KEY missing or invalid for enc:v1: secret")
    blob = base64.b64decode(val[len("enc:v1:"):], validate=True)
    if len(blob) < 28:
        raise ValueError("enc:v1: ciphertext truncated")
    return aes_gcm_decrypt(key, blob[:12], blob[12:]).decode("utf-8")

path, primary_path = sys.argv[1], sys.argv[2]
try:
    raw_text = _read_regular_file_nofollow(path)
except OSError:
    if os.path.abspath(path) == os.path.abspath(primary_path):
        print("__AF_CREDS_FATAL__")
    raise SystemExit(0)
try:
    d = json.loads(raw_text)
except Exception:
    if "enc:v1:" in raw_text or (raw_text.strip() and os.path.abspath(path) == os.path.abspath(primary_path)):
        print("__AF_CREDS_FATAL__")
    raise SystemExit(0)
if not isinstance(d, dict):
    if os.path.abspath(path) == os.path.abspath(primary_path):
        print("__AF_CREDS_FATAL__")
    raise SystemExit(0)
_, key = load_aes_key()
u = str(d.get("username") or "").strip()
raw_pw = d.get("password") or ""
raw_ha1 = d.get("ha1") or ""
try:
    p = decrypt_field(raw_pw, key)
    h = decrypt_field(raw_ha1, key) if str(raw_ha1).strip() else ""
except Exception:
    print("__AF_CREDS_FATAL__")
    raise SystemExit(0)
if isinstance(raw_pw, str) and raw_pw.strip().startswith("enc:v1:") and not p:
    print("__AF_CREDS_FATAL__")
    raise SystemExit(0)
if p == "adminadmin":
    p = ""
print(u)
print(p)
print(h)
PYEOF
)"
            if [[ "$parsed_creds" == "__AF_CREDS_FATAL__"* ]]; then
                printf 'Refusing to overwrite undecryptable or corrupted master credentials file: %s\n' "$creds_json" >&2
                return 1
            fi
            if [[ -n "$parsed_creds" ]]; then
                u="$(printf '%s\n' "$parsed_creds" | sed -n '1p')"
                p="$(printf '%s\n' "$parsed_creds" | sed -n '2p')"
                h="$(printf '%s\n' "$parsed_creds" | sed -n '3p')"
            fi
            [[ -n "$u" && -n "$p" ]] && break
        fi
    done
    local skip_host_env="${AETHERFLOW_SKIP_ENV_FILES:-0}"
    if [[ "$skip_host_env" != "1" ]]; then
        if [[ -z "$u" || -z "$p" ]] && [[ -f /install/.aetherflow.conf && ! -L /install/.aetherflow.conf ]]; then
            local _conf_parsed=""
            _conf_parsed="$(python3 - /install/.aetherflow.conf <<'PYEOF' 2>/dev/null || true
import base64, codecs, os, re, shlex, stat, sys

target = sys.argv[1]
parent = os.path.dirname(os.path.abspath(target)) or "."
pst = os.lstat(parent)
if stat.S_ISLNK(pst.st_mode) or not stat.S_ISDIR(pst.st_mode):
    raise SystemExit(1)
lst = os.lstat(target)
if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
    raise SystemExit(1)
fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    fst = os.fstat(fd)
    if not stat.S_ISREG(fst.st_mode) or (lst.st_dev, lst.st_ino) != (fst.st_dev, fst.st_ino):
        raise SystemExit(1)
    with os.fdopen(fd, "r", encoding="utf-8", errors="replace", closefd=False) as fh:
        raw_lines = fh.read().splitlines()
finally:
    os.close(fd)

def decode_shell_value(raw_val: str) -> str:
    val = raw_val.strip()
    if not val:
        return ""
    if val.startswith("$'") and val.endswith("'") and len(val) >= 3:
        inner = val[2:-1]
        try:
            return codecs.decode(inner, "unicode_escape")
        except Exception:
            return inner
    try:
        tokens = shlex.split(val, posix=True, comments=True)
        if not tokens:
            return ""
        return tokens[0]
    except ValueError:
        if (val.startswith("'") and val.endswith("'")) or (val.startswith('"') and val.endswith('"')):
            return val[1:-1]
        return val

parsed = {}
for raw_line in raw_lines:
    s = raw_line.strip()
    if not s or s.startswith("#"):
        continue
    if s.startswith("export "):
        s = s[7:].strip()
    if "=" not in s:
        continue
    key, raw_val = s.split("=", 1)
    key = key.strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
        continue
    if key in ("username", "passwd", "ha1pass"):
        parsed[key] = decode_shell_value(raw_val)

for field in ("username", "passwd", "ha1pass"):
    print(base64.b64encode(parsed.get(field, "").encode("utf-8")).decode("ascii"))
PYEOF
)"
            if [[ -n "$_conf_parsed" ]]; then
                local _conf_u _conf_p _conf_h
                _conf_u="$(printf '%s\n' "$_conf_parsed" | sed -n '1p' | base64 -d 2>/dev/null || true)"
                _conf_p="$(printf '%s\n' "$_conf_parsed" | sed -n '2p' | base64 -d 2>/dev/null || true)"
                _conf_h="$(printf '%s\n' "$_conf_parsed" | sed -n '3p' | base64 -d 2>/dev/null || true)"
                [[ -z "$u" && -n "$_conf_u" ]] && u="$_conf_u"
                [[ -z "$p" && -n "$_conf_p" ]] && p="$_conf_p"
                [[ -z "$h" && "$_conf_h" =~ ^[0-9a-fA-F]{32}$ ]] && h="$_conf_h"
            fi
        fi
        if [[ -z "$u" && -f /etc/apache2/master.txt ]]; then
            u="$(awk -F: 'NR==1 {print $1}' /etc/apache2/master.txt 2>/dev/null | tr -d '[:space:]' || true)"
        fi
    fi
    if [[ -z "$u" ]] && command -v sqlite3 >/dev/null 2>&1; then
        local db_cand="" env_db="" env_data_dir=""
        local _creds_env_file="${AETHERFLOW_ENV_FILE:-}"
        if [[ -z "$_creds_env_file" && "$skip_host_env" != "1" ]]; then
            _creds_env_file="/etc/aetherflow/aetherflow.env"
        fi
        if [[ -n "$_creds_env_file" && -e "$_creds_env_file" ]]; then
            local _creds_env_parsed=""
            _creds_env_parsed="$(python3 - "$_creds_env_file" <<'PYEOF' 2>/dev/null || true
import os, stat, sys
target = sys.argv[1]
parent = os.path.dirname(os.path.abspath(target)) or "."
pst = os.lstat(parent)
if stat.S_ISLNK(pst.st_mode) or not stat.S_ISDIR(pst.st_mode):
    raise SystemExit(1)
lst = os.lstat(target)
if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
    raise SystemExit(1)
fd = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
try:
    fst = os.fstat(fd)
    if not stat.S_ISREG(fst.st_mode) or (lst.st_dev, lst.st_ino) != (fst.st_dev, fst.st_ino):
        raise SystemExit(1)
    with os.fdopen(fd, "r", encoding="utf-8", errors="replace", closefd=False) as fh:
        lines = fh.read().splitlines()
finally:
    os.close(fd)
env_db = ""
env_data = ""
for raw_line in lines:
    s = raw_line.strip()
    if not s or s.startswith("#"):
        continue
    if s.startswith("export "):
        s = s[7:].strip()
    if "=" not in s:
        continue
    k, v = s.split("=", 1)
    k = k.strip()
    v = v.strip().strip("\"'")
    if k in ("AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH"):
        env_db = v
    elif k == "DATA_DIR":
        env_data = v
print(env_db.replace("\n", "").replace("\r", ""))
print(env_data.replace("\n", "").replace("\r", ""))
PYEOF
)"
            if [[ -n "$_creds_env_parsed" ]]; then
                env_db="$(printf '%s\n' "$_creds_env_parsed" | sed -n '1p')"
                env_data_dir="$(printf '%s\n' "$_creds_env_parsed" | sed -n '2p')"
            fi
        fi
        local -a _creds_db_candidates=(
            "${AF_DB_PATH:-}"
            "${DB_PATH:-}"
            "${AETHERFLOW_DB_PATH:-}"
            "$env_db"
            "${DATA_DIR:+${DATA_DIR%/}/aetherflow.sqlite}"
            "${env_data_dir:+${env_data_dir%/}/aetherflow.sqlite}"
        )
        if [[ "$skip_host_env" != "1" ]]; then
            _creds_db_candidates+=(
                /var/lib/aetherflow/aetherflow.sqlite
                /opt/AetherFlow/current/data/aetherflow.sqlite
                /opt/AetherFlow/data/aetherflow.sqlite
                /opt/AetherFlow/backend/data/aetherflow.sqlite
            )
        fi
        for db_cand in "${_creds_db_candidates[@]}"; do
            if [[ -n "$db_cand" && -f "$db_cand" ]]; then
                u="$(sqlite3 "$db_cand" "SELECT username FROM users ORDER BY id ASC LIMIT 1;" 2>/dev/null | tr -d '[:space:]' || true)"
                [[ -n "$u" ]] && break
            fi
        done
    fi
    if [[ "$skip_host_env" != "1" ]]; then
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
    fi
    if [[ -z "$p" ]]; then
        p="$(python3 -c 'import secrets; print(secrets.token_hex(16))' 2>/dev/null || openssl rand -hex 16)" || return $?
        [[ "$p" =~ ^[0-9a-f]{32}$ ]] || return 1
        h=""
        generated=true
    fi
    export MASTER_USER="${u:-admin}"
    export MASTER_PASS="$p"
    if [[ ! "$h" =~ ^[0-9a-fA-F]{32}$ ]]; then
        h="$(printf '%s:Welcome to AetherFlow:%s' "$MASTER_USER" "$MASTER_PASS" | md5sum | awk '{print $1}')"
    fi
    export MASTER_HA1="$h"
    if [[ "$generated" == true ]]; then
        python3 - "$primary_creds_file" <<'PYEOF'
import base64, ctypes, ctypes.util, errno, grp, json, os, pwd, stat, sys, tempfile
username, password, ha1 = (os.environ[name] for name in ('MASTER_USER', 'MASTER_PASS', 'MASTER_HA1'))
destination = sys.argv[1]
directory = os.path.dirname(destination) or '.'

def _ensure_no_symlink_ancestors(target_dir):
    abs_dir = os.path.abspath(target_dir)
    probe = abs_dir
    while True:
        if os.path.lexists(probe):
            st = os.lstat(probe)
            if stat.S_ISLNK(st.st_mode):
                raise RuntimeError(f'Refusing symlinked credentials ancestor: {probe}')
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent

def _read_regular_file_nofollow(target):
    parent = os.path.dirname(os.path.abspath(target)) or '.'
    pst = os.lstat(parent)
    if stat.S_ISLNK(pst.st_mode) or not stat.S_ISDIR(pst.st_mode):
        raise OSError(f'Unsafe parent directory for {target}')
    lst = os.lstat(target)
    if stat.S_ISLNK(lst.st_mode) or not stat.S_ISREG(lst.st_mode):
        raise OSError(f'Refusing non-regular or symlinked file {target}')
    fd = os.open(target, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        fst = os.fstat(fd)
        if not stat.S_ISREG(fst.st_mode) or (lst.st_dev, lst.st_ino) != (fst.st_dev, fst.st_ino):
            raise OSError(f'File identity changed during open for {target}')
        with os.fdopen(fd, 'r', encoding='utf-8', closefd=False) as fh:
            return fh.read()
    finally:
        os.close(fd)

_ensure_no_symlink_ancestors(directory)
if os.path.lexists(destination):
    dst_st = os.lstat(destination)
    if stat.S_ISLNK(dst_st.st_mode) or not stat.S_ISREG(dst_st.st_mode):
        raise RuntimeError(f'Refusing symlinked or non-regular master credentials path at {destination}')
    existing_raw = _read_regular_file_nofollow(destination)
    if 'enc:v1:' in existing_raw:
        raise RuntimeError(f'Refusing to overwrite encrypted master credentials at {destination}')

def resolve_aes_key():
    raw = os.environ.get('AES_MASTER_KEY', '').strip()
    if not raw:
        explicit_env = os.environ.get('AETHERFLOW_ENV_FILE', '').strip()
        env_path = explicit_env if explicit_env else (
            '/etc/aetherflow/aetherflow.env' if os.environ.get('AETHERFLOW_SKIP_ENV_FILES') != '1' else ''
        )
        if env_path:
            try:
                for line in _read_regular_file_nofollow(env_path).splitlines():
                    s = line.strip()
                    if not s or s.startswith('#'):
                        continue
                    if s.startswith('export '):
                        s = s[7:].strip()
                    if s.startswith('AES_MASTER_KEY='):
                        candidate = s.split('=', 1)[1].strip().strip("\"'")
                        if candidate:
                            raw = candidate
            except FileNotFoundError:
                raw = ''
            except OSError as exc:
                sys.stderr.write(f'Skipping unreadable env file {env_path}: {exc}\n')
    if not raw:
        return '', None
    if len(raw) == 64:
        try:
            dec_hex = bytes.fromhex(raw)
            if len(dec_hex) == 32:
                return raw, dec_hex
        except ValueError:
            pass
    try:
        dec = base64.b64decode(raw, validate=True)
        if len(dec) == 32:
            return raw, dec
    except Exception:
        pass
    raw_bytes = raw.encode('utf-8')
    return raw, (raw_bytes if len(raw_bytes) == 32 else None)

def _load_libcrypto():
    candidates = []
    found = ctypes.util.find_library('crypto')
    if found:
        candidates.append(found)
    candidates.extend(('libcrypto.so.3', 'libcrypto.so.1.1'))
    for name in candidates:
        try:
            lib = ctypes.CDLL(name)
            lib.EVP_CIPHER_CTX_new.argtypes = []
            lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
            lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
            lib.EVP_CIPHER_CTX_free.restype = None
            lib.EVP_aes_256_gcm.argtypes = []
            lib.EVP_aes_256_gcm.restype = ctypes.c_void_p
            lib.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
            lib.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_int
            lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
            lib.EVP_EncryptInit_ex.restype = ctypes.c_int
            lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_void_p, ctypes.c_int]
            lib.EVP_EncryptUpdate.restype = ctypes.c_int
            lib.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
            lib.EVP_EncryptFinal_ex.restype = ctypes.c_int
            return lib
        except OSError:
            continue
    raise RuntimeError('OpenSSL libcrypto unavailable')

def aes_gcm_encrypt(key, nonce, pt):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).encrypt(nonce, pt, None)
    except ImportError:
        pass
    lib = _load_libcrypto()
    ctx = lib.EVP_CIPHER_CTX_new()
    if not ctx:
        raise RuntimeError('EVP_CIPHER_CTX_new failed')
    try:
        key_buf = (ctypes.c_ubyte * 32).from_buffer_copy(key)
        iv_buf = (ctypes.c_ubyte * 12).from_buffer_copy(nonce)
        if lib.EVP_EncryptInit_ex(ctx, lib.EVP_aes_256_gcm(), None, None, None) != 1:
            raise RuntimeError('EVP_EncryptInit_ex cipher failed')
        if lib.EVP_CIPHER_CTX_ctrl(ctx, 0x9, 12, None) != 1:
            raise RuntimeError('EVP_CTRL_GCM_SET_IVLEN failed')
        if lib.EVP_EncryptInit_ex(ctx, None, None, ctypes.byref(key_buf), ctypes.byref(iv_buf)) != 1:
            raise RuntimeError('EVP_EncryptInit_ex key/iv failed')
        out_buf = (ctypes.c_ubyte * max(1, len(pt) + 16))()
        out_len = ctypes.c_int(0)
        if pt:
            pt_buf = (ctypes.c_ubyte * len(pt)).from_buffer_copy(pt)
            if lib.EVP_EncryptUpdate(ctx, ctypes.byref(out_buf), ctypes.byref(out_len), ctypes.byref(pt_buf), len(pt)) != 1:
                raise RuntimeError('EVP_EncryptUpdate failed')
        final_len = ctypes.c_int(0)
        tail_ptr = ctypes.cast(ctypes.addressof(out_buf) + out_len.value, ctypes.c_void_p)
        if lib.EVP_EncryptFinal_ex(ctx, tail_ptr, ctypes.byref(final_len)) != 1:
            raise RuntimeError('EVP_EncryptFinal_ex failed')
        tag_buf = (ctypes.c_ubyte * 16)()
        if lib.EVP_CIPHER_CTX_ctrl(ctx, 0x10, 16, ctypes.byref(tag_buf)) != 1:
            raise RuntimeError('EVP_CTRL_GCM_GET_TAG failed')
        return bytes(out_buf[:out_len.value + final_len.value]) + bytes(tag_buf)
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)

def maybe_encrypt(plaintext, raw_key, key):
    if not raw_key:
        return plaintext
    if key is None:
        raise RuntimeError('AES_MASTER_KEY is configured but is not a valid 32-byte key')
    nonce = os.urandom(12)
    ct = aes_gcm_encrypt(key, nonce, plaintext.encode('utf-8'))
    return 'enc:v1:' + base64.b64encode(nonce + ct).decode('ascii')

raw_key, key = resolve_aes_key()
stored_password = maybe_encrypt(password, raw_key, key)
stored_ha1 = maybe_encrypt(ha1, raw_key, key)
temporary = None
try:
    aetherflow_owner = None
    if os.geteuid() == 0 and destination == '/var/lib/aetherflow/.master.creds':
        try:
            pw = pwd.getpwnam('aetherflow')
            try:
                gid = grp.getgrnam('aetherflow').gr_gid
            except KeyError:
                gid = pw.pw_gid
            aetherflow_owner = (pw.pw_uid, gid)
        except KeyError:
            aetherflow_owner = None
    _ensure_no_symlink_ancestors(directory)
    os.makedirs(directory, mode=0o700, exist_ok=True)
    dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        os.fchmod(dir_fd, 0o700)
        if aetherflow_owner is not None:
            os.fchown(dir_fd, *aetherflow_owner)
    finally:
        os.close(dir_fd)
    if os.path.lexists(destination) and stat.S_ISLNK(os.lstat(destination).st_mode):
        raise RuntimeError(f'Refusing symlinked master credentials destination: {destination}')
    descriptor, temporary = tempfile.mkstemp(prefix='.master.creds.', dir=directory)
    with os.fdopen(descriptor, 'w') as output:
        os.fchmod(output.fileno(), 0o600)
        if aetherflow_owner is not None:
            os.fchown(output.fileno(), *aetherflow_owner)
        json.dump({'username': username, 'password': stored_password, 'ha1': stored_ha1}, output)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    if os.path.lexists(destination) and stat.S_ISLNK(os.lstat(destination).st_mode):
        raise RuntimeError(f'Refusing symlinked master credentials destination: {destination}')
    os.replace(temporary, destination)
    temporary = None
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | getattr(os, 'O_NOFOLLOW', 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
except OSError as error:
    if (
        error.errno in (errno.EACCES, errno.EPERM)
        and os.geteuid() != 0
        and 'AETHERFLOW_MASTER_CREDS_FILE' not in os.environ
        and destination == '/var/lib/aetherflow/.master.creds'
    ):
        pass
    elif error.errno not in (errno.EROFS, errno.ENODEV, errno.ENXIO):
        raise
finally:
    if temporary is not None:
        try:
            os.unlink(temporary)
        except OSError as error:
            if error.errno not in (errno.ENOENT, errno.EROFS, errno.ENODEV, errno.ENXIO):
                raise
PYEOF
    fi
}

derive_app_password() {
    local app_id="${1:?Application id is required for derive_app_password}"
    local master_secret="${2:-${MASTER_PASS:-}}"
    if [[ -z "$master_secret" ]]; then
        load_master_credentials || return $?
        master_secret="$MASTER_PASS"
    fi
    AF_DERIVE_APP="$app_id" AF_DERIVE_SECRET="$master_secret" python3 - <<'PYEOF'
import hashlib, hmac, os
app_id = os.environ["AF_DERIVE_APP"].strip().lower()
secret = os.environ["AF_DERIVE_SECRET"].encode("utf-8")
msg = f"aetherflow:{app_id}:webui:v1".encode("utf-8")
print(hmac.new(secret, msg, hashlib.sha256).hexdigest()[:32])
PYEOF
}

generate_qbittorrent_pbkdf2() {
    if [[ -z "${1:-}" && -z "${MASTER_PASS:-}" ]]; then
        load_master_credentials || return $?
    fi
    local pass="${1:-${MASTER_PASS:-}}"
    [[ -n "$pass" ]] || return 1
    AF_SEED_PASS="$pass" python3 -c '
import os, hashlib, base64
pw = os.environ["AF_SEED_PASS"].encode("utf-8")
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac("sha512", pw, salt, 100000, 64)
print(f"@ByteArray({base64.b64encode(salt).decode()}:{base64.b64encode(dk).decode()})")
'
}

seed_servarr_master_user() {
    local app="$1"
    local port="$2"
    local api_ver="${3:-v3}"
    local cfg_xml="/var/lib/${app}/config.xml"
    local keep_secrets="${AF_KEEP_EXISTING_SECRETS:-0}"
    if declare -F keep_existing_secrets_enabled >/dev/null 2>&1 && keep_existing_secrets_enabled; then
        keep_secrets="1"
    fi
    AF_SEED_USER="$MASTER_USER" AF_SEED_PASS="${AF_CONFIG_PASS:-${AF_PASS:-$MASTER_PASS}}" AF_KEEP_SECRETS_FLAG="$keep_secrets" AF_FORCE_PASSWORD_ROTATION="${AF_FORCE_PASSWORD_ROTATION:-0}" AF_CONFIG_PASS="${AF_CONFIG_PASS:-${AF_PASS:-}}" af_logged python3 - "$app" "$port" "$api_ver" "$cfg_xml" <<'PYEOF'
import sys, os, re, time, json, urllib.request

app, port, api_ver, cfg_xml = sys.argv[1:]
user, pw = os.environ["AF_SEED_USER"], os.environ["AF_SEED_PASS"]
keep_raw = str(os.environ.get("AF_KEEP_EXISTING_SECRETS") or os.environ.get("AF_KEEP_SECRETS_FLAG") or "").strip().lower()
keep_secrets = keep_raw in ("1", "true", "yes", "on")
rotate = (not keep_secrets) and (os.environ.get("AF_FORCE_PASSWORD_ROTATION") == "1" or bool(os.environ.get("AF_CONFIG_PASS")))
api_key = ""
url_base = ""
for _ in range(45):
    if os.path.exists(cfg_xml):
        raw = open(cfg_xml, "r", encoding="utf-8", errors="ignore").read()
        m = re.search(r"<ApiKey>([^<]+)</ApiKey>", raw)
        if m and m.group(1).strip():
            api_key = m.group(1).strip()
            base_match = re.search(r"<UrlBase>([^<]*)</UrlBase>", raw)
            url_base = base_match.group(1).strip() if base_match else ""
            if url_base and not url_base.startswith('/'):
                url_base = '/' + url_base
            if url_base and not re.fullmatch(r'/[A-Za-z0-9._/-]*', url_base):
                raise ValueError('Unsafe retained Servarr URL base')
            url_base = url_base.rstrip('/')
            if any(part in ('.', '..') for part in url_base.split('/')) or '//' in url_base:
                raise ValueError('Unsafe retained Servarr URL base')
            break
    time.sleep(1)

if not api_key:
    raise RuntimeError(f"Timed out waiting for {cfg_xml} ApiKey")

url = f"http://127.0.0.1:{port}{url_base}/api/{api_ver}/config/host"
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

authentication_method = str(cfg.get("authenticationMethod") or "").strip().lower()
authentication_configured = authentication_method not in ("", "none") and bool(str(cfg.get("username") or "").strip())
if authentication_configured and not rotate:
    sys.exit(0)

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

seed_servarr_credentials() {
    seed_servarr_master_user "$@"
}

seed_jellyfin_master_user() {
    local port="${1:-8096}"
    local keep_secrets="${AF_KEEP_EXISTING_SECRETS:-0}"
    if declare -F keep_existing_secrets_enabled >/dev/null 2>&1 && keep_existing_secrets_enabled; then
        keep_secrets="1"
    fi
    if AF_SEED_USER="$MASTER_USER" AF_SEED_PASS="${AF_CONFIG_PASS:-${AF_PASS:-$MASTER_PASS}}" AF_SEED_CURRENT_PASS="$MASTER_PASS" AF_KEEP_SECRETS_FLAG="$keep_secrets" AF_FORCE_PASSWORD_ROTATION="${AF_FORCE_PASSWORD_ROTATION:-0}" AF_CONFIG_PASS="${AF_CONFIG_PASS:-${AF_PASS:-}}" AF_SEED_EXISTING="${PRE_INSTALL_PRESENT:-false}" AF_SEED_EXISTING_CONFIG="${EXISTING_CONFIG_PRESENT:-false}" af_logged python3 - "$port" <<'PYEOF'
import http.client, os, sys, time, json, urllib.error, urllib.request

port = sys.argv[1]
user, pw = os.environ["AF_SEED_USER"], os.environ["AF_SEED_PASS"]
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

if not isinstance(pub, dict) or not pub:
    raise RuntimeError(f"Timed out waiting for {base}/System/Info/Public")
keep_raw = str(os.environ.get("AF_KEEP_EXISTING_SECRETS") or os.environ.get("AF_KEEP_SECRETS_FLAG") or "").strip().lower()
keep_secrets = keep_raw in ("1", "true", "yes", "on")
rotate = (not keep_secrets) and (os.environ.get("AF_FORCE_PASSWORD_ROTATION") == "1" or bool(os.environ.get("AF_CONFIG_PASS")))
if pub.get("StartupWizardCompleted") is True and not rotate:
    sys.exit(0)

def call(path, method="GET", body=None, retries=20):
    data = json.dumps(body).encode("utf-8") if body is not None else (b"" if method == "POST" else None)
    last_err = None
    for attempt in range(retries):
        req = urllib.request.Request(f"{base}{path}", data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                raw = r.read().decode("utf-8")
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as exc:
            if exc.code == 503 and attempt + 1 < retries:
                last_err = exc
                time.sleep(1)
                continue
            raise
        except (urllib.error.URLError, http.client.HTTPException, ConnectionError, TimeoutError, OSError) as exc:
            last_err = exc
            if attempt + 1 >= retries:
                raise
            time.sleep(1)
    raise last_err

if pub.get("StartupWizardCompleted") is True:
    authentication = call("/Users/AuthenticateByName", "POST", {"Username": user, "Pw": os.environ["AF_SEED_CURRENT_PASS"]})
    headers["X-Emby-Token"] = authentication["AccessToken"]
    call(f"/Users/{authentication['User']['Id']}/Password", "POST", {"CurrentPw": os.environ["AF_SEED_CURRENT_PASS"], "NewPw": pw})
    sys.exit(0)

startup_user = call("/Startup/User", "GET") or {}
existing_install = any(os.environ.get(name, "").lower() in ("true", "1", "yes") for name in ("AF_SEED_EXISTING", "AF_SEED_EXISTING_CONFIG"))
if existing_install and str(startup_user.get("Name") or "").strip() and not rotate:
    sys.exit(0)

cfg = call("/Startup/Configuration", "GET") or {
    "UICulture": "en-US",
    "MetadataCountryCode": "US",
    "PreferredMetadataLanguage": "en"
    }
call("/Startup/Configuration", "POST", cfg)
call("/Startup/User", "POST", {"Name": user, "Password": pw})
call("/Startup/RemoteAccess", "POST", {"EnableRemoteAccess": True, "EnableAutomaticPortMapping": False})
call("/Startup/Complete", "POST")
pub = call("/System/Info/Public")
if not isinstance(pub, dict) or pub.get("StartupWizardCompleted") is not True:
    raise RuntimeError("Server did not confirm completion of initial setup")
PYEOF
    then
        return 0
    else
        print_error "Jellyfin/Emby did not become reachable or initial user setup failed."
        return 1
    fi
}
