# AetherFlow shared helpers: Apache listeners/maintenance/quiesce, DNS/resolv.conf, locks, and domain lookup.
# Sourced by packages/common.sh; do not execute directly.

configure_apache_app_listener() {
    local package_name="$1" port="$2" apache_root="${AETHERFLOW_APACHE_ROOT:-/etc/apache2}" config staged listen_addr="127.0.0.1"
    [[ "$package_name" =~ ^[a-z0-9][a-z0-9-]*$ && "$port" =~ ^[0-9]+$ ]] || return 1
    (( port >= 1024 && port <= 65535 )) || return 1
    if [[ "${AF_APACHE_LISTEN_ALL:-0}" == "1" ]]; then
        listen_addr="0.0.0.0"
    fi
    config="aetherflow-${package_name}-listen.conf"
    mkdir -p "$apache_root/conf-available" "$apache_root/conf-enabled"
    if grep -Eq "^[[:space:]]*Listen[[:space:]]+(${listen_addr}:)?${port}([[:space:]]|$)" "$apache_root/ports.conf" 2>/dev/null; then
        rm -f -- "$apache_root/conf-enabled/$config" "$apache_root/conf-available/$config"
        log_info "Reusing existing shared Apache listener on $port"
        return 0
    fi
    staged="$(mktemp "$apache_root/conf-available/.${config}.XXXXXX")"
    if ! printf 'Listen %s:%s\n' "$listen_addr" "$port" > "$staged" || ! chmod 644 "$staged" || ! mv -f -- "$staged" "$apache_root/conf-available/$config"; then
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

apache_app_readiness_target() {
    local package_name="$1" port="$2" default_path="${3:-/}" apache_root="${AETHERFLOW_APACHE_ROOT:-/etc/apache2}" vhost_conf expected_root
    [[ "$package_name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || return 1
    (( 10#$port > 0 && 10#$port <= 65535 )) || return 1
    [[ "$default_path" == /* ]] || return 1
    vhost_conf="${apache_root}/sites-available/${package_name}.conf"
    expected_root="/var/www/${package_name}"
    if [[ ! -e "$vhost_conf" && ! -L "$vhost_conf" ]]; then
        printf 'http://127.0.0.1:%s%s\n\n' "$port" "$default_path"
        return 0
    fi
    safe_config_python "$vhost_conf" "$port" "$default_path" "$expected_root" <<'PYEOF'
import re, sys

vhost_conf, fallback_port, default_path, expected_root = sys.argv[1:5]
raw = safe_read_text(vhost_conf)

blocks = []
current = None
for line in raw.splitlines():
    stripped = line.strip()
    if not stripped or stripped.startswith('#'):
        continue
    m_open = re.match(r'^<VirtualHost\s+([^>]+)>\s*$', stripped, re.IGNORECASE)
    if m_open:
        current = {'header': m_open.group(1).strip(), 'lines': []}
        blocks.append(current)
        continue
    if re.match(r'^</VirtualHost>\s*$', stripped, re.IGNORECASE):
        current = None
        continue
    if current is not None:
        current['lines'].append(stripped)

def parse_vhost_endpoint(header):
    tokens = header.split()
    token = tokens[0] if tokens else ''
    m = re.fullmatch(r'(\[[^\]]+\]|[^:\s]+)(?::([0-9]+|\*))?', token)
    if not m:
        return '127.0.0.1', None
    raw_host, raw_port = m.group(1), m.group(2)
    port_val = raw_port if (raw_port and raw_port.isdecimal() and 1 <= int(raw_port) <= 65535) else None
    return raw_host, port_val

selected = None
for block in blocks:
    _, block_port = parse_vhost_endpoint(block['header'])
    if block_port == fallback_port:
        selected = block
        break
if selected is None and blocks:
    selected = blocks[0]

raw_host = '127.0.0.1'
port = fallback_port
if selected is not None:
    raw_host, parsed_port = parse_vhost_endpoint(selected['header'])
    if parsed_port is not None:
        port = parsed_port
    lines = selected['lines']
else:
    lines = [l.strip() for l in raw.splitlines() if l.strip() and not l.strip().startswith('#')]

host_map = {'*': '127.0.0.1', '_default_': '127.0.0.1', '0.0.0.0': '127.0.0.1', '127.0.0.1': '127.0.0.1', '::': '[::1]', '[::]': '[::1]', '::1': '[::1]', '[::1]': '[::1]'}
host = host_map.get(raw_host.lower(), raw_host)
if not re.fullmatch(r'[A-Za-z0-9_.:\[\]-]+', host):
    raise ValueError('Unsafe Apache VirtualHost listener')
if ':' in host and not host.startswith('['):
    host = '[' + host + ']'

scheme = 'http'
server_name = ''
docroot = None
aliases = []

def unquote(val):
    val = val.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
        return val[1:-1]
    return val

for line in lines:
    if re.match(r'^SSLEngine\s+on(?:\s|$|#)', line, re.IGNORECASE):
        scheme = 'https'
    m_sn = re.match(r'^ServerName\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
    if m_sn and not server_name:
        cand = unquote(m_sn.group(1))
        cand = re.sub(r'^https?://', '', cand, flags=re.IGNORECASE)
        cand = cand.split(':', 1)[0].strip()
        if re.fullmatch(r'[A-Za-z0-9._-]+', cand):
            server_name = cand
    m_dr = re.match(r'^DocumentRoot\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
    if m_dr and docroot is None:
        docroot = unquote(m_dr.group(1)).rstrip('/') or '/'
    m_al = re.match(r'^Alias\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
    if m_al:
        aliases.append((unquote(m_al.group(1)), unquote(m_al.group(5)).rstrip('/') or '/'))

expected_norm = expected_root.rstrip('/') or '/'
probe_path = default_path
if docroot is not None and docroot != expected_norm:
    for prefix, target in aliases:
        if target == expected_norm and re.fullmatch(r'/[A-Za-z0-9._/-]*', prefix):
            parts = prefix.split('/')
            if '..' not in parts and '.' not in parts and '//' not in prefix:
                clean_prefix = prefix.rstrip('/')
                if default_path == '/':
                    probe_path = (clean_prefix + '/') if clean_prefix else '/'
                else:
                    probe_path = clean_prefix + default_path
                break

print(f'{scheme}://{host}:{port}{probe_path}')
print(server_name)
PYEOF
}

apache_app_probe_body_is_healthy() {
    local package_name="$1" probe_file="$2" sample="" trimmed=""
    sample="$(head -c 8192 "$probe_file" 2>/dev/null | tr -d '\0' || true)"
    trimmed="${sample#"${sample%%[![:space:]]*}"}"
    if [[ "$trimmed" == '<?='* || "$trimmed" == $'\xef\xbb\xbf<?='* ]]; then
        return 1
    fi
    if printf '%s' "$sample" | LC_ALL=C grep -Eiq '<\?php([[:space:]]|$)'; then
        return 1
    fi
    if printf '%s' "$sample" | LC_ALL=C grep -Eiq '<b>(Fatal|Parse) error</b>:|(^|[[:space:]])(Fatal|Parse) error:.* in /'; then
        return 1
    fi
    if printf '%s' "$sample" | LC_ALL=C grep -Eiq 'Apache2 (Debian|Ubuntu) Default Page|<h1[^>]*>[[:space:]]*It works![[:space:]]*</h1>'; then
        return 1
    fi
    if [[ "$package_name" == "nextcloud" ]]; then
        if printf '%s' "$sample" | LC_ALL=C grep -Eiq '"installed"[[:space:]]*:[[:space:]]*false|"maintenance"[[:space:]]*:[[:space:]]*true'; then
            return 1
        fi
    fi
    return 0
}

wait_for_apache_app_ready() {
    local package_name="$1" port="$2" default_path="${3:-/}" attempts="${4:-${AF_READINESS_ATTEMPTS:-30}}"
    local attempt target_output="" ready_url="" server_name="" probe_file="" http_status="" auth_credentials="" rutorrent_token=""
    local -a target_lines=() curl_tls_args=() curl_host_args=()
    local loopback_https_re='^https://(127(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}|\[::1\]|localhost)(:[0-9]{1,5})?(/.*)?$'
    local loopback_url_re='^https?://(127(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}|\[::1\]|localhost)(:[0-9]{1,5})?(/.*)?$'

    [[ "$package_name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
    [[ "$port" =~ ^[0-9]{1,5}$ && "$attempts" =~ ^[1-9][0-9]*$ ]] || return 1
    (( 10#$port > 0 && 10#$port <= 65535 && 10#$attempts <= 300 )) || return 1
    [[ "$default_path" == /* ]] || return 1

    target_output="$(apache_app_readiness_target "$package_name" "$port" "$default_path")" || return 1
    mapfile -t target_lines <<< "$target_output"
    ready_url="${target_lines[0]:-}"
    server_name="${target_lines[1]:-}"
    [[ -n "$ready_url" ]] || return 1

    if [[ "$ready_url" =~ $loopback_https_re ]]; then
        curl_tls_args=(-k)
    fi
    if [[ -n "$server_name" ]]; then
        curl_host_args=(-H "Host: ${server_name}")
    fi
    if [[ "$package_name" == "rutorrent" && "$ready_url" =~ $loopback_url_re ]]; then
        if [[ -f /etc/aetherflow/rutorrent-proxy-token && ! -L /etc/aetherflow/rutorrent-proxy-token && -r /etc/aetherflow/rutorrent-proxy-token ]]; then
            rutorrent_token="$(tr -d '[:space:]' < /etc/aetherflow/rutorrent-proxy-token 2>/dev/null || true)"
            if [[ ! "$rutorrent_token" =~ ^[A-Za-z0-9_-]{32,128}$ ]]; then
                rutorrent_token=""
            fi
        fi
        if [[ -n "${MASTER_USER:-}" && -n "${MASTER_PASS:-}" ]]; then
            auth_credentials="${MASTER_USER}:${MASTER_PASS}"
            auth_credentials="${auth_credentials//\\/\\\\}"
            auth_credentials="${auth_credentials//\"/\\\"}"
            if [[ "$auth_credentials" == *$'\n'* || "$auth_credentials" == *$'\r'* ]]; then
                auth_credentials=""
            fi
        fi
    fi

    local probe_dir="${TMPDIR:-/tmp}"
    mkdir -p "$probe_dir" || return 1
    probe_file="$(mktemp "${probe_dir}/af-apache-ready.XXXXXX")" || return 1
    for ((attempt = 1; attempt <= attempts; attempt++)); do
        if systemctl is-active --quiet apache2; then
            : >"$probe_file"
            local primary_ok=false
            if [[ -n "$rutorrent_token" ]]; then
                if printf 'header = "X-Aetherflow-Rutorrent-Token: %s"\n' "$rutorrent_token" | curl --disable --noproxy '*' --max-filesize 2097152 "${curl_tls_args[@]}" "${curl_host_args[@]}" -K - -fsS --connect-timeout 2 --max-time 5 "$ready_url" >"$probe_file" 2>/dev/null; then
                    primary_ok=true
                fi
            elif curl --disable --noproxy '*' --max-filesize 2097152 "${curl_tls_args[@]}" "${curl_host_args[@]}" -fsS --connect-timeout 2 --max-time 5 "$ready_url" >"$probe_file" 2>/dev/null; then
                primary_ok=true
            fi
            if [[ "$primary_ok" == true ]]; then
                if apache_app_probe_body_is_healthy "$package_name" "$probe_file"; then
                    rm -f -- "$probe_file"
                    return 0
                fi
            else
                http_status="$(curl --disable --noproxy '*' --max-filesize 2097152 "${curl_tls_args[@]}" "${curl_host_args[@]}" -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' "$ready_url" 2>/dev/null || true)"
                if [[ "$http_status" == "401" ]]; then
                    if [[ -n "$auth_credentials" ]]; then
                        : >"$probe_file"
                        if printf 'user = "%s"\n' "$auth_credentials" | curl --disable --noproxy '*' --max-filesize 2097152 "${curl_tls_args[@]}" "${curl_host_args[@]}" -K - -fsS --connect-timeout 2 --max-time 5 "$ready_url" >"$probe_file" 2>/dev/null; then
                            if apache_app_probe_body_is_healthy "$package_name" "$probe_file"; then
                                rm -f -- "$probe_file"
                                return 0
                            fi
                        else
                            http_status="$(printf 'user = "%s"\n' "$auth_credentials" | curl --disable --noproxy '*' --max-filesize 2097152 "${curl_tls_args[@]}" "${curl_host_args[@]}" -K - -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' "$ready_url" 2>/dev/null || true)"
                            if [[ "$http_status" == "401" ]]; then
                                rm -f -- "$probe_file"
                                return 0
                            fi
                        fi
                    else
                        rm -f -- "$probe_file"
                        return 0
                    fi
                fi
            fi
        fi
        if (( attempt < attempts )); then sleep 1; fi
    done
    rm -f -- "$probe_file"
    print_error "Apache application ${package_name} did not become ready at ${ready_url}."
    return 1
}

apache_app_prepare_maintenance_vhost() {
    local package_name="$1" port="$2" default_path="${3:-/}"
    local apache_root="${AETHERFLOW_APACHE_ROOT:-/etc/apache2}" maint_conf
    local -a app_roots=("/var/www/${package_name}") optional_roots=()
    [[ "$package_name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 2
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || return 2
    (( 10#$port > 0 && 10#$port <= 65535 )) || return 2
    [[ "$default_path" == /* ]] || return 2
    case "$package_name" in
        nextcloud) optional_roots+=("/var/www/html/nextcloud") ;;
        rutorrent) app_roots+=("/srv/rutorrent") ;;
    esac
    maint_conf="${apache_root}/sites-available/aetherflow-${package_name}-maintenance.conf"
    safe_config_python "$apache_root" "$package_name" "$port" "$default_path" "$maint_conf" "${#app_roots[@]}" "${app_roots[@]}" "${optional_roots[@]}" <<'PYEOF'
import glob, os, posixpath, re, stat, sys

apache_root, package_name, fallback_port, default_path, maint_conf = sys.argv[1:6]
primary_count = int(sys.argv[6])
primary_roots = sys.argv[7:7 + primary_count]
optional_roots = sys.argv[7 + primary_count:]

sites_avail = os.path.join(apache_root, 'sites-available')
sites_en = os.path.join(apache_root, 'sites-enabled')
conf_en = os.path.join(apache_root, 'conf-enabled')
site_name = f'{package_name}.conf'
maint_name = f'aetherflow-{package_name}-maintenance.conf'
listen_name = f'aetherflow-{package_name}-listen.conf'
site_link = os.path.join(sites_en, site_name)
site_avail = os.path.join(sites_avail, site_name)
legacy_conf_link = os.path.join(conf_en, site_name)

def norm_path(value):
    val = value.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
        val = val[1:-1]
    if not val:
        return ''
    return posixpath.normpath(val)

def path_variants(path_str):
    out = set()
    p = norm_path(path_str)
    if p:
        out.add(p)
        if os.path.lexists(p):
            try:
                out.add(os.path.realpath(p))
            except OSError:
                pass
    return out

protected_exact = set()
protected_docroot_targets = set()
for r in primary_roots:
    vs = path_variants(r)
    protected_exact.update(vs)
    protected_docroot_targets.update(vs)
for r in optional_roots:
    vs = path_variants(r)
    protected_exact.update(vs)
    if os.path.lexists(r):
        protected_docroot_targets.update(vs)

def is_same_or_child(path_a, path_b):
    if path_a == path_b:
        return True
    prefix = path_b if path_b == '/' else path_b + '/'
    return path_a.startswith(prefix)

def path_exposes_app(candidate, is_docroot=False):
    cands = path_variants(candidate)
    for c in cands:
        for target in protected_exact:
            if is_same_or_child(c, target):
                return target
        if is_docroot:
            for target in protected_docroot_targets:
                if is_same_or_child(target, c):
                    return target
    return None

def expand_includes(pattern, optional):
    pat = norm_path(pattern)
    if not pat:
        return []
    if not os.path.isabs(pat):
        pat = os.path.join(apache_root, pat)
    matches = sorted(glob.glob(pat))
    if not matches and not optional and not os.path.lexists(pat):
        return None
    result = []
    for m in matches:
        if os.path.isdir(m):
            for entry in sorted(os.listdir(m)):
                full = os.path.join(m, entry)
                if os.path.isfile(full):
                    result.append(full)
        else:
            result.append(m)
    return result

def scan_external_file(file_path, label, depth=0, seen=None):
    if seen is None:
        seen = set()
    if depth > 3:
        return f'deep Apache Include nesting in {label}'
    if not os.path.exists(file_path):
        return f'dangling or missing Apache config {label}'
    try:
        real = os.path.realpath(file_path)
        st = os.stat(real)
        if not stat.S_ISREG(st.st_mode):
            return f'non-regular Apache config {label}'
    except OSError:
        return f'unreadable Apache config {label}'
    if real in seen:
        return None
    seen.add(real)
    try:
        with open(real, 'r', encoding='utf-8', errors='replace') as fh:
            text = fh.read()
    except OSError:
        return f'unreadable Apache config {label}'
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith('#'):
            continue
        m_dr = re.match(r'^DocumentRoot\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
        if m_dr:
            hit = path_exposes_app(m_dr.group(1), is_docroot=True)
            if hit:
                return f'external Apache config {label} DocumentRoot exposes {hit}'
            continue
        m_al = re.match(r'^(?:Alias|AliasMatch|ScriptAlias)\s+(?:"[^"]+"|\'[^\']+\'|[^\s#]+)\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
        if m_al:
            hit = path_exposes_app(m_al.group(1), is_docroot=True)
            if hit:
                return f'external Apache config {label} Alias exposes {hit}'
            continue
        m_dir = re.match(r'^<Directory\s+("([^"]+)"|\'([^\']+)\'|([^>\s]+))\s*>', line, re.IGNORECASE)
        if m_dir:
            hit = path_exposes_app(m_dir.group(1), is_docroot=False)
            if hit:
                return f'external Apache config {label} Directory exposes {hit}'
            continue
        m_inc = re.match(r'^(IncludeOptional|Include)\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
        if m_inc:
            is_opt = m_inc.group(1).lower() == 'includeoptional'
            inc_files = expand_includes(m_inc.group(2), is_opt)
            if inc_files is None:
                return f'unreadable Include in {label}'
            for inc_file in inc_files:
                blocker = scan_external_file(inc_file, f'{label}->{inc_file}', depth + 1, seen)
                if blocker:
                    return blocker
    return None

def unsupported(reason):
    print('MODE=unsupported')
    print(f'REASON={reason}')
    sys.exit(0)

for sub_label, dir_path, skip_names in (
    ('sites-enabled', sites_en, {site_name}),
    ('conf-enabled', conf_en, {site_name, listen_name}),
):
    if not os.path.isdir(dir_path):
        continue
    for entry in sorted(os.listdir(dir_path)):
        if not entry.endswith('.conf') or entry in skip_names:
            continue
        blocker = scan_external_file(os.path.join(dir_path, entry), f'{sub_label}/{entry}')
        if blocker:
            unsupported(blocker)

has_site = os.path.lexists(site_link)
has_legacy_conf = os.path.lexists(legacy_conf_link)

if not has_site and not has_legacy_conf:
    print('MODE=none')
    sys.exit(0)

if not has_site:
    print('MODE=maintenance')
    print('HAS_SITE=0')
    print('HAS_LEGACY_CONF=1')
    sys.exit(0)

# Validate sites-enabled/<app>.conf safely (fail closed on symlink escape).
try:
    if os.path.islink(site_link):
        if not os.path.isdir(sites_avail):
            raise ValueError(f'Missing Apache sites-available directory for {site_link}')
        avail_real = os.path.realpath(sites_avail)
        target_real = os.path.realpath(site_link)
        if os.path.dirname(target_real) != avail_real or os.path.basename(target_real) not in (site_name, maint_name):
            raise ValueError(f'Unsafe Apache site symlink target: {site_link}')
        if not os.path.isfile(target_real):
            raise ValueError(f'Apache site target is not a regular file: {site_link}')
        raw = safe_read_text(site_avail)
    else:
        raw = safe_read_text(site_link)
except Exception as exc:
    sys.stderr.write(f'ERROR: {exc}\n')
    sys.exit(2)

def unquote(val):
    val = val.strip()
    if len(val) >= 2 and val[0] == val[-1] and val[0] in ('"', "'"):
        return val[1:-1]
    return val

def include_is_ssl_only(pattern, optional):
    files = expand_includes(pattern, optional)
    if files is None:
        return False
    for path in files:
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                for raw_l in fh:
                    s = raw_l.strip()
                    if not s or s.startswith('#'):
                        continue
                    if not re.match(r'^SSL[A-Za-z0-9_]+\b', s, re.IGNORECASE):
                        return False
        except OSError:
            return False
    return True

def include_is_proxy_token_auth_only(pattern, optional):
    files = expand_includes(pattern, optional)
    if not files:
        return False
    for path in files:
        if not os.path.basename(path).endswith('-proxy-token.conf'):
            return False
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                saw_rule = False
                for raw_l in fh:
                    s = raw_l.strip()
                    if not s or s.startswith('#'):
                        continue
                    if not re.match(r'^Require\s+expr\b', s, re.IGNORECASE):
                        return False
                    saw_rule = True
                if not saw_rule:
                    return False
        except OSError:
            return False
    return True

blocks = []
current = None
for raw_line in raw.splitlines():
    stripped = raw_line.strip()
    if not stripped or stripped.startswith('#'):
        continue
    m_open = re.match(r'^<VirtualHost\s+([^>]+)>\s*$', stripped, re.IGNORECASE)
    if m_open:
        if current is not None:
            unsupported(f'nested VirtualHost in {site_name}')
        current = {'header': m_open.group(1).strip(), 'lines': []}
        blocks.append(current)
        continue
    if re.match(r'^</VirtualHost>\s*$', stripped, re.IGNORECASE):
        if current is None:
            unsupported(f'unmatched </VirtualHost> in {site_name}')
        current = None
        continue
    if current is not None:
        current['lines'].append(stripped)
    else:
        unsupported(f'top-level non-VirtualHost directive in {site_name}')

if current is not None or not blocks:
    unsupported(f'missing or unclosed VirtualHost block in {site_name}')

allowed_identity_re = re.compile(
    r'^(?:ServerName|ServerAlias|SSLEngine|SSLCertificateFile|SSLCertificateKeyFile|'
    r'SSLCertificateChainFile|SSLCACertificateFile|SSLProtocol|SSLCipherSuite|'
    r'SSLHonorCipherOrder|SSLCompression|SSLSessionTickets)\s+',
    re.IGNORECASE,
)

def parse_vhost_endpoint(header):
    tokens = header.split()
    token = tokens[0] if tokens else ''
    m = re.fullmatch(r'(\[[^\]]+\]|[^:\s]+)(?::([0-9]+|\*))?', token)
    if not m:
        return '127.0.0.1', None
    raw_host, raw_port = m.group(1), m.group(2)
    port_val = raw_port if (raw_port and raw_port.isdecimal() and 1 <= int(raw_port) <= 65535) else None
    return raw_host, port_val

host_map = {'*': '127.0.0.1', '_default_': '127.0.0.1', '0.0.0.0': '127.0.0.1', '127.0.0.1': '127.0.0.1', '::': '[::1]', '[::]': '[::1]', '::1': '[::1]', '[::1]': '[::1]'}
expected_norm = norm_path(primary_roots[0]) or '/'

rendered_blocks = []
probes = []
seen_probes = set()

for block in blocks:
    preserved = []
    scheme = 'http'
    server_name = ''
    docroot = None
    aliases = []
    for line in block['lines']:
        m_inc = re.match(r'^(IncludeOptional|Include)\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
        if m_inc:
            is_opt = m_inc.group(1).lower() == 'includeoptional'
            if include_is_ssl_only(m_inc.group(2), is_opt):
                preserved.append(line)
                continue
            if include_is_proxy_token_auth_only(m_inc.group(2), is_opt):
                continue
            unsupported(f'non-SSL Include directive inside VirtualHost in {site_name}')
        if allowed_identity_re.match(line):
            preserved.append(line)
        if re.match(r'^SSLEngine\s+on(?:\s|$|#)', line, re.IGNORECASE):
            scheme = 'https'
        m_sn = re.match(r'^ServerName\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
        if m_sn and not server_name:
            cand = unquote(m_sn.group(1))
            cand = re.sub(r'^https?://', '', cand, flags=re.IGNORECASE)
            cand = cand.split(':', 1)[0].strip()
            if re.fullmatch(r'[A-Za-z0-9._-]+', cand):
                server_name = cand
        m_dr = re.match(r'^DocumentRoot\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
        if m_dr and docroot is None:
            docroot = unquote(m_dr.group(1)).rstrip('/') or '/'
        m_al = re.match(r'^Alias\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))\s+("([^"]+)"|\'([^\']+)\'|([^\s#]+))', line, re.IGNORECASE)
        if m_al:
            aliases.append((unquote(m_al.group(1)), unquote(m_al.group(5)).rstrip('/') or '/'))

    raw_host, parsed_port = parse_vhost_endpoint(block['header'])
    probe_port = parsed_port or ('443' if scheme == 'https' else fallback_port)
    probe_host = host_map.get(raw_host.lower(), raw_host)
    if not re.fullmatch(r'[A-Za-z0-9_.:\[\]-]+', probe_host):
        unsupported(f'unsafe VirtualHost listener {raw_host} in {site_name}')
    if ':' in probe_host and not probe_host.startswith('['):
        probe_host = '[' + probe_host + ']'

    probe_path = default_path
    if docroot is not None and docroot != expected_norm:
        for prefix, target in aliases:
            if target == expected_norm and re.fullmatch(r'/[A-Za-z0-9._/-]*', prefix):
                parts = prefix.split('/')
                if '..' not in parts and '.' not in parts and '//' not in prefix:
                    clean_prefix = prefix.rstrip('/')
                    if default_path == '/':
                        probe_path = (clean_prefix + '/') if clean_prefix else '/'
                    else:
                        probe_path = clean_prefix + default_path
                    break

    probe_key = (f'{scheme}://{probe_host}:{probe_port}{probe_path}', server_name)
    if probe_key not in seen_probes:
        seen_probes.add(probe_key)
        probes.append(probe_key)

    lines_out = [f"<VirtualHost {block['header']}>"]
    for pl in preserved:
        lines_out.append(f'    {pl}')
    lines_out.extend([
        f'    ErrorDocument 503 "AetherFlow maintenance in progress for {package_name}"',
        '    <IfModule mod_headers.c>',
        '        Header always set Retry-After "30"',
        '        Header always set Cache-Control "no-store"',
        f'        Header always set X-AetherFlow-Maintenance "{package_name}"',
        '    </IfModule>',
        '    <IfModule mod_alias.c>',
        '        RedirectMatch 503 ^',
        '    </IfModule>',
        '    <IfModule !mod_alias.c>',
        '        <Location />',
        '            Require all denied',
        '        </Location>',
        '    </IfModule>',
        '</VirtualHost>',
    ])
    rendered_blocks.append('\n'.join(lines_out))

maint_content = '# Managed temporarily by AetherFlow during application maintenance\n' + '\n\n'.join(rendered_blocks) + '\n'
try:
    safe_write_text(maint_conf, maint_content, 0o644)
except Exception as exc:
    sys.stderr.write(f'ERROR: {exc}\n')
    sys.exit(2)

print('MODE=maintenance')
print('HAS_SITE=1')
print(f'HAS_LEGACY_CONF={1 if has_legacy_conf else 0}')
for url, sn in probes:
    print(f'PROBE={url}\t{sn}')
PYEOF
}

apache_app_capture_worker_pids() {
    local master_pid="" pid="" ppid="" stat_file="" stat_line="" _state=""
    local -a children=()
    if [[ -n "${AF_APACHE_PIDFILE:-}" && -f "${AF_APACHE_PIDFILE}" && ! -L "${AF_APACHE_PIDFILE}" ]]; then
        master_pid="$(tr -dc '0-9' < "${AF_APACHE_PIDFILE}" 2>/dev/null || true)"
    else
        master_pid="$(systemctl show --property=MainPID --value apache2 2>/dev/null || true)"
    fi
    if [[ -z "$master_pid" || ! "$master_pid" =~ ^[0-9]+$ ]] || (( 10#$master_pid <= 1 )) || [[ ! -d "/proc/${master_pid}" ]]; then
        printf '\n\n'
        return 0
    fi
    for stat_file in /proc/[0-9]*/stat; do
        [[ -r "$stat_file" ]] || continue
        pid="${stat_file#/proc/}"
        pid="${pid%/stat}"
        [[ "$pid" != "$master_pid" && "$pid" != "$$" ]] || continue
        if IFS= read -r stat_line < "$stat_file" 2>/dev/null; then
            stat_line="${stat_line##*) }"
            read -r _state ppid _ <<< "$stat_line"
            if [[ "$ppid" == "$master_pid" ]]; then
                children+=("$pid")
            fi
        fi
    done
    printf '%s\n' "$master_pid"
    local IFS=','
    printf '%s\n' "${children[*]}"
}

apache_app_drain_workers() {
    local package_name="$1" master_pid="$2" old_pids_csv="$3"
    local attempts="${AF_APACHE_DRAIN_ATTEMPTS:-30}" attempt pid ppid stat_line="" _state="" fd_link fd_target
    local -a pending=() next_pending=() protected_roots=("/var/www/${package_name}" "/var/lib/${package_name}")
    [[ -n "$master_pid" && -n "$old_pids_csv" ]] || return 0
    case "$package_name" in
        nextcloud) protected_roots+=("/var/www/html/nextcloud") ;;
        rutorrent) protected_roots+=("/srv/rutorrent") ;;
    esac
    IFS=',' read -r -a pending <<< "$old_pids_csv"
    for ((attempt = 1; attempt <= attempts; attempt++)); do
        next_pending=()
        for pid in "${pending[@]}"; do
            [[ -n "$pid" && -r "/proc/${pid}/stat" ]] || continue
            if IFS= read -r stat_line < "/proc/${pid}/stat" 2>/dev/null; then
                stat_line="${stat_line##*) }"
                read -r _state ppid _ <<< "$stat_line"
                if [[ "$ppid" == "$master_pid" ]]; then
                    next_pending+=("$pid")
                fi
            fi
        done
        if (( ${#next_pending[@]} == 0 )); then
            return 0
        fi
        pending=("${next_pending[@]}")
        if (( attempt < attempts )); then
            sleep 0.1 2>/dev/null || sleep 1
        fi
    done
    for pid in "${pending[@]}"; do
        [[ -d "/proc/${pid}/fd" ]] || continue
        for fd_link in "/proc/${pid}/fd"/*; do
            [[ -L "$fd_link" ]] || continue
            fd_target="$(readlink -- "$fd_link" 2>/dev/null || true)"
            [[ -n "$fd_target" ]] || continue
            local root_path
            for root_path in "${protected_roots[@]}"; do
                if [[ "$fd_target" == "$root_path" || "$fd_target" == "${root_path}/"* ]]; then
                    print_warn "Apache worker ${pid} still holds open file ${fd_target} after reload drain timeout"
                    return 1
                fi
            done
        done
    done
    return 0
}

apache_app_verify_quiesced() {
    local package_name="$1" probe_url="$2" server_name="${3:-}" attempts="${4:-${AF_QUIESCE_ATTEMPTS:-5}}"
    local attempt probe_dir hdr_file body_file http_status curl_rc
    local -a curl_tls_args=() curl_host_args=()
    local loopback_https_re='^https://(127(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}|\[::1\]|localhost)(:[0-9]{1,5})?(/.*)?$'

    [[ "$package_name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
    [[ "$attempts" =~ ^[1-9][0-9]*$ ]] || return 1
    if [[ "$probe_url" =~ $loopback_https_re ]]; then
        curl_tls_args=(-k)
    fi
    if [[ -n "$server_name" ]]; then
        curl_host_args=(-H "Host: ${server_name}")
    fi

    probe_dir="${TMPDIR:-/tmp}"
    mkdir -p "$probe_dir" || return 1
    hdr_file="$(mktemp "${probe_dir}/af-apache-quiesce-hdr.XXXXXX")" || return 1
    body_file="$(mktemp "${probe_dir}/af-apache-quiesce-body.XXXXXX")" || { rm -f -- "$hdr_file"; return 1; }

    for ((attempt = 1; attempt <= attempts; attempt++)); do
        if ! systemctl is-active --quiet apache2; then
            rm -f -- "$hdr_file" "$body_file"
            return 0
        fi
        : >"$hdr_file"
        : >"$body_file"
        curl_rc=0
        http_status="$(curl --disable --noproxy '*' --max-filesize 2097152 "${curl_tls_args[@]}" "${curl_host_args[@]}" \
            -sS --connect-timeout 2 --max-time 5 -D "$hdr_file" -o "$body_file" -w '%{http_code}' "$probe_url" 2>/dev/null)" || curl_rc=$?
        if [[ "$http_status" == "503" ]]; then
            if LC_ALL=C grep -Eiq "^X-AetherFlow-Maintenance:[[:space:]]*${package_name}[[:space:]]*$" "$hdr_file" 2>/dev/null || \
               LC_ALL=C grep -Fq "AetherFlow maintenance in progress for ${package_name}" "$body_file" 2>/dev/null; then
                rm -f -- "$hdr_file" "$body_file"
                return 0
            fi
        elif [[ "$http_status" == "403" ]]; then
            if LC_ALL=C grep -Eiq "^X-AetherFlow-Maintenance:[[:space:]]*${package_name}[[:space:]]*$" "$hdr_file" 2>/dev/null; then
                rm -f -- "$hdr_file" "$body_file"
                return 0
            fi
        elif [[ "$curl_rc" -eq 7 && "$http_status" == "000" ]]; then
            rm -f -- "$hdr_file" "$body_file"
            return 0
        fi
        if (( attempt < attempts )); then
            sleep 0.5 2>/dev/null || sleep 1
        fi
    done

    rm -f -- "$hdr_file" "$body_file"
    return 1
}

apache_app_swap_site_symlink() {
    local link_path="$1" target="$2" tmp_link
    tmp_link="$(mktemp -u "${link_path}.af-swap.XXXXXX")" || return 1
    if ! ln -s -- "$target" "$tmp_link"; then
        rm -f -- "$tmp_link" 2>/dev/null || true
        return 1
    fi
    if ! mv -Tf -- "$tmp_link" "$link_path"; then
        rm -f -- "$tmp_link" 2>/dev/null || true
        return 1
    fi
}

apache_app_enter_maintenance() {
    local package_name="$1" port="$2" default_path="${3:-/}" backup_dir="$4" for_rollback="${5:-false}"
    local apache_root="${AETHERFLOW_APACHE_ROOT:-/etc/apache2}"
    local site_link="${apache_root}/sites-enabled/${package_name}.conf"
    local legacy_conf_link="${apache_root}/conf-enabled/${package_name}.conf"
    local maint_conf="${apache_root}/sites-available/aetherflow-${package_name}-maintenance.conf"
    local maint_backup_dir="${backup_dir}/.af-maint-orig"
    local prep_output="" prep_rc=0 mode="" reason="" has_site="0" has_legacy_conf="0" line
    local -a probe_urls=() probe_hosts=()
    local worker_info="" master_pid="" old_pids_csv=""
    local -a worker_lines=()

    if [[ "$for_rollback" == true ]]; then
        maint_backup_dir="${backup_dir}/.af-maint-rollback"
    else
        AF_APACHE_ACTIVATED_NEW_VHOST=false
    fi

    AF_APACHE_QUIESCE_MODE="none"
    AF_APACHE_IN_MAINTENANCE=false

    if ! systemctl is-active --quiet apache2; then
        return 0
    fi

    prep_output="$(apache_app_prepare_maintenance_vhost "$package_name" "$port" "$default_path")" || prep_rc=$?
    if [[ "$prep_rc" -eq 2 ]]; then
        print_error "Refusing unsafe Apache vhost configuration for ${package_name}."
        return 1
    fi
    if [[ "$prep_rc" -eq 0 ]]; then
        while IFS= read -r line; do
            case "$line" in
                MODE=*) mode="${line#MODE=}" ;;
                REASON=*) reason="${line#REASON=}" ;;
                HAS_SITE=*) has_site="${line#HAS_SITE=}" ;;
                HAS_LEGACY_CONF=*) has_legacy_conf="${line#HAS_LEGACY_CONF=}" ;;
                PROBE=*)
                    local entry="${line#PROBE=}"
                    probe_urls+=("${entry%%$'\t'*}")
                    probe_hosts+=("${entry#*$'\t'}")
                    ;;
            esac
        done <<< "$prep_output"
    else
        mode="unsupported"
        reason="failed to prepare per-app maintenance vhost"
    fi

    if [[ "$mode" == "none" ]]; then
        return 0
    fi

    if [[ "$mode" == "maintenance" ]]; then
        mkdir -p -m 0700 -- "$maint_backup_dir" || return 1
        if [[ "$has_site" == "1" && ( -e "$site_link" || -L "$site_link" ) ]]; then
            cp -a -- "$site_link" "$maint_backup_dir/site-link" || return 1
        fi
        if [[ "$has_legacy_conf" == "1" && ( -e "$legacy_conf_link" || -L "$legacy_conf_link" ) ]]; then
            cp -a -- "$legacy_conf_link" "$maint_backup_dir/legacy-conf" || return 1
        fi

        worker_info="$(apache_app_capture_worker_pids)"
        mapfile -t worker_lines <<< "$worker_info"
        master_pid="${worker_lines[0]:-}"
        old_pids_csv="${worker_lines[1]:-}"

        local swap_ok=true
        if [[ "$has_site" == "1" ]]; then
            apache_app_swap_site_symlink "$site_link" "../sites-available/aetherflow-${package_name}-maintenance.conf" || swap_ok=false
        fi
        if [[ "$swap_ok" == true && "$has_legacy_conf" == "1" ]]; then
            rm -f -- "$legacy_conf_link" || swap_ok=false
        fi
        if [[ "$swap_ok" == true ]]; then
            if af_logged apache2ctl configtest && af_logged systemctl reload apache2; then
                local verified=true idx
                if ! apache_app_drain_workers "$package_name" "$master_pid" "$old_pids_csv"; then
                    verified=false
                fi
                if [[ "$verified" == true ]]; then
                    for idx in "${!probe_urls[@]}"; do
                        if ! apache_app_verify_quiesced "$package_name" "${probe_urls[$idx]}" "${probe_hosts[$idx]}"; then
                            verified=false
                            break
                        fi
                    done
                fi
                if [[ "$verified" == true ]]; then
                    AF_APACHE_QUIESCE_MODE="maintenance"
                    AF_APACHE_IN_MAINTENANCE=true
                    log_info "Quiesced Apache application ${package_name} via per-app maintenance vhost"
                    return 0
                fi
                reason="per-app maintenance verification did not observe quiesced traffic for ${package_name}"
            else
                reason="apache2ctl configtest or reload failed while entering maintenance for ${package_name}"
            fi
        else
            reason="failed to stage per-app maintenance symlink for ${package_name}"
        fi

        # Revert maintenance config before falling back to safe stop.
        if [[ -e "$maint_backup_dir/site-link" || -L "$maint_backup_dir/site-link" ]]; then
            safe_restore_path_from_backup "$maint_backup_dir/site-link" "$site_link" || true
        fi
        if [[ -e "$maint_backup_dir/legacy-conf" || -L "$maint_backup_dir/legacy-conf" ]]; then
            safe_restore_path_from_backup "$maint_backup_dir/legacy-conf" "$legacy_conf_link" || true
        fi
        rm -f -- "$maint_conf"
    fi

    print_warn "Per-app Apache quiescence unavailable for ${package_name} (${reason:-unsupported configuration}); falling back to stopping apache2"
    if [[ "$for_rollback" == true ]]; then
        quiesce_services_for_rollback apache2 || return 1
    else
        stop_systemd_unit apache2 || return 1
    fi
    AF_APACHE_QUIESCE_MODE="stopped"
    AF_APACHE_IN_MAINTENANCE=false
    APACHE_STOPPED=true
    RUNTIME_STOPPED=true
    return 0
}

apache_app_quiesce_for_rollback() {
    local package_name="$1" port="$2" default_path="${3:-/}" backup_dir="$4"
    if [[ "${AF_APACHE_QUIESCE_MODE:-}" == "stopped" ]]; then
        if systemd_unit_inactive apache2; then
            return 0
        fi
        quiesce_services_for_rollback apache2
        return $?
    fi
    if [[ "${AF_APACHE_IN_MAINTENANCE:-false}" == true && "${AF_APACHE_QUIESCE_MODE:-}" == "maintenance" ]]; then
        return 0
    fi
    if [[ "${AF_APACHE_ACTIVATED_NEW_VHOST:-false}" != true && "${AF_APACHE_QUIESCE_MODE:-none}" == "none" ]]; then
        return 0
    fi
    apache_app_enter_maintenance "$package_name" "$port" "$default_path" "$backup_dir" true
}

apache_app_activate_vhost() {
    local package_name="$1" backup_dir="${2:-}"
    local apache_root="${AETHERFLOW_APACHE_ROOT:-/etc/apache2}"
    local site_link="${apache_root}/sites-enabled/${package_name}.conf"
    local legacy_conf_link="${apache_root}/conf-enabled/${package_name}.conf"
    local maint_conf="${apache_root}/sites-available/aetherflow-${package_name}-maintenance.conf"
    local link_target=""

    if [[ -L "$site_link" ]]; then
        link_target="$(readlink -- "$site_link" 2>/dev/null || true)"
        if [[ "$link_target" == *"aetherflow-${package_name}-maintenance.conf" ]]; then
            apache_app_swap_site_symlink "$site_link" "../sites-available/${package_name}.conf" || return 1
        fi
    fi
    if [[ -n "$backup_dir" && ( -e "${backup_dir}/.af-maint-orig/legacy-conf" || -L "${backup_dir}/.af-maint-orig/legacy-conf" ) ]]; then
        safe_restore_path_from_backup "${backup_dir}/.af-maint-orig/legacy-conf" "$legacy_conf_link" || return 1
    fi

    af_logged a2enmod rewrite headers env dir mime
    af_logged a2ensite "${package_name}.conf"
    af_logged apache2ctl configtest
    if systemctl is-active --quiet apache2; then
        af_logged systemctl enable apache2 || true
        af_logged systemctl reload apache2
    else
        af_logged systemctl enable --now apache2
    fi

    AF_APACHE_ACTIVATED_NEW_VHOST=true
    AF_APACHE_IN_MAINTENANCE=false
    AF_APACHE_QUIESCE_MODE=""
    APACHE_STOPPED=false
    RUNTIME_STOPPED=false
    rm -f -- "$maint_conf"
}

apache_app_resume_after_rollback() {
    local package_name="$1" backup_dir="${2:-}"
    local apache_root="${AETHERFLOW_APACHE_ROOT:-/etc/apache2}"
    local legacy_conf_link="${apache_root}/conf-enabled/${package_name}.conf"
    local maint_conf="${apache_root}/sites-available/aetherflow-${package_name}-maintenance.conf"

    if [[ -n "$backup_dir" && ( -e "${backup_dir}/.af-maint-orig/legacy-conf" || -L "${backup_dir}/.af-maint-orig/legacy-conf" ) ]]; then
        safe_restore_path_from_backup "${backup_dir}/.af-maint-orig/legacy-conf" "$legacy_conf_link" || return 1
    fi
    rm -f -- "$maint_conf"

    if [[ "${AF_APACHE_QUIESCE_MODE:-}" == "stopped" || "${APACHE_STOPPED:-false}" == true || "${RUNTIME_STOPPED:-false}" == true ]]; then
        af_logged apache2ctl configtest && af_logged systemctl start apache2
        return $?
    fi
    if [[ "${AF_APACHE_QUIESCE_MODE:-}" == "maintenance" || "${AF_APACHE_ACTIVATED_NEW_VHOST:-false}" == true ]]; then
        if systemctl is-active --quiet apache2; then
            af_logged apache2ctl configtest && af_logged systemctl reload apache2
            return $?
        fi
        af_logged apache2ctl configtest && af_logged systemctl start apache2
        return $?
    fi
    return 0
}

check_dns_port_53_available() {
    local package_name="$1" competing_package="$2" self_proc_regex="$3"
    local dns_port="${4:-${AF_DNS_PORT:-53}}"
    if [[ ! "$dns_port" =~ ^[0-9]{1,5}$ ]] || (( 10#$dns_port < 1 || 10#$dns_port > 65535 )); then
        print_error "DNS port must be between 1 and 65535 (got: ${dns_port})."
        return 1
    fi
    if [[ "$dns_port" != "53" ]]; then
        return 0
    fi
    local competing_lock="/install/.${competing_package}.lock"
    if [[ -e "$competing_lock" ]]; then
        print_error "Cannot install ${package_name} on DNS port 53 while ${competing_package} is installed (${competing_lock} exists). Remove ${competing_package} first or set AF_DNS_PORT to a non-53 port."
        return 1
    fi
    if command -v ss >/dev/null 2>&1; then
        local ss_bin listeners conflict
        ss_bin="$(command -v ss)"
        if [[ -n "${TEST_ROOT:-}" && "$ss_bin" != "${TEST_ROOT}"* ]] || [[ -n "${AF_FIXTURE_ROOT:-}" && "$ss_bin" != "${AF_FIXTURE_ROOT}"* ]]; then
            return 0
        fi
        listeners="$(ss -H -lntup 'sport = :53' 2>/dev/null || true)"
        if [[ -n "$listeners" ]]; then
            conflict="$(printf '%s\n' "$listeners" | grep -Ev "users:\(\(\"(${self_proc_regex}|systemd-resolved)\"" | grep -Ev '127\.0\.0\.5[34](%[^:[:space:]]+)?:53\b' || true)"
            if [[ -n "$conflict" ]]; then
                print_error "DNS port 53 is already in use by another process; cannot safely configure ${package_name}: ${conflict%%$'\n'*}"
                return 1
            fi
        fi
    fi
    return 0
}

af_backup_resolv_conf_state() {
    local app_name="$1"
    local backup_dir="${2:-}"
    [[ -n "$backup_dir" ]] || backup_dir="/etc/aetherflow/dns-backup"
    local resolv_path="${3:-}"
    [[ -n "$resolv_path" ]] || resolv_path="/etc/resolv.conf"
    [[ "$app_name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
    python3 -I - "$app_name" "$backup_dir" "$resolv_path" <<'PYEOF'
import json, os, pathlib, secrets, stat, sys

app_name, backup_dir_str, resolv_str = sys.argv[1:4]
backup_dir = pathlib.PurePath(backup_dir_str)
resolv_path = pathlib.PurePath(resolv_str)
for label, p in (("backup_dir", backup_dir), ("resolv_path", resolv_path)):
    if not p.is_absolute() or ".." in p.parts or not p.name:
        raise ValueError(f"Invalid {label}: {p}")

o_nofollow = getattr(os, "O_NOFOLLOW", 0)
o_directory = getattr(os, "O_DIRECTORY", 0)
o_cloexec = getattr(os, "O_CLOEXEC", 0)

def open_dir_nofollow(path: pathlib.PurePath, create_mode=None):
    fd = os.open("/", os.O_RDONLY | o_directory | o_cloexec)
    try:
        for idx, comp in enumerate(path.parts[1:]):
            try:
                child = os.open(comp, os.O_RDONLY | o_directory | o_nofollow | o_cloexec, dir_fd=fd)
            except FileNotFoundError:
                if create_mode is None:
                    raise
                mode = 0o750 if idx < len(path.parts[1:]) - 1 else create_mode
                os.mkdir(comp, mode, dir_fd=fd)
                child = os.open(comp, os.O_RDONLY | o_directory | o_nofollow | o_cloexec, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise

bdir_fd = open_dir_nofollow(backup_dir, create_mode=0o700)
try:
    os.fchmod(bdir_fd, 0o700)
    state_name = f"{app_name}-resolv.conf.state"
    bak_name = f"{app_name}-resolv.conf.bak"
    try:
        st_existing = os.lstat(state_name, dir_fd=bdir_fd)
    except FileNotFoundError:
        st_existing = None
    if st_existing is not None:
        if stat.S_ISLNK(st_existing.st_mode) or not stat.S_ISREG(st_existing.st_mode):
            raise ValueError(f"Unsafe existing DNS state file: {backup_dir / state_name}")
        raise SystemExit(0)

    rdir_fd = open_dir_nofollow(resolv_path.parent, create_mode=None)
    try:
        try:
            rst = os.lstat(resolv_path.name, dir_fd=rdir_fd)
        except FileNotFoundError:
            state = {"kind": "absent"}
        else:
            if stat.S_ISLNK(rst.st_mode):
                target = os.readlink(resolv_path.name, dir_fd=rdir_fd)
                state = {"kind": "symlink", "target": target}
            elif stat.S_ISREG(rst.st_mode):
                rfd = os.open(resolv_path.name, os.O_RDONLY | o_nofollow | o_cloexec, dir_fd=rdir_fd)
                try:
                    data = os.pread(rfd, 1048576, 0)
                finally:
                    os.close(rfd)
                tmp_bak = f".{bak_name}.{secrets.token_hex(6)}"
                bfd = os.open(tmp_bak, os.O_WRONLY | os.O_CREAT | os.O_EXCL | o_nofollow | o_cloexec, 0o600, dir_fd=bdir_fd)
                try:
                    os.fchmod(bfd, 0o600)
                    os.write(bfd, data)
                    os.fsync(bfd)
                finally:
                    os.close(bfd)
                os.replace(tmp_bak, bak_name, src_dir_fd=bdir_fd, dst_dir_fd=bdir_fd)
                state = {"kind": "file", "mode": stat.S_IMODE(rst.st_mode)}
            else:
                raise ValueError(f"Unsupported /etc/resolv.conf file type: {resolv_path}")
    finally:
        os.close(rdir_fd)

    tmp_state = f".{state_name}.{secrets.token_hex(6)}"
    sfd = os.open(tmp_state, os.O_WRONLY | os.O_CREAT | os.O_EXCL | o_nofollow | o_cloexec, 0o600, dir_fd=bdir_fd)
    try:
        os.fchmod(sfd, 0o600)
        os.write(sfd, (json.dumps(state, sort_keys=True) + "\n").encode("utf-8"))
        os.fsync(sfd)
    finally:
        os.close(sfd)
    os.replace(tmp_state, state_name, src_dir_fd=bdir_fd, dst_dir_fd=bdir_fd)
finally:
    os.close(bdir_fd)
PYEOF
}

af_write_resolv_conf_nameserver() {
    local nameserver="${1:-127.0.0.1}"
    local resolv_path="${2:-}"
    [[ -n "$resolv_path" ]] || resolv_path="/etc/resolv.conf"
    python3 -I - "$nameserver" "$resolv_path" <<'PYEOF'
import os, pathlib, secrets, stat, sys

nameserver, resolv_str = sys.argv[1:3]
resolv_path = pathlib.PurePath(resolv_str)
if not resolv_path.is_absolute() or ".." in resolv_path.parts or not resolv_path.name:
    raise ValueError(f"Invalid resolv_path: {resolv_path}")

o_nofollow = getattr(os, "O_NOFOLLOW", 0)
o_directory = getattr(os, "O_DIRECTORY", 0)
o_cloexec = getattr(os, "O_CLOEXEC", 0)

fd = os.open("/", os.O_RDONLY | o_directory | o_cloexec)
try:
    for comp in resolv_path.parent.parts[1:]:
        child = os.open(comp, os.O_RDONLY | o_directory | o_nofollow | o_cloexec, dir_fd=fd)
        os.close(fd)
        fd = child
    preserved_lines = []
    try:
        with open(resolv_str, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                stripped = line.strip()
                if stripped.startswith(("search ", "domain ", "options ")):
                    preserved_lines.append(stripped)
    except FileNotFoundError:
        pass
    content = "".join(line + "\n" for line in preserved_lines) + f"nameserver {nameserver}\n"
    tmp_name = f".{resolv_path.name}.af-new.{secrets.token_hex(6)}"
    tfd = os.open(tmp_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | o_nofollow | o_cloexec, 0o644, dir_fd=fd)
    try:
        os.fchmod(tfd, 0o644)
        os.write(tfd, content.encode("utf-8"))
        os.fsync(tfd)
    finally:
        os.close(tfd)
    os.replace(tmp_name, resolv_path.name, src_dir_fd=fd, dst_dir_fd=fd)
finally:
    os.close(fd)
PYEOF
}

af_restore_resolv_conf_state() {
    local app_name="$1"
    local dropin_removed="${2:-false}"
    local backup_dir="${3:-}"
    [[ -n "$backup_dir" ]] || backup_dir="/etc/aetherflow/dns-backup"
    local resolv_path="${4:-}"
    [[ -n "$resolv_path" ]] || resolv_path="/etc/resolv.conf"
    local stub_target="${5:-}"
    [[ -n "$stub_target" ]] || stub_target="/run/systemd/resolve/stub-resolv.conf"
    [[ "$app_name" =~ ^[a-z0-9][a-z0-9-]*$ ]] || return 1
    local resolved_active="false"
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        resolved_active="true"
    fi
    python3 -I - "$app_name" "$dropin_removed" "$backup_dir" "$resolv_path" "$stub_target" "$resolved_active" <<'PYEOF'
import json, os, pathlib, secrets, stat, sys

app_name, dropin_removed, backup_dir_str, resolv_str, stub_target, resolved_active = sys.argv[1:7]
backup_dir = pathlib.PurePath(backup_dir_str)
resolv_path = pathlib.PurePath(resolv_str)
o_nofollow = getattr(os, "O_NOFOLLOW", 0)
o_directory = getattr(os, "O_DIRECTORY", 0)
o_cloexec = getattr(os, "O_CLOEXEC", 0)

def open_dir_nofollow(path: pathlib.PurePath):
    fd = os.open("/", os.O_RDONLY | o_directory | o_cloexec)
    try:
        for comp in path.parts[1:]:
            child = os.open(comp, os.O_RDONLY | o_directory | o_nofollow | o_cloexec, dir_fd=fd)
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise

rdir_fd = open_dir_nofollow(resolv_path.parent)
try:
    bdir_fd = None
    try:
        bdir_fd = open_dir_nofollow(backup_dir)
    except FileNotFoundError:
        bdir_fd = None

    state_name = f"{app_name}-resolv.conf.state"
    bak_name = f"{app_name}-resolv.conf.bak"
    restored_from_state = False

    if bdir_fd is not None:
        try:
            try:
                st_state = os.lstat(state_name, dir_fd=bdir_fd)
            except FileNotFoundError:
                st_state = None
            if st_state is not None:
                if stat.S_ISLNK(st_state.st_mode) or not stat.S_ISREG(st_state.st_mode):
                    raise ValueError(f"Unsafe DNS backup state file: {backup_dir / state_name}")
                sfd = os.open(state_name, os.O_RDONLY | o_nofollow | o_cloexec, dir_fd=bdir_fd)
                try:
                    state = json.loads(os.pread(sfd, 65536, 0).decode("utf-8"))
                finally:
                    os.close(sfd)
                kind = state.get("kind")
                if kind == "symlink":
                    target = str(state.get("target") or "")
                    if not target or "\n" in target or "\x00" in target:
                        raise ValueError("Invalid saved resolv.conf symlink target")
                    tmp_link = f".{resolv_path.name}.af-restore.{secrets.token_hex(6)}"
                    os.symlink(target, tmp_link, dir_fd=rdir_fd)
                    try:
                        os.replace(tmp_link, resolv_path.name, src_dir_fd=rdir_fd, dst_dir_fd=rdir_fd)
                    except BaseException:
                        try:
                            os.unlink(tmp_link, dir_fd=rdir_fd)
                        except OSError:
                            pass
                        raise
                elif kind == "file":
                    st_bak = os.lstat(bak_name, dir_fd=bdir_fd)
                    if stat.S_ISLNK(st_bak.st_mode) or not stat.S_ISREG(st_bak.st_mode):
                        raise ValueError(f"Unsafe DNS backup file: {backup_dir / bak_name}")
                    bfd = os.open(bak_name, os.O_RDONLY | o_nofollow | o_cloexec, dir_fd=bdir_fd)
                    try:
                        data = os.pread(bfd, 1048576, 0)
                    finally:
                        os.close(bfd)
                    mode = int(state.get("mode") or 0o644) & 0o644
                    if (mode & 0o444) == 0:
                        mode = 0o644
                    tmp_file = f".{resolv_path.name}.af-restore.{secrets.token_hex(6)}"
                    tfd = os.open(tmp_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | o_nofollow | o_cloexec, mode, dir_fd=rdir_fd)
                    try:
                        os.fchmod(tfd, mode)
                        os.write(tfd, data)
                        os.fsync(tfd)
                    finally:
                        os.close(tfd)
                    os.replace(tmp_file, resolv_path.name, src_dir_fd=rdir_fd, dst_dir_fd=rdir_fd)
                elif kind == "absent":
                    try:
                        os.unlink(resolv_path.name, dir_fd=rdir_fd)
                    except FileNotFoundError:
                        pass
                else:
                    raise ValueError(f"Unsupported saved resolv.conf state kind: {kind!r}")

                for fname in (state_name, bak_name):
                    try:
                        os.unlink(fname, dir_fd=bdir_fd)
                    except FileNotFoundError:
                        pass
                restored_from_state = True
        finally:
            os.close(bdir_fd)

    if not restored_from_state and (dropin_removed == "true" or resolved_active == "true") and os.path.exists(stub_target):
        should_restore_stub = False
        try:
            rst = os.lstat(resolv_path.name, dir_fd=rdir_fd)
        except FileNotFoundError:
            should_restore_stub = (dropin_removed == "true")
        else:
            if stat.S_ISLNK(rst.st_mode):
                cur_target = os.readlink(resolv_path.name, dir_fd=rdir_fd)
                if cur_target.endswith("/resolv.conf") and "systemd/resolve" in cur_target:
                    should_restore_stub = True
            elif stat.S_ISREG(rst.st_mode):
                rfd = os.open(resolv_path.name, os.O_RDONLY | o_nofollow | o_cloexec, dir_fd=rdir_fd)
                try:
                    lines = [ln.strip() for ln in os.pread(rfd, 65536, 0).decode("utf-8", errors="replace").splitlines() if ln.strip() and not ln.strip().startswith("#")]
                finally:
                    os.close(rfd)
                ns = [ln.split()[1] for ln in lines if ln.startswith("nameserver ") and len(ln.split()) >= 2]
                if ns == ["127.0.0.1"] or (dropin_removed == "true" and ns == ["127.0.0.53"]):
                    should_restore_stub = True
        if should_restore_stub:
            tmp_link = f".{resolv_path.name}.af-restore.{secrets.token_hex(6)}"
            os.symlink(stub_target, tmp_link, dir_fd=rdir_fd)
            try:
                os.replace(tmp_link, resolv_path.name, src_dir_fd=rdir_fd, dst_dir_fd=rdir_fd)
            except BaseException:
                try:
                    os.unlink(tmp_link, dir_fd=rdir_fd)
                except OSError:
                    pass
                raise
finally:
    os.close(rdir_fd)
PYEOF
}

af_verify_local_dns_lookup() {
    local dns_port="${1:-53}"
    local max_attempts="${2:-15}"
    local retry_delay="${3:-1}"
    local timeout_sec="${4:-2.0}"
    python3 -I - "$dns_port" "$max_attempts" "$retry_delay" "$timeout_sec" <<'PYEOF'
import os, socket, struct, sys, time

port = int(sys.argv[1])
attempts = max(1, int(sys.argv[2]))
retry_delay = max(0.0, float(sys.argv[3]))
timeout_sec = max(0.1, float(sys.argv[4]))
question = b"\x09localhost\x00" + struct.pack(">HH", 1, 1)

last_err = None
for attempt in range(attempts):
    txid = struct.unpack(">H", os.urandom(2))[0]
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    packet = header + question
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout_sec)
    try:
        sock.connect(("127.0.0.1", port))
        sock.send(packet)
        resp = sock.recv(512)
        if len(resp) >= 12:
            resp_id, flags, questions, answers, _, _ = struct.unpack(">HHHHHH", resp[:12])
            if (resp_id == txid and flags & 0x8000 and not flags & 0x020F
                    and questions == 1 and answers > 0 and resp[12:12 + len(question)] == question):
                raise SystemExit(0)
        last_err = "malformed DNS response"
    except OSError as exc:
        last_err = str(exc)
    finally:
        sock.close()
    if attempt + 1 < attempts and retry_delay > 0:
        time.sleep(retry_delay)

print(f"Local DNS lookup probe failed against 127.0.0.1:{port}: {last_err}", file=sys.stderr)
raise SystemExit(1)
PYEOF
}

lock_path() {
    local package_name="$1"
    printf '%s/.%s.lock\n' "$LOCK_DIR" "$package_name"
}

retained_lock_path() {
    local package_name="$1"
    printf '%s/.%s.retained\n' "$LOCK_DIR" "$package_name"
}

legacy_swizzin_lock_path() {
    local package_name="$1"
    local fs_root="${AETHERFLOW_FS_ROOT:-${AETHERFLOW_INSTALL_ROOT:-}}"
    if [[ -n "$fs_root" && "$fs_root" != "/" ]]; then
        printf '%s/etc/Swizzin/.%s.lock\n' "${fs_root%/}" "$package_name"
        return 0
    fi
    local clean_lock_dir="${LOCK_DIR%/}"
    if [[ "$clean_lock_dir" == "/install" ]]; then
        printf '/etc/Swizzin/.%s.lock\n' "$package_name"
        return 0
    fi
    if [[ "$clean_lock_dir" == */install ]]; then
        printf '%s/etc/Swizzin/.%s.lock\n' "${clean_lock_dir%/install}" "$package_name"
        return 0
    fi
    return 1
}

remove_legacy_swizzin_lock() {
    local package_name="$1" legacy_lock="" legacy_dir="" legacy_etc=""
    legacy_lock="$(legacy_swizzin_lock_path "$package_name")" || return 0
    legacy_dir="${legacy_lock%/*}"
    legacy_etc="${legacy_dir%/*}"
    if [[ -L "$legacy_etc" || -L "$legacy_dir" ]]; then
        print_error "Refusing symlinked legacy lock directory: $legacy_dir"
        return 1
    fi
    if [[ ! -e "$legacy_lock" && ! -L "$legacy_lock" ]]; then
        return 0
    fi
    if [[ -L "$legacy_lock" || ! -f "$legacy_lock" ]]; then
        print_error "Refusing unsafe legacy installation lock: $legacy_lock"
        return 1
    fi
    rm -f -- "$legacy_lock"
}

has_lock() {
    local package_name="$1" lp=""
    lp="$(lock_path "$package_name")"
    [[ ! -L "$LOCK_DIR" && -d "$LOCK_DIR" && ! -L "$lp" && -f "$lp" ]]
}

launch_detached_helper() (
    local maintenance_fd="${AF_MAINTENANCE_GUARD_FD:-}"
    if [[ -n "$maintenance_fd" ]]; then
        [[ "$maintenance_fd" =~ ^[0-9]+$ && "$maintenance_fd" -gt 2 ]] || return 1
        exec {maintenance_fd}>&-
    fi
    unset AF_MAINTENANCE_GUARD_FD
    if command -v setsid >/dev/null 2>&1; then
        setsid -w /bin/bash -c '"$@" </dev/null >/dev/null 2>&1 &' _ "$@" </dev/null >/dev/null 2>&1
    else
        "$@" </dev/null >/dev/null 2>&1 &
    fi
)

write_lock() {
    local package_name="$1" lp="" rp=""
    if [[ -n "${AF_STATE_BACKUP:-}" && -n "${AF_STATE_UNIT:-}" ]]; then
        verify_systemd_service_active "$AF_STATE_UNIT" || return 1
        if [[ "${AF_STATE_PORT:-0}" != 0 ]]; then
            wait_for_service_ready "$AF_STATE_UNIT" "$AF_STATE_PORT" "$AF_STATE_READINESS_PATH" || return 1
        fi
    fi
    if [[ -d "${AF_TX_DIR:-}/apt-packages" ]]; then
        clear_apt_reinstall_markers || return 1
    fi
    lp="$(lock_path "$package_name")"
    rp="$(retained_lock_path "$package_name")"
    if [[ -L "$LOCK_DIR" || -L "$lp" || ( -e "$lp" && ! -f "$lp" ) ]]; then
        print_error "Refusing unsafe installation lock path: $lp"
        return 1
    fi
    if [[ -L "$rp" || ( -e "$rp" && ! -f "$rp" ) ]]; then
        print_error "Refusing unsafe retained installation receipt path: $rp"
        return 1
    fi
    local new_lock=false
    [[ -f "$lp" ]] || new_lock=true
    touch "$lp" || return 1
    if ! remove_legacy_swizzin_lock "$package_name"; then
        [[ "$new_lock" != true ]] || rm -f -- "$lp"
        return 1
    fi
    if [[ -f "$rp" ]]; then
        rm -f -- "$rp" || {
            [[ "$new_lock" != true ]] || rm -f -- "$lp"
            return 1
        }
    fi
    INSTALL_COMMITTED=true
    if [[ -n "${AF_ARCHIVE_BACKUP:-}" ]]; then
        rm -f -- "$AF_ARCHIVE_BACKUP/.af-archive-pending"
        if [[ -n "${AF_ARCHIVE_DESTINATION:-}" ]] && declare -F prune_app_archive_backups >/dev/null 2>&1; then
            prune_app_archive_backups "$AF_ARCHIVE_DESTINATION" "${AF_ARCHIVE_UNIT:-$package_name}" "$AF_ARCHIVE_BACKUP" 2
        fi
    fi
    local certbot_sync="${AF_CERTBOT_SYNC_BIN:-/usr/local/bin/af-certbot-sync}"
    if [[ -x "$certbot_sync" ]]; then
        launch_detached_helper "$certbot_sync"
    fi
}

get_base_domain() {
    local dom="" db_cand=""
    local explicit_env_file="${AETHERFLOW_ENV_FILE:-}"
    local skip_host_env="${AETHERFLOW_SKIP_ENV_FILES:-0}"
    local env_file=""
    if [[ -n "$explicit_env_file" ]]; then
        env_file="$explicit_env_file"
    elif [[ "$skip_host_env" != "1" ]]; then
        env_file="/etc/aetherflow/aetherflow.env"
    fi
    local env_af_db="" env_db="" env_aetherflow_db="" env_data_dir="" env_base_domain=""
    if [[ -n "$env_file" && -e "$env_file" ]]; then
        local _parsed_env=""
        _parsed_env="$(python3 -I - "$env_file" <<'PYEOF' 2>/dev/null || true
import os, pathlib, stat, sys
target = sys.argv[1]
O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
MAX_ENV_BYTES = 65536
p = pathlib.PurePosixPath(os.path.abspath(target))
if ".." in p.parts or len(p.parts) < 2:
    raise SystemExit(1)
cur_fd = os.open("/", os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
try:
    for part in p.parts[1:-1]:
        nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
        os.close(cur_fd)
        cur_fd = nxt_fd
    fd = os.open(p.parts[-1], os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=cur_fd)
finally:
    os.close(cur_fd)
try:
    fst = os.fstat(fd)
    if not stat.S_ISREG(fst.st_mode) or fst.st_nlink != 1 or fst.st_size > MAX_ENV_BYTES:
        raise SystemExit(1)
    chunks = []
    total = 0
    while True:
        chunk = os.read(fd, 8192)
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_ENV_BYTES:
            raise SystemExit(1)
        chunks.append(chunk)
    content = b"".join(chunks).decode("utf-8", errors="replace")
finally:
    os.close(fd)
vals = {}
for raw_line in content.splitlines():
    s = raw_line.strip()
    if not s or s.startswith("#"):
        continue
    if s.startswith("export "):
        s = s[7:].strip()
    if "=" not in s:
        continue
    k, v = s.split("=", 1)
    k = k.strip()
    v = v.strip()
    if len(v) >= 2 and ((v[0] == '"' and v[-1] == '"') or (v[0] == "'" and v[-1] == "'")):
        v = v[1:-1]
    if k in ("AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH", "DATA_DIR", "AETHERFLOW_BASE_DOMAIN"):
        vals[k] = v
for key in ("AF_DB_PATH", "DB_PATH", "AETHERFLOW_DB_PATH", "DATA_DIR", "AETHERFLOW_BASE_DOMAIN"):
    print(vals.get(key, "").replace("\n", "").replace("\r", ""))
PYEOF
)"
        if [[ -n "$_parsed_env" ]]; then
            env_af_db="$(printf '%s\n' "$_parsed_env" | sed -n '1p')"
            env_db="$(printf '%s\n' "$_parsed_env" | sed -n '2p')"
            env_aetherflow_db="$(printf '%s\n' "$_parsed_env" | sed -n '3p')"
            env_data_dir="$(printf '%s\n' "$_parsed_env" | sed -n '4p')"
            env_base_domain="$(printf '%s\n' "$_parsed_env" | sed -n '5p')"
        fi
    fi
    local eff_data_dir="${AETHERFLOW_DATA_DIR:-$env_data_dir}"
    local custom_data_db=""
    if [[ -n "$eff_data_dir" && "${eff_data_dir%/}" != "/var/lib/aetherflow" ]]; then
        custom_data_db="${eff_data_dir%/}/aetherflow.sqlite"
    fi
    if command -v python3 >/dev/null 2>&1; then
        local -a _db_candidates=(
            "${AF_DB_PATH:-}"
            "${DB_PATH:-}"
            "${AETHERFLOW_DB_PATH:-}"
            "$env_af_db"
            "$env_db"
            "$env_aetherflow_db"
            "$custom_data_db"
        )
        if [[ "$skip_host_env" != "1" ]]; then
            _db_candidates+=(
                /var/lib/aetherflow/aetherflow.sqlite
                /opt/AetherFlow/current/data/aetherflow.sqlite
                /opt/AetherFlow/data/aetherflow.sqlite
                /opt/AetherFlow/backend/data/aetherflow.sqlite
            )
        fi
        local _raw_db_dom=""
        _raw_db_dom="$(python3 -I - "${_db_candidates[@]}" <<'PYDB' 2>/dev/null || true
import os, pathlib, sqlite3, stat, sys, time, uuid

O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
MAX_SCRATCH_BYTES = 2 * 1024 * 1024 * 1024
is_root = os.geteuid() == 0

def open_dir_nofollow(dir_str):
    p = pathlib.PurePosixPath(os.path.abspath(dir_str))
    if ".." in p.parts:
        return -1
    try:
        cur_fd = os.open("/", os.O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    except OSError:
        return -1
    try:
        for part in p.parts[1:]:
            nxt_fd = os.open(part, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cur_fd)
            os.close(cur_fd)
            cur_fd = nxt_fd
        return cur_fd
    except OSError:
        os.close(cur_fd)
        return -1

def is_trusted_root_dir(dir_str, allow_sticky):
    dp = pathlib.PurePosixPath(os.path.abspath(dir_str))
    if not dp.is_absolute() or ".." in dp.parts:
        return False
    cur_p = pathlib.Path("/")
    for part in dp.parts:
        cur_p = pathlib.Path("/") if part == "/" else cur_p / part
        try:
            cst = os.lstat(cur_p)
        except OSError:
            return False
        if stat.S_ISLNK(cst.st_mode) or not stat.S_ISDIR(cst.st_mode) or cst.st_uid != 0:
            return False
        writable = (cst.st_mode & 0o022) != 0
        sticky = (cst.st_mode & getattr(stat, "S_ISVTX", 0o1000)) != 0
        if writable and not (allow_sticky and sticky):
            return False
    return True

def create_root_scratch(min_free):
    sc_name = f".af-root-dom.{os.getpid()}.{uuid.uuid4().hex}"
    for cand in ("/var/tmp", "/tmp", "/run"):
        if not is_trusted_root_dir(cand, allow_sticky=True):
            continue
        cand_fd = -1
        try:
            cand_fd = os.open(cand, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            vfs = os.fstatvfs(cand_fd)
            avail = vfs.f_bavail * (vfs.f_frsize or vfs.f_bsize)
            if avail < min_free:
                os.close(cand_fd)
                continue
            os.mkdir(sc_name, 0o700, dir_fd=cand_fd)
            sc_fd = os.open(sc_name, os.O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, dir_fd=cand_fd)
            if not stat.S_ISDIR(os.fstat(sc_fd).st_mode) or os.fstat(sc_fd).st_uid != 0:
                os.close(sc_fd)
                os.rmdir(sc_name, dir_fd=cand_fd)
                os.close(cand_fd)
                continue
            os.fchmod(sc_fd, 0o700)
            return cand_fd, sc_fd, sc_name, os.path.join(cand, sc_name)
        except OSError:
            if cand_fd >= 0:
                os.close(cand_fd)
    return None

def copy_fd_bounded(in_fd, out_dir_fd, out_name, remaining):
    out_fd = os.open(out_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600, dir_fd=out_dir_fd)
    copied = 0
    tail8 = b""
    try:
        while True:
            chunk = os.read(in_fd, 65536)
            if not chunk:
                break
            copied += len(chunk)
            if copied > remaining:
                raise OSError("scratch copy cap exceeded")
            tail8 = (tail8 + chunk)[-8:]
            view = memoryview(chunk)
            while view:
                w = os.write(out_fd, view)
                if w <= 0:
                    raise OSError("short write")
                view = view[w:]
        if out_name.endswith("-journal") and copied >= 16 and tail8 == b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7":
            raise OSError("forbidden SQLite super-journal trailer")
        return remaining - copied
    finally:
        os.close(out_fd)

def db_files_root_owned_safe(parent_fd, leaf_name):
    for suffix in ("", "-wal", "-shm", "-journal"):
        try:
            st = os.stat(leaf_name + suffix, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            st = None
        if st is not None and (st.st_uid != 0 or (st.st_mode & 0o022) != 0):
            return False
    return True

def query_candidate(db_cand):
    db_abs = os.path.abspath(db_cand)
    parent_str = os.path.dirname(db_abs)
    leaf_name = os.path.basename(db_abs)
    if not leaf_name:
        return None
    parent_fd = open_dir_nofollow(parent_str)
    if parent_fd < 0:
        return None
    try:
        use_scratch = is_root and (
            not is_trusted_root_dir(parent_str, allow_sticky=False)
            or not db_files_root_owned_safe(parent_fd, leaf_name)
        )
        attempts = 3 if use_scratch else 1
        for attempt in range(attempts):
            db_fd = -1
            wal_fd = -1
            jrn_fd = -1
            sc = None
            try:
                db_fd = os.open(leaf_name, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=parent_fd)
                st = os.fstat(db_fd)
                if not stat.S_ISREG(st.st_mode) or st.st_nlink != 1:
                    return None
                if os.read(db_fd, 16) != b"SQLite format 3\x00":
                    return None
                total_sz = st.st_size
                for suffix in ("-wal", "-shm", "-journal"):
                    try:
                        sfd = os.open(leaf_name + suffix, os.O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, dir_fd=parent_fd)
                    except FileNotFoundError:
                        continue
                    sst = os.fstat(sfd)
                    if not stat.S_ISREG(sst.st_mode) or sst.st_nlink != 1:
                        os.close(sfd)
                        return None
                    if suffix == "-wal":
                        wal_fd = sfd
                        total_sz += sst.st_size
                    elif suffix == "-journal":
                        if sst.st_size >= 16:
                            os.lseek(sfd, -8, os.SEEK_END)
                            jtail = os.read(sfd, 8)
                            os.lseek(sfd, 0, os.SEEK_SET)
                            if jtail == b"\xd9\xd5\x05\xf9\x20\xa1\x63\xd7":
                                os.close(sfd)
                                return None
                        jrn_fd = sfd
                        total_sz += sst.st_size
                    else:
                        os.close(sfd)
                if use_scratch:
                    if total_sz > MAX_SCRATCH_BYTES:
                        return None
                    sc = create_root_scratch(total_sz * 2 + 16 * 1024 * 1024)
                    if sc is None:
                        return None
                    _, sc_fd, _, sc_path = sc
                    os.lseek(db_fd, 0, os.SEEK_SET)
                    rem = copy_fd_bounded(db_fd, sc_fd, "dom.sqlite", MAX_SCRATCH_BYTES)
                    if wal_fd >= 0:
                        rem = copy_fd_bounded(wal_fd, sc_fd, "dom.sqlite-wal", rem)
                    if jrn_fd >= 0:
                        copy_fd_bounded(jrn_fd, sc_fd, "dom.sqlite-journal", rem)
                    conn = sqlite3.connect(os.path.join(sc_path, "dom.sqlite"), timeout=2)
                else:
                    conn = sqlite3.connect(pathlib.Path(db_abs).as_uri() + "?mode=ro", uri=True, timeout=2)
                try:
                    conn.execute("PRAGMA trusted_schema = OFF;")
                    has_settings = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='settings'").fetchone()
                    if has_settings and has_settings[0] == 1:
                        row = conn.execute("SELECT base_domain FROM settings WHERE id = 1").fetchone()
                        return (row[0] or "") if row else ""
                    return None
                finally:
                    conn.close()
            except sqlite3.DatabaseError:
                if attempt + 1 < attempts:
                    time.sleep(0.025)
                    continue
                return None
            except OSError:
                return None
            finally:
                for fd in (db_fd, wal_fd, jrn_fd):
                    if fd >= 0:
                        os.close(fd)
                if sc is not None:
                    sc_base_fd, sc_fd, sc_name, _ = sc
                    for nm in ("dom.sqlite", "dom.sqlite-wal", "dom.sqlite-shm", "dom.sqlite-journal"):
                        try:
                            os.unlink(nm, dir_fd=sc_fd)
                        except FileNotFoundError:
                            _ = nm
                    os.close(sc_fd)
                    try:
                        os.rmdir(sc_name, dir_fd=sc_base_fd)
                    except OSError:
                        _ = sc_name
                    os.close(sc_base_fd)
    finally:
        os.close(parent_fd)
    return None

for cand in sys.argv[1:]:
    if not cand:
        continue
    res = query_candidate(cand)
    if res is not None:
        sys.stdout.write(res)
        break
PYDB
)"
        if [[ -n "$_raw_db_dom" ]]; then
            dom="$(printf '%s' "$_raw_db_dom" | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's/^\*\.//' | tr -d '[:space:]')"
        fi
    fi
    if [[ -z "$dom" ]]; then
        local raw_env_dom="${AETHERFLOW_BASE_DOMAIN:-$env_base_domain}"
        if [[ -n "$raw_env_dom" ]]; then
            dom="$(printf '%s' "$raw_env_dom" | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's/^\*\.//' | tr -d '[:space:]')"
        fi
    fi
    local domain_regex='^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$'
    if [[ "$dom" == "localhost" || "$dom" == *.local ]] || { [[ -n "$dom" ]] && [[ ! "$dom" =~ $domain_regex ]]; }; then
        dom=""
    fi
    printf '%s\n' "$dom"
}

remove_lock() {
    local package_name="$1" lp="" rp="" legacy_lock="" legacy_dir="" legacy_etc="" had_receipt=false tmp_retained=""
    lp="$(lock_path "$package_name")"
    rp="$(retained_lock_path "$package_name")"
    if [[ -L "$LOCK_DIR" || -L "$lp" || ( -e "$lp" && ! -f "$lp" ) ]]; then
        print_error "Refusing unsafe installation lock path: $lp"
        return 1
    fi
    if [[ -L "$rp" || ( -e "$rp" && ! -f "$rp" ) ]]; then
        print_error "Refusing unsafe retained installation receipt path: $rp"
        return 1
    fi
    if legacy_lock="$(legacy_swizzin_lock_path "$package_name" 2>/dev/null)"; then
        legacy_dir="${legacy_lock%/*}"
        legacy_etc="${legacy_dir%/*}"
        if [[ -L "$legacy_etc" || -L "$legacy_dir" ]]; then
            print_error "Refusing symlinked legacy lock directory: $legacy_dir"
            return 1
        fi
        if [[ -L "$legacy_lock" || ( -e "$legacy_lock" && ! -f "$legacy_lock" ) ]]; then
            print_error "Refusing unsafe legacy installation lock: $legacy_lock"
            return 1
        fi
    fi
    if [[ "${DELETE_DATA:-false}" == true ]]; then
        purge_app_backups "$package_name" || return 1
    fi
    if [[ -f "$lp" || -f "$rp" || ( -n "$legacy_lock" && -f "$legacy_lock" ) ]]; then
        had_receipt=true
    fi
    if [[ "${DELETE_DATA:-false}" == true ]]; then
        rm -f -- "$rp" || return 1
    elif [[ "$had_receipt" == true ]]; then
        mkdir -p -- "$LOCK_DIR" || return 1
        tmp_retained="$(mktemp "${LOCK_DIR}/.af-retained.XXXXXX")" || return 1
        if ! printf 'package=%s\nstate=retained\nupdated_at=%s\n' "${package_name,,}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$tmp_retained" ||
            ! chmod 0644 "$tmp_retained" ||
            ! mv -f -- "$tmp_retained" "$rp"; then
            rm -f -- "$tmp_retained"
            return 1
        fi
    fi
    remove_legacy_swizzin_lock "$package_name" || return 1
    rm -f -- "$lp"
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

fetch_and_run() {
    local url="$1"
    local checksum="${2:-}"
    shift 2

    local tmp_script
    tmp_script=$(mktemp "${TMPDIR:-/tmp}/aetherflow-install-XXXXXX.sh") || return 1

    if [[ -z "$checksum" || "$checksum" == "SKIP" || ! "$checksum" =~ ^[0-9a-fA-F]{64}$ ]]; then
        print_error "Refusing to execute remote bootstrap script without a pinned 64-hex SHA-256 digest: $url"
        rm -f "$tmp_script"
        return 1
    fi
    
    log_info "Downloading install script from $url"
    local -a _boot_proto=()
    [[ "$url" == https://* ]] && _boot_proto=(--proto '=https' --proto-redir '=https')
    if ! curl "${_boot_proto[@]}" -fsSL -o "$tmp_script" "$url"; then
        print_error "Failed to download $url"
        rm -f "$tmp_script"
        return 1
    fi

    local computed_hash
    if ! computed_hash=$(sha256sum "$tmp_script" | awk '{print $1}') || [[ "${computed_hash,,}" != "${checksum,,}" ]]; then
        print_error "Checksum validation failed for $url! Expected: $checksum, Got: ${computed_hash:-unavailable}"
        rm -f "$tmp_script"
        return 1
    fi
    log_info "Checksum validation passed."
    af_logged printf '%s\n' "[BOOTSTRAP-PROVENANCE] url=${url} sha256=${computed_hash,,}" || true

    if ! bash "$tmp_script" "$@"; then
        print_error "Script execution failed for $url"
        rm -f "$tmp_script"
        return 1
    fi

    rm -f "$tmp_script"
    return 0
}
