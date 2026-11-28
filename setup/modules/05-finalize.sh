#!/bin/bash
# Module: 05-finalize.sh

# Adapt vsftpd TLS version directives to match the installed vsftpd binary's parseconf table:
# - vsftpd 3.0.5 (Debian 13 / Ubuntu 22.04+): ssl_tlsv11 / ssl_tlsv12 / ssl_tlsv13 (no underscore)
# - alternate patched builds: ssl_tlsv1_1 / ssl_tlsv1_2 / ssl_tlsv1_3
# - vsftpd 3.0.3 (Debian 11/12): lacks per-version TLS 1.1+ toggles (uses OpenSSL defaults with ssl_tlsv1=NO)
function _af_vsftpd_sync_tls_directives() {
	local conf_path="$1"
	local vsftpd_bin="${2:-}"

	if [[ -z "${vsftpd_bin}" || ! -r "${vsftpd_bin}" ]]; then
		return 0
	fi

	if LC_ALL=C grep -aFq "ssl_tlsv11" "${vsftpd_bin}" 2>/dev/null && LC_ALL=C grep -aFq "ssl_tlsv12" "${vsftpd_bin}" 2>/dev/null; then
		if ! LC_ALL=C grep -aFq "ssl_tlsv13" "${vsftpd_bin}" 2>/dev/null; then
			sed -i '/^ssl_tlsv13=/d' "${conf_path}" || return 1
		fi
	elif LC_ALL=C grep -aFq "ssl_tlsv1_1" "${vsftpd_bin}" 2>/dev/null && LC_ALL=C grep -aFq "ssl_tlsv1_2" "${vsftpd_bin}" 2>/dev/null; then
		sed -i \
			-e 's/^ssl_tlsv11=/ssl_tlsv1_1=/' \
			-e 's/^ssl_tlsv12=/ssl_tlsv1_2=/' \
			"${conf_path}" || return 1
		if LC_ALL=C grep -aFq "ssl_tlsv1_3" "${vsftpd_bin}" 2>/dev/null; then
			sed -i 's/^ssl_tlsv13=/ssl_tlsv1_3=/' "${conf_path}" || return 1
		else
			sed -i '/^ssl_tlsv13=/d' "${conf_path}" || return 1
		fi
	else
		sed -i -e '/^ssl_tlsv11=/d' -e '/^ssl_tlsv12=/d' -e '/^ssl_tlsv13=/d' "${conf_path}" || return 1
	fi
}

# Extract primary IPv4 source address safely (handles direct-interface /32 routes and offline hosts under set -eo pipefail)
function _af_primary_ipv4() {
	ip route get 8.8.8.8 2>/dev/null | awk 'NR==1 {for (i=1; i<NF; i++) if ($i == "src") {print $(i+1); exit}}' || true
}

# function to configure vsftpd (explicit opt-in via AETHERFLOW_ENABLE_FTPD=yes)
function _ftpdconfig() {
	local ftpd_flag="${AETHERFLOW_ENABLE_FTPD:-no}"
	case "${ftpd_flag,,}" in
		1|true|yes|y|on) ;;
		*) return 0 ;;
	esac

	local outto="${OUTTO:-/dev/null}"
	local openssl_cnf="${AF_OPENSSL_CNF:-/root/.openssl.cnf}"
	local vsftpd_cert="${AF_VSFTPD_CERT:-/etc/ssl/private/vsftpd.pem}"
	local vsftpd_conf="${AF_VSFTPD_CONF:-/etc/vsftpd.conf}"
	local vsftpd_chroot_list="${AF_VSFTPD_CHROOT_LIST:-/etc/vsftpd.chroot_list}"
	local vsftpd_bin="${AF_VSFTPD_BIN:-}"
	if [[ -z "${vsftpd_bin}" ]]; then
		vsftpd_bin="$(command -v vsftpd 2>/dev/null || echo /usr/sbin/vsftpd)"
	fi

	local openssl_dir cert_dir conf_dir chroot_dir
	openssl_dir="$(dirname "${openssl_cnf}")"
	cert_dir="$(dirname "${vsftpd_cert}")"
	conf_dir="$(dirname "${vsftpd_conf}")"
	chroot_dir="$(dirname "${vsftpd_chroot_list}")"
	local p
	for p in "${openssl_dir}" "${cert_dir}" "${conf_dir}" "${chroot_dir}"; do
		if [[ -L "${p}" ]]; then
			echo "[ERROR] Refusing symlinked vsftpd directory: ${p}" >>"${outto}" 2>&1
			return 1
		fi
	done
	for p in "${openssl_cnf}" "${vsftpd_cert}" "${vsftpd_conf}" "${vsftpd_chroot_list}"; do
		if [[ -L "${p}" || ( -e "${p}" && ! -f "${p}" ) ]]; then
			echo "[ERROR] Refusing unsafe vsftpd file path: ${p}" >>"${outto}" 2>&1
			return 1
		fi
	done
	[[ -d "${openssl_dir}" ]] || install -d -m 0700 "${openssl_dir}"
	[[ -d "${cert_dir}" ]] || install -d -m 0710 "${cert_dir}"
	[[ -d "${conf_dir}" ]] || mkdir -p "${conf_dir}"
	[[ -d "${chroot_dir}" ]] || mkdir -p "${chroot_dir}"
	local tmp_openssl_cnf
	tmp_openssl_cnf="$(umask 0077 && mktemp "${openssl_dir}/.openssl.cnf.af.XXXXXX")" || return 1
	if ! \cp -f "${local_setup}templates/openssl.cnf.template" "${tmp_openssl_cnf}" || ! chmod 0600 "${tmp_openssl_cnf}" || ! mv -fT -- "${tmp_openssl_cnf}" "${openssl_cnf}"; then
		rm -f -- "${tmp_openssl_cnf}"
		return 1
	fi

	#openssl req -config /root/.openssl.cnf -x509 -nodes -days 365 -newkey rsa:1024 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem >/dev/null 2>&1
	local tmp_cert
	tmp_cert="$(umask 0077 && mktemp "${cert_dir}/.vsftpd.pem.af.XXXXXX")" || return 1
	if ! openssl req -config "${openssl_cnf}" -x509 -nodes -days 720 -newkey rsa:2048 -keyout "${tmp_cert}" -out "${tmp_cert}" >>"${outto}" 2>&1; then
		rm -f -- "${tmp_cert}"
		return 1
	fi
	chown root:root "${tmp_cert}" 2>/dev/null || true
	chmod 0600 "${tmp_cert}"
	if [[ -n "${AF_VSFTPD_CERT:-}" ]]; then
		mv -fT -- "${tmp_cert}" "${vsftpd_cert}" || { rm -f -- "${tmp_cert}"; return 1; }
		chmod 0600 "${vsftpd_cert}"
	else
		mv -fT -- "${tmp_cert}" /etc/ssl/private/vsftpd.pem || { rm -f -- "${tmp_cert}"; return 1; }
		chmod 0600 /etc/ssl/private/vsftpd.pem
	fi

	local passive_ip="${IP:-}"
	if [[ -z "${passive_ip}" ]]; then
		passive_ip="$(_af_primary_ipv4)"
	fi
	if [[ -n "${passive_ip}" ]]; then
		if [[ ! "${passive_ip}" =~ ^(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})$ ]] || \
		   (( 10#${BASH_REMATCH[1]} > 255 || 10#${BASH_REMATCH[2]} > 255 || 10#${BASH_REMATCH[3]} > 255 || 10#${BASH_REMATCH[4]} > 255 )); then
			printf '[ERROR] Invalid IPv4 address for vsftpd pasv_address\n' >>"${outto}" 2>&1
			return 1
		fi
	fi

	local tmp_conf
	tmp_conf="$(mktemp "${conf_dir}/.vsftpd.conf.af.XXXXXX")" || return 1
	if ! \cp -f "${local_setup}templates/vsftpd.conf.template" "${tmp_conf}" || \
	   ! _af_vsftpd_sync_tls_directives "${tmp_conf}" "${vsftpd_bin}"; then
		rm -f -- "${tmp_conf}"
		return 1
	fi

	# Enabling passive mode (firewall rules for 21/tcp and 10090:10100/tcp are
	# managed centrally by _setup_firewall so UFW detection is not bypassed).
	if ! sed -i 's/^\(pasv_min_port=\).*/\110090/' "${tmp_conf}" || \
	   ! sed -i 's/^\(pasv_max_port=\).*/\110100/' "${tmp_conf}"; then
		rm -f -- "${tmp_conf}"
		return 1
	fi
	if [[ -n "${passive_ip}" ]]; then
		if ! sed -i '/^pasv_address=/d' "${tmp_conf}" || \
		   ! printf 'pasv_address=%s\n' "${passive_ip}" >>"${tmp_conf}"; then
			rm -f -- "${tmp_conf}"
			return 1
		fi
	fi
	if [[ ! -s "${tmp_conf}" ]] || ! chmod 0644 "${tmp_conf}" || ! mv -fT -- "${tmp_conf}" "${vsftpd_conf}"; then
		rm -f -- "${tmp_conf}"
		return 1
	fi

	local tmp_chroot
	tmp_chroot="$(mktemp "${chroot_dir}/.vsftpd.chroot_list.af.XXXXXX")" || return 1
	if ! printf '\n' >"${tmp_chroot}" || ! chmod 0644 "${tmp_chroot}" || ! mv -fT -- "${tmp_chroot}" "${vsftpd_chroot_list}"; then
		rm -f -- "${tmp_chroot}"
		return 1
	fi

	if [[ "${AF_SKIP_SYSTEMCTL:-0}" != "1" ]] && command -v systemctl >/dev/null 2>&1; then
		systemctl enable vsftpd >>"${outto}" 2>&1 || return 1
		if ! systemctl restart vsftpd >>"${outto}" 2>&1; then
			echo "[ERROR] vsftpd failed to start with ${vsftpd_conf} — check 'journalctl -u vsftpd'" >>"${outto}" 2>&1
			return 1
		fi
	fi
}

# seedbox boot for first user
function _boot() {
	local af_root="${AF_INSTALL_ROOT:-/opt/AetherFlow}"
	local runner_unit_src="" api_unit_src=""
	if [[ -f "${af_root}/deploy/systemd/aetherflow-runner.service" ]]; then
		runner_unit_src="${af_root}/deploy/systemd/aetherflow-runner.service"
	elif [[ -f "${af_root}/current/deploy/systemd/aetherflow-runner.service" ]]; then
		runner_unit_src="${af_root}/current/deploy/systemd/aetherflow-runner.service"
	elif [[ -n "${BASE_DIR:-}" && -f "${BASE_DIR}/deploy/systemd/aetherflow-runner.service" ]]; then
		runner_unit_src="${BASE_DIR}/deploy/systemd/aetherflow-runner.service"
	fi
	if [[ -f "${af_root}/deploy/systemd/aetherflow-api.service" ]]; then
		api_unit_src="${af_root}/deploy/systemd/aetherflow-api.service"
	elif [[ -f "${af_root}/current/deploy/systemd/aetherflow-api.service" ]]; then
		api_unit_src="${af_root}/current/deploy/systemd/aetherflow-api.service"
	elif [[ -n "${BASE_DIR:-}" && -f "${BASE_DIR}/deploy/systemd/aetherflow-api.service" ]]; then
		api_unit_src="${BASE_DIR}/deploy/systemd/aetherflow-api.service"
	fi

	# Install AetherFlow Runner and Control Plane single-binary systemd service files
	if [[ ! -f /etc/systemd/system/aetherflow-runner.service && -n "${runner_unit_src}" ]]; then
		_safe_overlay_config "${runner_unit_src}" \
			/etc/systemd/system/aetherflow-runner.service
	fi
	if [[ -n "${api_unit_src}" ]] && { [[ ! -f /etc/systemd/system/aetherflow-api.service ]] || grep -qE "__AES_MASTER_KEY__|ProtectProc=invisible|ProcSubset=pid" /etc/systemd/system/aetherflow-api.service 2>/dev/null; }; then
		_safe_overlay_config "${api_unit_src}" \
			/etc/systemd/system/aetherflow-api.service
	fi
	rm -f /etc/systemd/system/aetherflow-front*.service 2>/dev/null || true

	install -d -m 0755 /etc/systemd/system.conf.d
	cat > /etc/systemd/system.conf.d/aetherflow.conf <<'EOF'
[Manager]
DefaultLimitNOFILE=65535
EOF
	chmod 0644 /etc/systemd/system.conf.d/aetherflow.conf

	# Ensure permissions and service user are configured before starting services
	# (do not prematurely mark harden_perms complete here; the canonical ALL_STEPS
	# harden_perms step executes after boot and firewall).
	_harden_permissions || return 1
	local log_retention_service_src="${AF_INSTALL_ROOT:+${AF_INSTALL_ROOT}/current/deploy/systemd/aetherflow-log-retention.service}"
	log_retention_service_src="${log_retention_service_src:-/opt/AetherFlow/current/deploy/systemd/aetherflow-log-retention.service}"
	local log_retention_timer_src="${AF_INSTALL_ROOT:+${AF_INSTALL_ROOT}/current/deploy/systemd/aetherflow-log-retention.timer}"
	log_retention_timer_src="${log_retention_timer_src:-/opt/AetherFlow/current/deploy/systemd/aetherflow-log-retention.timer}"
	_safe_overlay_config "${log_retention_service_src}" \
		/etc/systemd/system/aetherflow-log-retention.service || return 1
	_safe_overlay_config "${log_retention_timer_src}" \
		/etc/systemd/system/aetherflow-log-retention.timer || return 1

	systemctl daemon-reload >/dev/null 2>&1
	systemctl start aetherflow-log-retention.service || return 1
	systemctl enable --now aetherflow-log-retention.timer || return 1
	# Recovery is governed solely by the Rust heal coordinator (respecting AETHERFLOW_DISABLE_AUTOHEAL).
	systemctl disable --now aetherflow-heal.timer 2>/dev/null || true
	systemctl stop aetherflow-heal.service 2>/dev/null || true
	rm -f /etc/systemd/system/aetherflow-heal.service /etc/systemd/system/aetherflow-heal.timer 2>/dev/null || true

	# Enable and start the privileged runner daemon and control plane single binary
	mkdir -p /mnt/storage/media 2>/dev/null || true
	systemctl enable aetherflow-runner.service >/dev/null 2>&1 || true
	systemctl restart aetherflow-runner.service >/dev/null 2>&1 || true
	systemctl enable aetherflow-api.service >/dev/null 2>&1 || true
	systemctl restart aetherflow-api.service >/dev/null 2>&1 || true

	# Wait for Control Plane readiness; only auto-seed /api/v1/public/auth/setup when an explicit
	# dedicated web admin password (AETHERFLOW_WEB_ADMIN_PASSWORD) is supplied — never reuse ${passwd}.
	if [[ -n "${username:-}" ]]; then
		local _api_try=0
		while (( _api_try < 20 )); do
			if curl -fsS --max-time 1 "http://127.0.0.1:8080/health/ready" >/dev/null 2>&1; then
				break
			fi
			sleep 0.5
			_api_try=$((_api_try + 1))
		done
		AF_SETUP_USER="${username}" AF_SETUP_WEB_PASS="${AETHERFLOW_WEB_ADMIN_PASSWORD:-}" python3 -c '
import json, os, urllib.request
web_pass = os.environ.get("AF_SETUP_WEB_PASS", "")
if not web_pass:
    raise SystemExit(0)
payload = json.dumps({"username": os.environ["AF_SETUP_USER"], "password": web_pass}).encode("utf-8")
req = urllib.request.Request("http://127.0.0.1:8080/api/v1/public/auth/setup", data=payload, headers={"Content-Type": "application/json"}, method="POST")
try:
    urllib.request.urlopen(req, timeout=5)
except Exception:
    pass
' >/dev/null 2>&1 || true
	fi

	mkdir -p "${af_root}/config"
	if [[ -n "${IFACE:-}" ]]; then
		printf '%s\n' "${IFACE}" > "${af_root}/config/interface.txt"
	fi
	rm -f /etc/cron.d/set_interface
}

# function to set permissions on first user
function _perms() {
	local outto="${OUTTO:-/dev/null}"
	sudo -u "${username}" chmod 755 "/home/${username}/" >>"${outto}" 2>&1
	chmod +x /etc/cron.daily/denypublic >/dev/null 2>&1
	# Tightened from 777 → 770 (owner + group only, no world access)
	sudo -u "${username}" chmod 770 "/home/${username}/.sessions" >/dev/null 2>&1
}

################################################################################
# Permission Bounding — Principle of Least Privilege
################################################################################

# Create the dedicated aetherflow system user for running services
_ensure_aetherflow_user() {
	local af_root="${AF_INSTALL_ROOT:-/opt/AetherFlow}"
	local outto="${OUTTO:-/dev/null}"
	if ! id -u aetherflow >/dev/null 2>&1; then
		useradd --system --shell /usr/sbin/nologin \
			--home-dir "${af_root}" \
			--comment "AetherFlow service account" \
			aetherflow >>"${outto}" 2>&1
		echo "[$(date '+%Y-%m-%d %H:%M:%S')] Created system user: aetherflow" >> "${INSTALL_LOG:-/dev/null}"
	fi
	usermod -a -G systemd-journal,adm aetherflow >>"${outto}" 2>&1 || true
}

# Comprehensive permission hardening across AF_INSTALL_ROOT (default /opt/AetherFlow)
_harden_permissions() {
	local default_af_root="/opt/AetherFlow"
	local af_root="${AF_INSTALL_ROOT:-${default_af_root}}"
	local outto="${OUTTO:-/dev/null}"

	# Ensure the service user exists
	_ensure_aetherflow_user

	# Ownership: root:aetherflow for immutable code, releases, and scripts; only mutable data dirs are writable by aetherflow
	if [[ -d "${af_root}" ]]; then
		find "${af_root}" \( -path "${af_root}/backend/data" -o -path "${af_root}/dashboard/db" -o -path "${af_root}/logs" -o -path "${af_root}/releases/*/data-snapshot" \) -prune -o -exec chown -h root:aetherflow {} + >>"${outto}" 2>&1

		# Directories: 755 (rwxr-xr-x), pruning sensitive mutable/snapshot/credential directories
		find "${af_root}" \( -path "${af_root}/backend/data" -o -path "${af_root}/dashboard/db" -o -path "${af_root}/logs" -o -path "${af_root}/releases/*/data-snapshot" \) -prune -o -type d -exec chmod 755 {} + >>"${outto}" 2>&1

		# Regular files: 644 (rw-r--r--), pruning sensitive mutable/snapshot/credential directories
		find "${af_root}" \( -path "${af_root}/backend/data" -o -path "${af_root}/dashboard/db" -o -path "${af_root}/logs" -o -path "${af_root}/releases/*/data-snapshot" \) -prune -o -type f -exec chmod 644 {} + >>"${outto}" 2>&1

		# Enforce root-only 0700/0600 confinement on /opt/AetherFlow/logs bootstrap credential receipts
		if [[ -L "${af_root}/logs" ]]; then
			echo "[ERROR] Refusing symlinked ${af_root}/logs directory" >>"${outto}"
			return 1
		elif [[ -d "${af_root}/logs" ]]; then
			chown -h root:root "${af_root}/logs" >>"${outto}" 2>&1
			chmod 700 "${af_root}/logs" >>"${outto}" 2>&1
			find -P "${af_root}/logs" -mindepth 1 -type d -exec chown -h root:root {} + -exec chmod 700 {} + >>"${outto}" 2>&1
			find -P "${af_root}/logs" -mindepth 1 -type f -exec chown -h root:root {} + -exec chmod 600 {} + >>"${outto}" 2>&1
		fi

		# Executables: restore execute permission on known binaries
		if [[ -f "${af_root}/backend/aetherflow-api" ]]; then
			chmod 755 "${af_root}/backend/aetherflow-api"
		fi
		if [[ -f "${af_root}/current/aetherflow-api" ]]; then
			chmod 755 "${af_root}/current/aetherflow-api"
		fi
		if [[ -f "${af_root}/current/af" ]]; then
			chmod 755 "${af_root}/current/af"
		fi
		if [[ -f "${af_root}/current/bin/af" ]]; then
			chmod 755 "${af_root}/current/bin/af"
		fi
		local speedtest_binary
		for speedtest_binary in "${af_root}/current/speedtest-backend" "${af_root}/current/bin/speedtest-backend" "${af_root}/current/af-transcode" "${af_root}/current/bin/af-transcode"; do
			if [[ -f "${speedtest_binary}" && ! -L "${speedtest_binary}" ]]; then
				chmod 755 "${speedtest_binary}"
			fi
		done
		if [[ -d "${af_root}/releases" ]]; then
			find "${af_root}/releases" \( -path "${af_root}/releases/*/data-snapshot" \) -prune -o -type f \( -name "speedtest-backend" -o -name "af-transcode" -o -name "aetherflow-api" -o -name "af" -o -name "*.sh" -o -name "*.py" -o -path "*/bin/aetherflow-plugin-*" -o -path "*/backend/hooks/*.sh" \) -exec chmod 755 {} + 2>/dev/null || true
			find "${af_root}/releases" \( -path "${af_root}/releases/*/data-snapshot" \) -prune -o -path "*/packages/*" -type f -exec chmod 755 {} + 2>/dev/null || true
		fi
		if [[ -d "${af_root}/plugins" ]]; then
			find "${af_root}/plugins" -type f \( -path "*/bin/aetherflow-plugin-*" -o -path "*/backend/hooks/*.sh" \) -exec chmod 755 {} + 2>/dev/null || true
		fi

		if [[ -d "${af_root}/setup" ]]; then
			find "${af_root}/setup" -name "*.sh" -type f -exec chmod 755 {} + 2>/dev/null || true
			if [[ -f "${af_root}/setup/AetherFlow-Setup" ]]; then
				chmod 755 "${af_root}/setup/AetherFlow-Setup"
			fi
		fi
		if [[ -d "${af_root}/packages" ]]; then
			find "${af_root}/packages" -type f -exec chmod 755 {} + 2>/dev/null || true
		fi
		if [[ -d "${af_root}/deploy" ]]; then
			find "${af_root}/deploy" \( -name "*.sh" -o -name "*.py" \) -type f -exec chmod 755 {} + 2>/dev/null || true
		fi
		if [[ -d "${af_root}/scripts" ]]; then
			find "${af_root}/scripts" \( -name "*.sh" -o -name "*.py" \) -type f -exec chmod 755 {} + 2>/dev/null || true
		fi
		if [[ -f "${af_root}/build_gold.sh" ]]; then
			chmod 755 "${af_root}/build_gold.sh"
		fi

		# Database & runtime state directories: exclusively writable by the service user
		mkdir -p "${af_root}/backend/data" /var/lib/aetherflow /var/log/aetherflow
		chmod 700 /var/lib/aetherflow "${af_root}/backend/data" 2>/dev/null || true
		if [[ -n "${username:-}" && ! -f /var/lib/aetherflow/.master.creds ]]; then
			AF_SETUP_USER="${username}" AF_MASTER_SECRET="${AETHERFLOW_MASTER_CREDS_SECRET:-}" python3 - <<'PY' 2>/dev/null || true
import base64, binascii, ctypes, ctypes.util, hashlib, importlib.util, json, os, secrets, stat, tempfile

destination = "/var/lib/aetherflow/.master.creds"
directory = "/var/lib/aetherflow"
u = os.environ["AF_SETUP_USER"]
p = os.environ.get("AF_MASTER_SECRET", "").strip() or secrets.token_hex(16)
h = hashlib.md5(f"{u}:Welcome to AetherFlow:{p}".encode("utf-8")).hexdigest()

if os.path.lexists(directory) and stat.S_ISLNK(os.lstat(directory).st_mode):
    raise SystemExit("Refusing symlinked /var/lib/aetherflow")
if os.path.lexists(destination) and stat.S_ISLNK(os.lstat(destination).st_mode):
    raise SystemExit("Refusing symlinked .master.creds")

def resolve_aes_key():
    raw = os.environ.get("AES_MASTER_KEY", "").strip()
    if not raw:
        env_path = os.environ.get("AETHERFLOW_ENV_FILE", "/etc/aetherflow/aetherflow.env")
        if os.path.isfile(env_path) and not os.path.islink(env_path):
            fd = os.open(env_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            try:
                with os.fdopen(fd, "r", encoding="utf-8", closefd=False) as fh:
                    for line in fh:
                        s = line.strip()
                        if not s or s.startswith("#"):
                            continue
                        if s.startswith("export "):
                            s = s[7:].strip()
                        if s.startswith("AES_MASTER_KEY="):
                            cand = s.split("=", 1)[1].strip().strip("\"'")
                            if cand:
                                raw = cand
            finally:
                os.close(fd)
    if not raw:
        return None
    if len(raw) == 64:
        if all(ch in "0123456789abcdefABCDEF" for ch in raw):
            return bytes.fromhex(raw)
        raise SystemExit("Invalid 64-character hex AES_MASTER_KEY")
    decoded_b64 = None
    try:
        decoded_b64 = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        decoded_b64 = None
    if decoded_b64 is not None and len(decoded_b64) == 32:
        return decoded_b64
    rb = raw.encode("utf-8")
    if len(rb) == 32:
        return rb
    raise SystemExit("Invalid AES_MASTER_KEY length; expected 32 bytes, base64(32B), or 64-char hex")

def encrypt_if_key(pt_str, key):
    if key is None:
        return pt_str
    nonce = os.urandom(12)
    pt = pt_str.encode("utf-8")
    if importlib.util.find_spec("cryptography") is not None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        ct = AESGCM(key).encrypt(nonce, pt, None)
        return "enc:v1:" + base64.b64encode(nonce + ct).decode("ascii")
    found = ctypes.util.find_library("crypto")
    for name in ([found] if found else []) + ["libcrypto.so.3", "libcrypto.so.1.1"]:
        try:
            lib = ctypes.CDLL(name)
            break
        except OSError:
            lib = None
    if lib is None:
        raise RuntimeError("libcrypto unavailable")
    lib.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    lib.EVP_aes_256_gcm.restype = ctypes.c_void_p
    lib.EVP_CIPHER_CTX_ctrl.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
    lib.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
    lib.EVP_EncryptUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int), ctypes.c_void_p, ctypes.c_int]
    lib.EVP_EncryptFinal_ex.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int)]
    ctx = lib.EVP_CIPHER_CTX_new()
    try:
        key_buf = (ctypes.c_ubyte * 32).from_buffer_copy(key)
        iv_buf = (ctypes.c_ubyte * 12).from_buffer_copy(nonce)
        lib.EVP_EncryptInit_ex(ctx, lib.EVP_aes_256_gcm(), None, None, None)
        lib.EVP_CIPHER_CTX_ctrl(ctx, 0x9, 12, None)
        lib.EVP_EncryptInit_ex(ctx, None, None, ctypes.byref(key_buf), ctypes.byref(iv_buf))
        out_buf = (ctypes.c_ubyte * max(1, len(pt) + 16))()
        out_len = ctypes.c_int(0)
        if pt:
            pt_buf = (ctypes.c_ubyte * len(pt)).from_buffer_copy(pt)
            lib.EVP_EncryptUpdate(ctx, ctypes.byref(out_buf), ctypes.byref(out_len), ctypes.byref(pt_buf), len(pt))
        final_len = ctypes.c_int(0)
        tail_ptr = ctypes.cast(ctypes.addressof(out_buf) + out_len.value, ctypes.c_void_p)
        lib.EVP_EncryptFinal_ex(ctx, tail_ptr, ctypes.byref(final_len))
        tag_buf = (ctypes.c_ubyte * 16)()
        lib.EVP_CIPHER_CTX_ctrl(ctx, 0x10, 16, ctypes.byref(tag_buf))
        ct = bytes(out_buf[:out_len.value + final_len.value]) + bytes(tag_buf)
        return "enc:v1:" + base64.b64encode(nonce + ct).decode("ascii")
    finally:
        lib.EVP_CIPHER_CTX_free(ctx)

key = resolve_aes_key()
fd, tmp_path = tempfile.mkstemp(prefix=".master.creds.", dir=directory)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        os.fchmod(fh.fileno(), 0o600)
        json.dump({"username": u, "password": encrypt_if_key(p, key), "ha1": encrypt_if_key(h, key)}, fh)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp_path, destination)
    tmp_path = None
finally:
    if tmp_path and os.path.exists(tmp_path):
        os.unlink(tmp_path)
PY
			chmod 600 /var/lib/aetherflow/.master.creds 2>/dev/null || true
		fi
		if [[ -f /var/lib/aetherflow/.master.creds ]] && type _scrub_config_keys &>/dev/null; then
			_scrub_config_keys passwd ha1pass || true
		fi
		if [[ "${EUID:-$(id -u)}" -eq 0 && ! -L /install ]]; then
			install -d -m 0750 -o root -g aetherflow /install 2>/dev/null || true
		fi
		chown -R aetherflow:aetherflow "${af_root}/backend/data" /var/lib/aetherflow 2>/dev/null || true
		chown root:aetherflow /var/log/aetherflow 2>/dev/null || true
		chmod 750 /var/log/aetherflow 2>/dev/null || true
		chmod 700 /var/lib/aetherflow "${af_root}/backend/data" 2>/dev/null || true
		find "${af_root}/backend/data" /var/lib/aetherflow -maxdepth 1 -type f -exec chmod 600 {} + 2>/dev/null || true
		if [[ -d "${af_root}/releases" ]]; then
			find "${af_root}/releases" -path "*/data-snapshot" -type d -exec chmod 700 {} + 2>/dev/null || true
			find "${af_root}/releases" -path "*/data-snapshot/*" -type f -exec chmod 600 {} + 2>/dev/null || true
		fi
		if [[ -d "${af_root}/dashboard/db" ]]; then
			chown -R aetherflow:aetherflow "${af_root}/dashboard/db" 2>/dev/null || true
			chmod 750 "${af_root}/dashboard/db"
		fi

		# Remove any world-writable files
		find "${af_root}" -perm -002 -type f -exec chmod o-w {} + 2>/dev/null || true
		find "${af_root}" -perm -002 -type d -exec chmod o-w {} + 2>/dev/null || true
	fi

	echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✓ Permission hardening complete for ${af_root}" >> "${INSTALL_LOG:-/dev/null}"
}

# Post-check: ensure aetherflow-api runs as unprivileged user
_validate_no_root_services() {
	local warnings=0

	# Validate aetherflow-api.service runs as unprivileged user
	if systemctl is-active aetherflow-api.service >/dev/null 2>&1; then
		local exec_user
		exec_user="$(systemctl show -p MainPID aetherflow-api.service --value 2>/dev/null)"
		if [[ -n "${exec_user}" ]] && [[ "${exec_user}" != "0" ]]; then
			local running_user
			running_user="$(ps -o user= -p "${exec_user}" 2>/dev/null)" || true
			if [[ "${running_user}" == "root" ]]; then
				echo -e "[ ${yellow:-\033[33m}WARN${normal:-\033[0m} ] aetherflow-api.service is running as root!"
				echo "[$(date '+%Y-%m-%d %H:%M:%S')] ⚠ WARNING: aetherflow-api.service running as root" >> "${INSTALL_LOG}"
				((warnings++))
			fi
		fi
	fi

	if [[ ${warnings} -eq 0 ]]; then
		echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✓ AetherFlow services running with verified least privilege" >> "${INSTALL_LOG}"
	fi

	return 0
}

# Configure TCP BBR congestion control via native kernel sysctl
function _configure_bbr() {
	install -d -m 0755 /etc/sysctl.d
	cat > /etc/sysctl.d/99-aetherflow-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
	chmod 0644 /etc/sysctl.d/99-aetherflow-bbr.conf
	modprobe tcp_bbr >/dev/null 2>&1 || true
	sysctl --system >/dev/null 2>&1 || true
}

# function to show finished data
# shellcheck disable=2312,2162,2249,2250
function _finished() {
	local outto="${OUTTO:-/dev/null}"
	local info_file="${AF_INFO_FILE:-/root/information.info}"
	ip="$(_af_primary_ipv4)"
	[[ -n "${ip}" ]] || ip="127.0.0.1"
	local saved_host=""
	if type _load_config &>/dev/null; then
		saved_host="$(_load_config hostname_value 2>/dev/null || true)"
		if [[ -z "${saved_host}" ]]; then
			saved_host="$(_load_config domain 2>/dev/null || true)"
		fi
	fi
	local onboarding_host="${domain:-${hostname_value:-${saved_host:-${ip}}}}"
	local onboarding_url="https://${onboarding_host}/"
	echo
	echo
	echo -e " ╭────────────────────────────────────────────────────────────────╮"
	echo -e " │ ${bold}${green}      [AetherFlow] Installation Successfully Completed!       ${normal}│"
	echo -e " │────────────────────────────────────────────────────────────────│"
	echo -e " │ ${cyan}Time elapsed:${normal} ${FIN:-0} minutes"
	echo -e " │"
	echo -e " │ ${bold}Next Steps:${normal}"
	echo -e " │ Please complete setup using the web onboarding UI:"
	echo -e " │"
	echo -e " │ 👉 ${bold}${magenta}${onboarding_url}${normal}"
	echo -e " │"
	if [[ -n "${AETHERFLOW_WEB_ADMIN_PASSWORD:-}" ]]; then
		echo -e " │ Sign in with the web administrator account seeded during setup."
	else
		echo -e " │ Create your first web admin account using the one-time setup"
		echo -e " │ bootstrap token at:"
		echo -e " │   ${bold}/var/lib/aetherflow/.setup-bootstrap-token${normal}"
	fi
	echo -e " ╰────────────────────────────────────────────────────────────────╯"
	echo
	echo -e "  Useful CLI Commands:"
	echo '  --------------------'
	echo -e "  ${green}af health${normal}                         - Verify privileged runner & control plane health"
	echo -e "  ${green}af service status aetherflow-api${normal}  - Check status of the control plane API service"
	echo -e "  ${green}af service restart aetherflow-api${normal} - Restart the control plane API service"
	echo

	local info_dir
	info_dir="$(dirname "${info_file}")"
	if [[ ! -d "${info_dir}" ]]; then
		install -d -m 0700 "${info_dir}"
	fi
	if [[ -L "${info_file}" ]]; then
		echo "[ERROR] Refusing symlinked info file: ${info_file}" >>"${outto}" 2>&1
		return 1
	fi
	install -m 0600 /dev/null "${info_file}"
	cat >"${info_file}" <<EOF
AetherFlow Seedbox Initialized successfully.
Dashboard Onboarding: ${onboarding_url}
Admin Username: ${username:-}
Setup Bootstrap Token File (for remote/proxied first-admin setup): /var/lib/aetherflow/.setup-bootstrap-token
EOF
	local af_root="${AF_INSTALL_ROOT:-/opt/AetherFlow}"
	af_root="$(realpath -m "${af_root}" 2>/dev/null || printf '%s' "${af_root%/}")"
	af_root="${af_root%/}"
	if [[ "${AF_SKIP_SELF_DELETE:-0}" != "1" ]] && [[ -n "${af_root}" ]] && [[ "$(realpath "$0" 2>/dev/null || echo "$0")" != "${af_root}"/* ]]; then
		rm -rf "$0" >>"${outto}" 2>&1
	fi
	if [[ "${AF_SKIP_SYSTEMCTL:-0}" != "1" ]] && command -v systemctl >/dev/null 2>&1; then
		local _php_etc="${AF_PHP_ETC_DIR:-/etc/php}"
		local _php_ver="${PHP_VER:-}"
		if [[ -z "${_php_ver}" || ! -d "${_php_etc}/${_php_ver}/fpm" ]]; then
			local _detected_php_ver=""
			_detected_php_ver="$(find "${_php_etc}" -mindepth 2 -maxdepth 2 -type d -name fpm 2>/dev/null | awk -F/ '{print $(NF-1)}' | sort -V | tail -n1)" || true
			if [[ -n "${_detected_php_ver}" ]]; then
				_php_ver="${_detected_php_ver}"
			fi
		fi
		if [[ -n "${_php_ver}" ]]; then
			systemctl enable "php${_php_ver}-fpm" >>"${outto}" 2>&1 || true
			systemctl restart "php${_php_ver}-fpm" >>"${outto}" 2>&1 || true
		fi
		for i in ssh apache2 fail2ban cron; do
			systemctl restart "${i}" >>"${outto}" 2>&1 || true
			systemctl enable "${i}" >>"${outto}" 2>&1 || true
		done
		local ftpd_flag="${AETHERFLOW_ENABLE_FTPD:-no}"
		case "${ftpd_flag,,}" in
			1|true|yes|y|on)
				systemctl enable vsftpd >>"${outto}" 2>&1 || true
				if ! systemctl restart vsftpd >>"${outto}" 2>&1; then
					echo -e "[ ${yellow:-\033[33m}WARN${normal:-\033[0m} ] vsftpd failed to start; inspect /etc/vsftpd.conf and 'journalctl -u vsftpd'"
				fi
				;;
		esac
	fi
	if [[ -n "${AF_SETUP_SCRATCH_DIR:-}" && "${AF_SETUP_SCRATCH_DIR}" == /var/tmp/aetherflow-setup.* && "${AF_SETUP_SCRATCH_DIR}" != *".."* && -d "${AF_SETUP_SCRATCH_DIR}" && ! -L "${AF_SETUP_SCRATCH_DIR}" ]]; then
		rm -rf -- "${AF_SETUP_SCRATCH_DIR}"
	fi
	local reboot_response
	local saved_reboot
	saved_reboot="$(_load_config reboot_after_install)"
	if [[ -n "${saved_reboot}" ]]; then
		reboot_response="$(_af_normalize_yes_no "${saved_reboot}" "no")"
		echo "  Using saved reboot preference: ${reboot_response}"
	elif [[ "${UNATTENDED:-false}" == "true" ]]; then
		reboot_response="no"
		echo "  Unattended mode: skipping automatic reboot."
		_save_config reboot_after_install "${reboot_response}"
	else
		echo -ne "  Do you wish to reboot (recommended!): (Default ${green}Y${normal}) "
		read -r reboot_response
		reboot_response="$(_af_normalize_yes_no "${reboot_response}" "yes")"
		_save_config reboot_after_install "${reboot_response}"
	fi
	case $reboot_response in
	[yY] | [yY][Ee][Ss] | "") systemctl reboot ;;
	[nN] | [nN][Oo]) echo "  ${cyan}Skipping reboot${normal} ... " ;;
	esac
}
