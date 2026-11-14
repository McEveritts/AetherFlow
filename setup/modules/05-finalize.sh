#!/bin/bash
# Module: 05-finalize.sh

# Failsafe: ensure OUTTO has a default value
OUTTO="${OUTTO:-/dev/null}"


# function to configure pure-ftpd
function _ftpdconfig() {
	\cp -f ${local_setup}templates/openssl.cnf.template /root/.openssl.cnf

	#openssl req -config /root/.openssl.cnf -x509 -nodes -days 365 -newkey rsa:1024 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem >/dev/null 2>&1
	openssl req -config /root/.openssl.cnf -x509 -nodes -days 720 -newkey rsa:2048 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem >/dev/null 2>&1

	\cp -f ${local_setup}templates/vsftpd.conf.template /etc/vsftpd.conf

	# Enabling passive mode
	sed -i 's/^\(pasv_min_port=\).*/\110090/' /etc/vsftpd.conf
	sed -i 's/^\(pasv_max_port=\).*/\110100/' /etc/vsftpd.conf
	local passive_ip
	passive_ip="$(ip route get 8.8.8.8 | awk 'NR==1 {print $7}')"
	echo "pasv_address=${passive_ip}" >>/etc/vsftpd.conf
	/sbin/iptables -I INPUT -p tcp --destination-port 10090:10100 -j ACCEPT

	echo "" >/etc/vsftpd.chroot_list
}

# seedbox boot for first user
function _boot() {
	# Use safe overlay for AetherFlow systemd unit files — preserves user modifications
	_safe_overlay_config "${local_setup}templates/sysd/aetherflow-heal.service" \
		/etc/systemd/system/aetherflow-heal.service
	_safe_overlay_config "${local_setup}templates/sysd/aetherflow-heal.timer" \
		/etc/systemd/system/aetherflow-heal.timer

	# Install AetherFlow Runner and Control Plane single-binary systemd service files
	if [[ ! -f /etc/systemd/system/aetherflow-runner.service ]]; then
		_safe_overlay_config "${local_setup}templates/sysd/aetherflow-runner.template" \
			/etc/systemd/system/aetherflow-runner.service
	fi
	if [[ ! -f /etc/systemd/system/aetherflow-api.service ]] || grep -qE "__AES_MASTER_KEY__|ProtectProc=invisible|ProcSubset=pid" /etc/systemd/system/aetherflow-api.service 2>/dev/null; then
		_safe_overlay_config "${local_setup}templates/sysd/aetherflow-api.template" \
			/etc/systemd/system/aetherflow-api.service
	fi
	rm -f /etc/systemd/system/aetherflow-front*.service 2>/dev/null || true

	# Ensure permissions and service user are configured before starting services
	_harden_permissions
	_safe_overlay_config /opt/AetherFlow/current/deploy/systemd/aetherflow-log-retention.service \
		/etc/systemd/system/aetherflow-log-retention.service || return 1
	_safe_overlay_config /opt/AetherFlow/current/deploy/systemd/aetherflow-log-retention.timer \
		/etc/systemd/system/aetherflow-log-retention.timer || return 1
	if type _mark_step &>/dev/null; then
		_mark_step "harden_perms"
	fi

	systemctl daemon-reload >/dev/null 2>&1
	systemctl start aetherflow-log-retention.service || return 1
	systemctl enable --now aetherflow-log-retention.timer || return 1
	systemctl enable --now aetherflow-heal.timer >/dev/null 2>&1 || true

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

	mkdir -p /opt/AetherFlow/config
	if [[ -n "${IFACE:-}" ]]; then
		printf '%s\n' "${IFACE}" > /opt/AetherFlow/config/interface.txt
	fi
	echo "*/1 * * * * root bash /usr/local/bin/AetherFlow/system/set_interface" >/etc/cron.d/set_interface
	/usr/local/bin/AetherFlow/system/set_interface >/dev/null 2>&1 || true
}

# function to set permissions on first user
function _perms() {
	chown -R ${username}.${username} /home/${username}/ >>"${OUTTO}" 2>&1
	sudo -u ${username} chmod 755 /home/${username}/ >>"${OUTTO}" 2>&1
	chmod +x /etc/cron.daily/denypublic >/dev/null 2>&1
	# Tightened from 777 → 770 (owner + group only, no world access)
	chmod 770 /home/${username}/.sessions >/dev/null 2>&1
}

################################################################################
# Permission Bounding — Principle of Least Privilege
################################################################################

# Create the dedicated aetherflow system user for running services
_ensure_aetherflow_user() {
	if ! id -u aetherflow >/dev/null 2>&1; then
		useradd --system --shell /usr/sbin/nologin \
			--home-dir /opt/AetherFlow \
			--comment "AetherFlow service account" \
			aetherflow >>"${OUTTO}" 2>&1
		echo "[$(date '+%Y-%m-%d %H:%M:%S')] Created system user: aetherflow" >> "${INSTALL_LOG}"
	fi
	usermod -a -G systemd-journal,adm aetherflow >>"${OUTTO}" 2>&1 || true
}

# Comprehensive permission hardening across /opt/AetherFlow
_harden_permissions() {
	local af_root="/opt/AetherFlow"

	# Ensure the service user exists
	_ensure_aetherflow_user

	# Ownership: root:aetherflow for immutable code, releases, and scripts; only mutable data dirs are writable by aetherflow
	if [[ -d "${af_root}" ]]; then
		find "${af_root}" \( -path "${af_root}/backend/data" -o -path "${af_root}/dashboard/db" -o -path "${af_root}/releases/*/data-snapshot" \) -prune -o -exec chown -h root:aetherflow {} + >>"${OUTTO}" 2>&1

		# Directories: 755 (rwxr-xr-x), pruning sensitive mutable/snapshot directories
		find "${af_root}" \( -path "${af_root}/backend/data" -o -path "${af_root}/dashboard/db" -o -path "${af_root}/releases/*/data-snapshot" \) -prune -o -type d -exec chmod 755 {} + >>"${OUTTO}" 2>&1

		# Regular files: 644 (rw-r--r--), pruning sensitive mutable/snapshot directories
		find "${af_root}" \( -path "${af_root}/backend/data" -o -path "${af_root}/dashboard/db" -o -path "${af_root}/releases/*/data-snapshot" \) -prune -o -type f -exec chmod 644 {} + >>"${OUTTO}" 2>&1

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
		if [[ -d "${af_root}/releases" ]]; then
			find "${af_root}/releases" -type f \( -name "aetherflow-api" -o -name "af" -o -name "*.sh" -o -name "*.py" \) -exec chmod 755 {} + 2>/dev/null || true
			find "${af_root}/releases" -path "*/packages/*" -type f -exec chmod 755 {} + 2>/dev/null || true
		fi

		# Node binaries in node_modules/.bin (including workspace root) need execute
		chmod 755 "${af_root}"/node_modules/.bin/* "${af_root}"/frontend/node_modules/.bin/* 2>/dev/null || true
		if [[ -d "${af_root}/frontend/node_modules/.bin" ]]; then
			find "${af_root}/frontend/node_modules/.bin" -type f -exec chmod 755 {} + 2>/dev/null || true
			find "${af_root}/frontend/node_modules/.bin" -type l -exec chmod 755 {} + 2>/dev/null || true
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
h = hashlib.md5(p.encode("utf-8")).hexdigest()

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

	echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✓ Permission hardening complete for ${af_root}" >> "${INSTALL_LOG}"
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

# BBR function
function _insbbr() {
	cd /tmp
	\cp -rf ${local_setup}sources/BBR/BBR.sh .
	chmod a+x BBR.sh
	bash BBR.sh -f v4.14.32 >>"${OUTTO}" 2>&1
	cd
}

# fix bcm NIC firmware
function _insbcm() {
	mkdir -p ${local_setup}/bcm
	cd ${local_setup}/bcm
	git clone https://git.kernel.org/pub/scm/linux/kernel/git/firmware/linux-firmware.git >>"${OUTTO}" 2>&1
	mkdir -p /lib/firmware/bnx2/
	\cp -rf ${local_setup}/bcm/linux-firmware/bnx2/ /lib/firmware
}

# function to create ssl cert for pure-ftpd ()
function _pureftpcert() {
	/bin/true
}
################################################################################
#   //END UNUSED FUNCTIONS//
################################################################################

# function to show finished data
# shellcheck disable=2312,2162,2249,2250
function _finished() {
	ip=$(ip route get 8.8.8.8 | awk 'NR==1 {print $7}')
	echo
	echo
	echo -e " ╭──────────────────────────────────────────────────────────╮"
	echo -e " │ ${bold}${green}    [AetherFlow] Installation Successfully Completed!    ${normal}│"
	echo -e " │──────────────────────────────────────────────────────────│"
	echo -e " │ ${cyan}Time elapsed:${normal} ${FIN} minutes                                  │"
	echo -e " │                                                          │"
	echo -e " │ ${bold}Next Steps:${normal}                                              │"
	echo -e " │ Please complete the setup using the web onboarding UI:   │"
	echo -e " │                                                          │"
	echo -e " │ 👉 ${bold}${magenta}http://${ip}:8080${normal}                              │"
	echo -e " │                                                          │"
	echo -e " │ Log in using the administrator credentials you created   │"
	echo -e " │ during this setup process.                               │"
	echo -e " ╰──────────────────────────────────────────────────────────╯"
	echo
	echo -e "  Useful CLI Commands:  "
	echo '  ----------------------'
	echo -e "  ${green}aetherflow logs${normal}    - View real-time system logs"
	echo -e "  ${green}aetherflow restart${normal} - Restart all AetherFlow services"
	echo -e "  ${green}aetherflow status${normal}  - Check status of backend & frontend"
	echo
	
	install -m 0600 /dev/null /root/information.info
	cat >/root/information.info <<EOF
AetherFlow Seedbox Initialized successfully.
Dashboard Onboarding: http://${ip}:8080
Admin Username: ${username}
EOF
	if [[ "$(realpath "$0" 2>/dev/null || echo "$0")" != /opt/AetherFlow/* ]]; then
		rm -rf "$0" >>"${OUTTO}" 2>&1
	fi
	for i in ssh apache2 vsftpd fail2ban memcached cron; do
		systemctl restart "${i}" >>/dev/null 2>&1 || true
		systemctl enable "${i}" >>/dev/null 2>&1 || true
	done
	rm -rf /root/tmp/
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
