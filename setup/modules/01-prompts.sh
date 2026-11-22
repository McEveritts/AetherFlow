#!/bin/bash
# Module: 01-prompts.sh



# shellcheck disable=2162
function _ask10g() {
	local saved=$(_load_config is10g)
	if [[ -n "${saved}" ]]; then
		if [[ "${saved}" == "yes" ]]; then
			if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
				install -d -m 0750 -o root -g "$(getent group aetherflow >/dev/null 2>&1 && echo aetherflow || echo root)" /install
			else
				mkdir -p /install
			fi
			touch /install/.10g.lock
		fi
		echo "Using saved preference: 10g=${saved}"
		return 0
	fi

	if [[ "${UNATTENDED:-false}" == "true" ]]; then
		echo "${cyan}Unattended mode: assuming this is not a 10 gigabit server.${normal}"
		_save_config is10g "no"
		echo
		return 0
	fi

	echo -ne "${bold}${yellow}Is this a 10 gigabit server?${normal} (Default: ${green}${bold}N${normal}) "
	read -r input
	case ${input} in
	[yY] | [yY][Ee][Ss])
		if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
			install -d -m 0750 -o root -g "$(getent group aetherflow >/dev/null 2>&1 && echo aetherflow || echo root)" /install
		else
			mkdir -p /install
		fi
		touch /install/.10g.lock
		echo "${bold}The devs are officially jealous${normal}"
		_save_config is10g "yes"
		;;
	[nN] | [nN][Oo] | "")
		echo "${cyan}Who can afford that stuff anyway?${normal}"
		_save_config is10g "no"
		;;
	*)
		echo "${cyan}Who can afford that stuff anyway?${normal}"
		_save_config is10g "no"
		;;
	esac
	echo
}

# primary partition question
# shellcheck disable=2250,2162
function _askpartition() {
	if [[ ${quota} == yes ]]; then
		local saved=$(_load_config primaryroot)
		if [[ -n "${saved}" ]]; then
			primaryroot="${saved}"
			echo "Using saved preference: primaryroot=${primaryroot}"
			return 0
		fi

		if [[ "${UNATTENDED:-false}" == "true" ]]; then
			primaryroot="root"
			echo "Unattended mode: using root mount for quotas."
			_save_config primaryroot "${primaryroot}"
			return 0
		fi

		echo
		echo "##################################################################################"
		echo "#${bold} By default the AetherFlow script will initiate a build using ${green}/${normal} ${bold}as the${normal}"
		echo "#${bold} primary partition for mounting quotas.${normal}"
		echo "#"
		echo "#${bold} Some providers, such as OVH and SYS force ${green}/home${normal} ${bold}as the primary mount ${normal}"
		echo "#${bold} on their server setups. So if you have an OVH or SYS server and have not"
		echo "#${bold} modified your partitions, it is safe to choose option ${yellow}2)${normal} ${bold}below.${normal}"
		echo "#"
		echo "#${bold} If you are not sure:${normal}"
		echo "#${bold} I have listed out your current partitions below. Your mountpoint will be"
		echo "#${bold} listed as ${green}/home${normal} ${bold}or ${green}/${normal}${bold}. ${normal}"
		echo "#"
		echo "#${bold} Typically, the partition with the most space assigned is your default.${normal}"
		echo "##################################################################################"
		echo
		lsblk
		echo
		echo -e "${bold}${yellow}1)${normal} / - ${green}root mount${normal}"
		echo -e "${bold}${yellow}2)${normal} /home - ${green}home mount${normal}"
		echo -ne "${bold}${yellow}What is your mount point for user quotas?${normal} (Default ${green}1${normal}): "
		read -r version
		case $version in
		1 | "") primaryroot=root ;;
		2) primaryroot=home ;;
		*) primaryroot=root ;;
		esac
		echo "Using ${green}$primaryroot mount${normal} for quotas"
		echo
		_save_config primaryroot "${primaryroot}"
	fi
}

# shellcheck disable=2162
function _askcontinue() {
	# If resuming, skip the "press enter" prompt
	local saved=$(_load_config continued)
	if [[ -n "${saved}" ]]; then
		return 0
	fi

	if [[ "${UNATTENDED:-false}" == "true" ]]; then
		_save_config continued "yes"
		return 0
	fi

	echo
	echo "Press ${standout}${green}ENTER${normal} when you're ready to begin or ${standout}${red}Ctrl+Z${normal} to cancel"
	read -r input
	echo
	_save_config continued "yes"
}

# Write Basic-Auth bcrypt (/etc/apache2/AetherFlow/htpasswd) and, only when explicitly opted in
# (AF_ENABLE_LEGACY_SEEDBOX_ALIASES=1) or preserving an upgraded host, legacy Digest (/etc/htpasswd).
function _write_apache_htpasswd_files() {
	local user_name="$1"
	local user_pass="$2"
	local realm="${3:-Welcome to AetherFlow}"
	local digest_file="${HTPASSWD:-/etc/htpasswd}"
	local basic_file="${AF_APACHE_HTPASSWD:-/etc/apache2/AetherFlow/htpasswd}"
	local legacy_aliases_conf="${AF_LEGACY_SEEDBOX_ALIASES_CONF:-/etc/apache2/sites-enabled/aliases-seedbox.conf}"
	local basic_dir digest_dir tmp_digest ha1
	basic_dir="$(dirname "${basic_file}")"
	digest_dir="$(dirname "${digest_file}")"

	if [[ ! "${user_name}" =~ ^[a-z_][a-z0-9_-]{0,31}$ || "${realm}" == *:* || "${realm}" =~ [[:cntrl:]] ]]; then
		printf '[ERROR] Invalid Apache credential username or realm\n' >>"${OUTTO:-/dev/null}"
		return 1
	fi
	if [[ -L "${basic_dir}" || -L "${basic_file}" || ( -e "${basic_file}" && ! -f "${basic_file}" ) ]]; then
		printf '[ERROR] Refusing unsafe Apache credential file paths\n' >>"${OUTTO:-/dev/null}"
		return 1
	fi
	if [[ "${AF_ENABLE_LEGACY_SEEDBOX_ALIASES:-0}" == "1" || -e "${digest_file}" || -L "${digest_file}" || -e "${legacy_aliases_conf}" || -L "${legacy_aliases_conf}" ]]; then
		if [[ -L "${digest_dir}" || -L "${digest_file}" || ( -e "${digest_file}" && ! -f "${digest_file}" ) ]]; then
			printf '[ERROR] Refusing unsafe Apache credential file paths\n' >>"${OUTTO:-/dev/null}"
			return 1
		fi
		mkdir -p -- "${digest_dir}" || return 1
		ha1="$(printf '%s' "${user_name}:${realm}:${user_pass}" | md5sum)" || return 1
		tmp_digest="$(mktemp "${digest_dir}/.htdigest.XXXXXX")" || return 1
		if { [[ -f "${digest_file}" ]] && ! awk -F: -v u="${user_name}" '$1 != u' "${digest_file}" > "${tmp_digest}"; } ||
		   ! printf '%s:%s:%s\n' "${user_name}" "${realm}" "${ha1%% *}" >> "${tmp_digest}" ||
		   ! chown root:www-data "${tmp_digest}" || ! chmod 0640 "${tmp_digest}" ||
		   ! mv -fT -- "${tmp_digest}" "${digest_file}"; then
			rm -f -- "${tmp_digest}"
			return 1
		fi
	fi

	install -d -m 0750 -o root -g "$(getent group www-data >/dev/null 2>&1 && echo www-data || echo root)" "${basic_dir}" 2>/dev/null || mkdir -p "${basic_dir}"

	local bcrypt_entry=""
	if command -v htpasswd >/dev/null 2>&1; then
		bcrypt_entry="$(printf '%s\n' "${user_pass}" | htpasswd -niB "${user_name}" 2>/dev/null | head -n1)" || bcrypt_entry=""
	fi
	if [[ -z "${bcrypt_entry}" || "${bcrypt_entry}" != "${user_name}:\$2y\$"* ]] && command -v python3 >/dev/null 2>&1; then
		bcrypt_entry="$(AF_HTPASSWD_USER="${user_name}" AF_HTPASSWD_PASS="${user_pass}" python3 - <<'PY' 2>/dev/null || true
import ctypes, os

ALPHABET = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
raw = os.urandom(16)
salt = []
for i in range(0, 15, 3):
    b0, b1, b2 = raw[i], raw[i + 1], raw[i + 2]
    salt.append(ALPHABET[b0 >> 2])
    salt.append(ALPHABET[((b0 & 0x03) << 4) | (b1 >> 4)])
    salt.append(ALPHABET[((b1 & 0x0F) << 2) | (b2 >> 6)])
    salt.append(ALPHABET[b2 & 0x3F])
b15 = raw[15]
salt.append(ALPHABET[b15 >> 2])
salt.append(ALPHABET[(b15 & 0x03) << 4])
setting = ("$2y$10$" + "".join(salt)).encode("ascii")

lib = None
for name in ("libcrypt.so.2", "libcrypt.so.1", "libcrypt.so"):
    try:
        lib = ctypes.CDLL(name)
        break
    except OSError:
        pass
if lib is None:
    raise SystemExit(1)
lib.crypt_rn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int]
lib.crypt_rn.restype = ctypes.c_char_p
buf = ctypes.create_string_buffer(131072)
out = lib.crypt_rn(os.environ["AF_HTPASSWD_PASS"].encode("utf-8"), setting, buf, len(buf))
if not out:
    raise SystemExit(1)
digest = out.decode("ascii")
if not digest.startswith("$2y$"):
    raise SystemExit(1)
print(f"{os.environ['AF_HTPASSWD_USER']}:{digest}")
PY
)"
	fi
	if [[ -n "${bcrypt_entry}" ]]; then
		local tmp_basic
		tmp_basic="$(umask 0027 && mktemp "${basic_dir}/.htpasswd.tmp.XXXXXX")" || return 1
		if { [[ -f "${basic_file}" ]] && ! awk -F: -v u="${user_name}" '$1 != u' "${basic_file}" > "${tmp_basic}"; } ||
		   ! printf '%s\n' "${bcrypt_entry}" >> "${tmp_basic}" ||
		   ! chown root:www-data "${tmp_basic}" || ! chmod 0640 "${tmp_basic}" ||
		   ! mv -fT -- "${tmp_basic}" "${basic_file}"; then
			rm -f -- "${tmp_basic}"
			return 1
		fi
	fi
}

# adduser function (10)
# shellcheck disable=2215,2312,2250,2162
function _adduser() {
	# Check for saved user credentials
	local saved_user=$(_load_config username)
	local saved_pass=$(_load_config passwd)
	local REALM="Welcome to AetherFlow"
	local HTPASSWD="/etc/htpasswd"
	local theshell="/bin/bash"

	if [[ "${UNATTENDED:-false}" == "true" ]]; then
		if [[ -z "${saved_user}" ]]; then
			saved_user="${username:-admin}"
		fi
		if [[ -z "${saved_pass}" ]]; then
			saved_pass="${passwd:-${password:-${genpass}}}"
		fi
		_save_config username "${saved_user}"
		_save_config passwd "${saved_pass}"
	fi

	if [[ -n "${saved_user}" && -n "${saved_pass}" ]]; then
		username="${saved_user}"
		passwd="${saved_pass}"
		echo "Using saved user: ${username}"
		# Ensure user exists on system (idempotent)
		if id "${username}" &>/dev/null; then
			/usr/sbin/usermod -a -G www-data,sudo -s "${theshell}" "${username}" 2>/dev/null || true
		else
			/usr/sbin/useradd "${username}" -m -G www-data,sudo -s "/bin/bash" 2>/dev/null
		fi
		echo "${username}:${passwd}" | /usr/sbin/chpasswd >>"${OUTTO}" 2>&1
		_write_apache_htpasswd_files "${username}" "${passwd}" "${REALM}" || return 1
		rm -f /root/"${username}".info.db
		_save_config username "${username}"
		_save_config passwd "${passwd}"
		return 0
	fi

	echo ""
	echo " ╭──────────────────────────────────────────────────────────╮"
	echo " │ ${bold}${cyan}Administrator Account Setup${normal}                                │"
	echo " │──────────────────────────────────────────────────────────│"
	echo " │ Please enter a username for your master admin account.   │"
	echo " │ This user will have sudo privileges and access to the    │"
	echo " │ web dashboard.                                           │"
	echo " ╰──────────────────────────────────────────────────────────╯"
	while true; do
		echo -ne "   ${bold}${magenta}Username (Default: admin):${normal} "
		read -r user
		username=$(printf '%s' "${user:-admin}" | tr '[:upper:]' '[:lower:]')
		if [[ "${username}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] && [[ "${username}" != "root" && "${username}" != "www-data" && "${username}" != "aetherflow" && "${username}" != "nobody" ]]; then
			break
		fi
		echo "   ${yellow}⚠ Invalid or reserved username. Use 1-32 lowercase alphanumeric/underscore/hyphen characters.${normal}"
	done
	if ! id "${username}" &>/dev/null; then
		/usr/sbin/useradd "${username}" -m -G www-data,sudo -s "${theshell}"
	else
		/usr/sbin/usermod -a -G www-data,sudo -s "${theshell}" "${username}" 2>/dev/null || true
	fi
	
	echo ""
	echo " ╭──────────────────────────────────────────────────────────╮"
	echo " │ ${bold}${cyan}Secure Password Configuration${normal}                              │"
	echo " │──────────────────────────────────────────────────────────│"
	echo " │ Type a strong password or press [ENTER] to autogenerate. │"
	echo " │ Security Requirements:                                   │"
	echo " │  • Minimum 8 characters in length                        │"
	echo " │  • Mix of uppercase, lowercase, and numbers              │"
	echo " ╰──────────────────────────────────────────────────────────╯"
	while true; do
		echo -ne "   ${bold}${magenta}Password:${normal} "
		read -rs password
		echo ""
		if [[ -z "${password}" ]]; then
			break
		elif [[ ${#password} -lt 8 ]]; then
			echo "   ${yellow}⚠ Password must be at least 8 characters long (or press [ENTER] to autogenerate).${normal}"
		else
			break
		fi
	done
	if [[ -n "${password}" ]]; then
		echo "   ${green}✓ Password manually provided.${normal}"
		passwd=${password}
		echo "${username}:${passwd}" | /usr/sbin/chpasswd >>"${OUTTO}" 2>&1
	else
		passwd=${genpass}
		echo "   ${green}✓ Password autogenerated:${normal} ${bold}${passwd}${normal}"
		echo "${username}:${passwd}" | /usr/sbin/chpasswd >>"${OUTTO}" 2>&1
	fi
	_write_apache_htpasswd_files "${username}" "${passwd}" "${REALM}" || return 1
	rm -f /root/"${username}".info.db
	echo

	# Persist username and temporary passwd for resume (scrubbed once .master.creds is initialized)
	_save_config username "${username}"
	_save_config passwd "${passwd}"
}

# install ffmpeg question (11)
# shellcheck disable=2162
function _askffmpeg() {
	local saved=$(_load_config ffmpeg)
	if [[ -n "${saved}" ]]; then
		ffmpeg="${saved}"
		echo "Using saved preference: ffmpeg=${ffmpeg}"
		return 0
	fi

	if [[ "${UNATTENDED:-false}" == "true" ]]; then
		ffmpeg="yes"
		echo
		_save_config ffmpeg "${ffmpeg}"
		return 0
	fi

	echo -ne "${bold}${yellow}Would you like to install ffmpeg? (Used for screenshots)${normal} [${green}y${normal}]es or [n]o: "
	read -r response
	case ${response} in
	[yY] | [yY][Ee][Ss] | "") ffmpeg=yes ;;
	[nN] | [nN][Oo]) ffmpeg=no ;;
	*) ffmpeg=yes ;;
	esac
	echo
	_save_config ffmpeg "${ffmpeg}"
}

# ask user for vsftpd conf (12)
# shellcheck disable=2162,2312
function _askvsftpd() {
	local saved=$(_load_config IP)
	if [[ -n "${saved}" ]]; then
		IP="${saved}"
		echo "Using saved preference: IP=${IP}"
		return 0
	fi

	local DEFAULTIP
	DEFAULTIP=$(ip -4 addr show | grep -oP 'inet \K[0-9.]+' | grep -v '127.0.0.1' | head -1)
	if [[ "${UNATTENDED:-false}" == "true" ]]; then
		IP=${DEFAULTIP}
		echo "Unattended mode: using detected public IP ${IP}"
		echo
		_save_config IP "${IP}"
		return 0
	fi
	echo -ne "${bold}${yellow}Please, write your public server IP (used for ftp)${normal} (Default: ${green}${bold}${DEFAULTIP}${normal}) "
	read -r input
	if [[ -z "${input}" ]]; then
		IP=${DEFAULTIP}
	else
		IP=${input}
	fi

	echo
	_save_config IP "${IP}"
}

# install bbr question (x)
# shellcheck disable=2162
function _askbbr() {
	local saved=$(_load_config bbr)
	if [[ -n "${saved}" ]]; then
		bbr="${saved}"
		echo "Using saved preference: bbr=${bbr}"
		return 0
	fi

	if [[ "${UNATTENDED:-false}" == "true" ]]; then
		bbr="yes"
		echo
		_save_config bbr "${bbr}"
		return 0
	fi

	echo -ne "${bold}${yellow}Would you like to install bbr? (Used for Congestion Control)${normal} [${green}y${normal}]es or [n]o: "
	read -r response
	case ${response} in
	[yY] | [yY][Ee][Ss] | "") bbr=yes ;;
	[nN] | [nN][Oo]) bbr=no ;;
	*) bbr=yes ;;
	esac
	echo
	_save_config bbr "${bbr}"
}
