#!/bin/bash
# Module: 04-security.sh


# Strict firewall enforcement during bootstrap.
# Allows configured SSH listener port(s) (defaulting to 22/tcp), HTTP (80/tcp),
# HTTPS (443/tcp), optional FTP (21/tcp + passive 10090:10100/tcp when
# AETHERFLOW_ENABLE_FTPD=yes), and optionally direct API (8080/tcp).
# Preserves legitimate operator-managed rules and persists via UFW or
# netfilter-persistent (/etc/iptables/rules.v4 and rules.v6).
#
# This replaces the old _ssdpblock() which only blocked port 1900.
function _ssdpblock() {
	# Retained as a no-op for backward compatibility with state files
	# that already have "ssdpblock" marked as done. Actual firewall
	# work is now handled by _setup_firewall.
	return 0
}

_fw_is_valid_port() {
	local p="${1:-}"
	[[ "${p}" =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#${p} >= 1 && 10#${p} <= 65535 ))
}

_fw_extract_port_from_endpoint() {
	local endpoint="${1:-}"
	local candidate=""
	endpoint="${endpoint%\"}"
	endpoint="${endpoint#\"}"
	if _fw_is_valid_port "${endpoint}"; then
		printf '%s\n' "${endpoint}"
		return 0
	fi
	if [[ "${endpoint}" =~ ^\[[^]]+\]:([1-9][0-9]{0,4})$ ]]; then
		candidate="${BASH_REMATCH[1]}"
	elif [[ "${endpoint}" =~ ^[^:]+:([1-9][0-9]{0,4})$ ]]; then
		candidate="${BASH_REMATCH[1]}"
	fi
	if _fw_is_valid_port "${candidate}"; then
		printf '%s\n' "${candidate}"
		return 0
	fi
	return 1
}

_fw_detect_ssh_ports() {
	local sys_root="${AF_SYS_ROOT:-}"
	local explicit="${AF_SSH_PORTS:-${AETHERFLOW_SSH_PORT:-}}"
	local sshd_config="${AF_SSHD_CONFIG:-$sys_root/etc/ssh/sshd_config}"
	local port directive value rest unit socket_ports="" line
	{
		if [[ -n "$explicit" ]]; then
			for port in ${explicit//,/ }; do
				if _fw_is_valid_port "$port"; then printf '%s\n' "$port"; fi
			done
		else
			# systemd applies ListenStream resets and drop-in precedence.
			if [[ -z "$sys_root" || "${AF_FW_USE_SYSTEMCTL:-0}" == 1 ]]; then
				for unit in ssh.socket sshd.socket; do
					if systemctl is-active --quiet "$unit" 2>/dev/null || systemctl is-enabled --quiet "$unit" 2>/dev/null; then
						while read -r value rest; do
							if port="$(_fw_extract_port_from_endpoint "$value")"; then
								socket_ports="yes"
								printf '%s\n' "$port"
							fi
						done < <(systemctl show -p Listen --value "$unit" 2>/dev/null || true)
					fi
				done
			fi
			# sshd evaluates includes and ignores options outside the global scope.
			if [[ -z "$socket_ports" && -f "$sshd_config" ]]; then
				while read -r directive value rest; do
					case "$directive" in
						port|listenaddress) _fw_extract_port_from_endpoint "$value" || true ;;
					esac
				done < <(sshd -T -f "$sshd_config" 2>/dev/null || true)
			fi
			if [[ -z "$sys_root" || "${AF_FW_USE_SS:-0}" == 1 ]]; then
				while IFS= read -r line; do
					_fw_extract_port_from_endpoint "$line" || true
				done < <(ss -H -ltnp 2>/dev/null | awk '/"sshd"|"sshd-session"/ {print $4}' || true)
			fi
		fi
		# Keep the port of the current administrative connection.
		read -r _ _ _ port _ <<< "${SSH_CONNECTION:-}"
		if _fw_is_valid_port "$port"; then printf '%s\n' "$port"; fi
	} | awk 'NF && !seen[$0]++ { printf "%s%s", (count++ ? " " : ""), $0 }
	         END { print (count ? "" : "22") }'
}

_fw_allowed_ports() {
	local ssh_ports=""
	local port=""
	local ports=""
	ssh_ports="$(_fw_detect_ssh_ports)"
	for port in ${ssh_ports}; do
		ports="${ports:+${ports} }${port}/tcp"
	done
	ports="${ports:+${ports} }80/tcp 443/tcp"
	local ftpd_flag="${AETHERFLOW_ENABLE_FTPD:-no}"
	case "${ftpd_flag,,}" in
		1|true|yes|y|on)
			ports="${ports} 21/tcp 10090:10100/tcp"
			;;
	esac
	if [[ "${AF_ALLOW_DIRECT_8080:-0}" == "1" || "${AF_ALLOW_DIRECT_8080:-false}" == "true" ]]; then
		ports="${ports} 8080/tcp"
	fi
	echo "${ports}"
}

_fw_ufw_is_active() {
	command -v ufw >/dev/null 2>&1 || return 1
	local status_out=""
	status_out="$(ufw status 2>/dev/null || true)"
	[[ "${status_out}" == *"Status: active"* ]]
}

_fw_chain_has_operator_rules() {
	local tool="$1"
	local rules=""
	command -v "${tool}" >/dev/null 2>&1 || return 1
	rules="$("${tool}" -S INPUT 2>/dev/null || true)"
	if [[ -n "${rules}" ]] && awk '
		/^-P[ \t]+INPUT[ \t]+(DROP|REJECT)([ \t]|$)/ { found=1; exit 0 }
		/^-A[ \t]+INPUT[ \t]+/ {
			if ($0 ~ /-j[ \t]+(ufw-|f2b-)/) next
			found=1
			exit 0
		}
		END { exit(found ? 0 : 1) }
	' <<< "${rules}"; then
		return 0
	fi
	rules="$("${tool}" -S FORWARD 2>/dev/null || true)"
	if [[ -n "${rules}" ]] && awk '
		/^-A[ \t]+FORWARD[ \t]+/ {
			if ($0 ~ /-j[ \t]+(ufw-|f2b-)/) next
			found=1
			exit 0
		}
		END { exit(found ? 0 : 1) }
	' <<< "${rules}"; then
		return 0
	fi
	return 1
}

_fw_has_operator_iptables_rules() {
	_fw_chain_has_operator_rules iptables || _fw_chain_has_operator_rules ip6tables
}

_setup_firewall() {
	local install_log="${INSTALL_LOG:-/dev/null}"
	local outto="${OUTTO:-/dev/null}"
	local allowed_ports=""
	allowed_ports="$(_fw_allowed_ports)"
	if [[ -z "${allowed_ports}" ]]; then
		echo "[ERROR] Refusing firewall setup with empty allowed port list." >>"${outto}" 2>&1
		return 1
	fi

	# If UFW is already active, reconcile non-destructively via UFW to preserve existing UFW rules.
	if _fw_ufw_is_active; then
		if _setup_firewall_ufw "${allowed_ports}"; then
			echo "[$(date '+%Y-%m-%d %H:%M:%S')] Firewall configured via active UFW (${allowed_ports})" >> "${install_log}"
			return 0
		fi
		return 1
	fi

	# If operator-managed raw iptables rules already exist while UFW is inactive,
	# do not let UFW flush them; reconcile non-destructively via iptables + netfilter-persistent.
	if _fw_has_operator_iptables_rules; then
		echo "[INFO] Preserving existing operator-managed iptables rules" >>"${outto}" 2>&1
		_setup_firewall_iptables "${allowed_ports}" || return 1
		echo "[$(date '+%Y-%m-%d %H:%M:%S')] Firewall configured via iptables preserving operator rules (${allowed_ports})" >> "${install_log}"
		return 0
	fi

	# Clean host: prefer UFW, with non-destructive iptables + netfilter-persistent fallback.
	if _setup_firewall_ufw "${allowed_ports}"; then
		echo "[$(date '+%Y-%m-%d %H:%M:%S')] Firewall configured via UFW (${allowed_ports})" >> "${install_log}"
		return 0
	fi

	echo "[INFO] UFW unavailable — falling back to iptables"
	_setup_firewall_iptables "${allowed_ports}" || return 1
	echo "[$(date '+%Y-%m-%d %H:%M:%S')] Firewall configured via iptables (${allowed_ports})" >> "${install_log}"
	return 0
}

_setup_firewall_ufw() {
	local allowed_ports="$1"
	local outto="${OUTTO:-/dev/null}"

	# Install UFW if not present
	if ! command -v ufw >/dev/null 2>&1; then
		DEBIAN_FRONTEND=noninteractive apt-get -yqq install ufw >>"${outto}" 2>&1 || return 1
	fi

	# Verify it installed
	command -v ufw >/dev/null 2>&1 || return 1

	# Allow required ports (including configured SSH listeners) BEFORE setting deny-incoming or enabling.
	# Never call `ufw reset` so existing operator UFW rules are preserved.
	local port_spec=""
	for port_spec in ${allowed_ports}; do
		ufw allow "${port_spec}" >>"${outto}" 2>&1 || return 1
	done

	# Block SSDP (port 1900 UDP) — migrated from old _ssdpblock()
	ufw deny 1900/udp >>"${outto}" 2>&1 || return 1

	if ! _fw_ufw_is_active; then
		ufw default deny incoming >>"${outto}" 2>&1 || return 1
		ufw default allow outgoing >>"${outto}" 2>&1 || return 1
	fi

	# Enable non-interactively
	ufw --force enable >>"${outto}" 2>&1 || return 1

	# Ensure boot persistence via ufw.service when systemd is available
	if command -v systemctl >/dev/null 2>&1; then
		systemctl enable ufw >>"${outto}" 2>&1 || true
	fi

	# Verify
	ufw status verbose >>"${outto}" 2>&1 || true
	return 0
}

_fw_iptables_catchall_line() {
	local tool="$1"
	local rules=""
	rules="$("${tool}" -S INPUT 2>/dev/null || true)"
	[[ -n "${rules}" ]] || return 0
	awk '
		/^-A[ \t]+INPUT[ \t]+/ {
			idx++
			if ($0 ~ /^-A[ \t]+INPUT[ \t]+-j[ \t]+(DROP|REJECT)([ \t]+--reject-with[ \t]+[^ \t]+)?[ \t]*$/) {
				print idx
				exit 0
			}
		}
	' <<< "${rules}"
}

_fw_iptables_ensure_rule() {
	local tool="$1"
	shift
	local outto="${OUTTO:-/dev/null}"

	if "${tool}" -C INPUT "$@" 2>/dev/null; then
		return 0
	fi

	local catchall_line=""
	catchall_line="$(_fw_iptables_catchall_line "${tool}")"
	if [[ -n "${catchall_line}" ]]; then
		"${tool}" -I INPUT "${catchall_line}" "$@" 2>>"${outto}" || return 1
	else
		"${tool}" -A INPUT "$@" 2>>"${outto}" || return 1
	fi
	return 0
}

_fw_iptables_has_established_rule() {
	local tool="$1"
	"${tool}" -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null && return 0
	"${tool}" -C INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null && return 0
	"${tool}" -C INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null && return 0
	"${tool}" -C INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null && return 0
	return 1
}

_fw_apply_iptables_family() {
	local tool="$1"
	local allowed_ports="$2"
	local outto="${OUTTO:-/dev/null}"

	# Never flush INPUT: preserve existing legitimate operator-managed rules and fail2ban chains.
	_fw_iptables_ensure_rule "${tool}" -i lo -j ACCEPT || return 1

	if ! _fw_iptables_has_established_rule "${tool}"; then
		if ! _fw_iptables_ensure_rule "${tool}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT; then
			_fw_iptables_ensure_rule "${tool}" -m state --state ESTABLISHED,RELATED -j ACCEPT || return 1
		fi
	fi

	if [[ "${tool}" == "ip6tables" ]]; then
		_fw_iptables_ensure_rule "${tool}" -p ipv6-icmp -j ACCEPT || return 1
	fi

	# Allow required ports (including detected SSH listener ports) BEFORE setting INPUT DROP.
	local port_spec="" port="" proto=""
	for port_spec in ${allowed_ports}; do
		port="${port_spec%%/*}"
		proto="${port_spec##*/}"
		_fw_iptables_ensure_rule "${tool}" -p "${proto}" --dport "${port}" -j ACCEPT || return 1
	done

	# Block SSDP (port 1900 UDP) — migrated from old _ssdpblock()
	_fw_iptables_ensure_rule "${tool}" -p udp --dport 1900 -j DROP || return 1

	# Set default policies only after all allow rules succeeded (prevents SSH lockout on partial failure).
	"${tool}" -P INPUT DROP 2>>"${outto}" || return 1

	# Only restrict FORWARD default policy if no operator-managed FORWARD rules exist.
	local fwd_rules=""
	fwd_rules="$("${tool}" -S FORWARD 2>/dev/null || true)"
	if ! grep -qE '^-A[[:space:]]+FORWARD[[:space:]]+' <<< "${fwd_rules}"; then
		"${tool}" -P FORWARD DROP 2>>"${outto}" || return 1
	fi
	return 0
}

_fw_persist_iptables() {
	local outto="${OUTTO:-/dev/null}"
	local sys_root="${AF_SYS_ROOT:-}"
	local rules_dir="${AF_IPTABLES_RULES_DIR:-${sys_root}/etc/iptables}"
	local v4_file="${rules_dir}/rules.v4"
	local v6_file="${rules_dir}/rules.v6"

	if [[ -L "${rules_dir}" || -L "${v4_file}" || ( -e "${v4_file}" && ! -f "${v4_file}" ) || -L "${v6_file}" || ( -e "${v6_file}" && ! -f "${v6_file}" ) ]]; then
		echo "[ERROR] Refusing unsafe symlinked iptables persistence path under ${rules_dir}." >>"${outto}" 2>&1
		return 1
	fi

	# Prefer the installed iptables-persistent / netfilter-persistent mechanism consistently.
	if command -v netfilter-persistent >/dev/null 2>&1; then
		if netfilter-persistent save >>"${outto}" 2>&1; then
			if command -v systemctl >/dev/null 2>&1; then
				systemctl enable netfilter-persistent.service >>"${outto}" 2>&1 || true
			fi
			return 0
		fi
		echo "[WARN] netfilter-persistent save failed; falling back to atomic rules.v4/rules.v6 write" >>"${outto}" 2>&1
	fi

	if ! command -v iptables-save >/dev/null 2>&1; then
		echo "[ERROR] Neither netfilter-persistent nor iptables-save is available to persist iptables rules." >>"${outto}" 2>&1
		return 1
	fi

	install -d -m 0755 "${rules_dir}" || return 1
	local tmp_v4=""
	tmp_v4="$(umask 0027 && mktemp "${rules_dir}/.rules.v4.af.XXXXXX")" || return 1
	if ! iptables-save > "${tmp_v4}" 2>>"${outto}" || [[ ! -s "${tmp_v4}" ]] || ! chmod 0640 "${tmp_v4}" || ! mv -fT -- "${tmp_v4}" "${v4_file}"; then
		rm -f -- "${tmp_v4}"
		return 1
	fi

	if command -v ip6tables-save >/dev/null 2>&1; then
		local tmp_v6=""
		tmp_v6="$(umask 0027 && mktemp "${rules_dir}/.rules.v6.af.XXXXXX")" || return 1
		if ip6tables-save > "${tmp_v6}" 2>>"${outto}" && [[ -s "${tmp_v6}" ]]; then
			if ! chmod 0640 "${tmp_v6}" || ! mv -fT -- "${tmp_v6}" "${v6_file}"; then
				rm -f -- "${tmp_v6}"
				return 1
			fi
		else
			rm -f -- "${tmp_v6}"
		fi
	fi

	if command -v systemctl >/dev/null 2>&1; then
		systemctl enable netfilter-persistent.service >>"${outto}" 2>&1 || true
	fi
	return 0
}

_setup_firewall_iptables() {
	local allowed_ports="$1"
	local outto="${OUTTO:-/dev/null}"

	if ! command -v iptables >/dev/null 2>&1; then
		echo "[ERROR] iptables binary not found." >>"${outto}" 2>&1
		return 1
	fi

	_fw_apply_iptables_family iptables "${allowed_ports}" || return 1

	if command -v ip6tables >/dev/null 2>&1 && ip6tables -S INPUT >/dev/null 2>&1; then
		_fw_apply_iptables_family ip6tables "${allowed_ports}" || return 1
	fi

	_fw_persist_iptables || return 1
	return 0
}

# ban public trackers [iptables option] (11)
# shellcheck disable=2249,2162
function _denyhosts() {
	local response
	local saved_response
	saved_response="$(_load_config denyhosts)"
	if [[ -n "${saved_response}" ]]; then
		response="${saved_response}"
		echo "Using saved preference: denyhosts=${response}"
	elif [[ "${UNATTENDED:-false}" == "true" ]]; then
		response="yes"
		echo "Unattended mode: blocking public trackers."
		_save_config denyhosts "${response}"
	else
		echo -ne "${bold}${yellow}Block Public Trackers?${normal}: [${green}y${normal}]es or [n]o: "
		read -r response
	fi

	case ${response} in
	[yY] | [yY][Ee][Ss] | "")

		echo "[ ${red}-  Blocking public trackers  -${normal} ]"
		\cp -f "${local_setup}templates/trackers.template" /etc/trackers
		\cp -f "${local_setup}templates/denypublic.template" /etc/cron.daily/denypublic
		chmod +x /etc/cron.daily/denypublic
		local hosts_file="${AF_HOSTS_FILE:-/etc/hosts}"
		if [[ -L "${hosts_file}" ]]; then
			echo "[ERROR] Refusing symlinked hosts file: ${hosts_file}" >>"${OUTTO:-/dev/null}" 2>&1
			return 1
		fi
		local hosts_dir
		hosts_dir="$(dirname "${hosts_file}")"
		local tmp_hosts
		tmp_hosts="$(mktemp "${hosts_dir}/.hosts.af.XXXXXX")" || return 1
		if [[ -f "${hosts_file}" ]]; then
			awk '
				/^# BEGIN AETHERFLOW TRACKER BLOCK$/ { in_block=1; next }
				/^# END AETHERFLOW TRACKER BLOCK$/ { in_block=0; next }
				!in_block { print }
			' "${hosts_file}" > "${tmp_hosts}" || { rm -f "${tmp_hosts}"; return 1; }
		fi
		{
			printf '# BEGIN AETHERFLOW TRACKER BLOCK\n'
			sed '$a\' "${local_setup}templates/hostsTrackers.template"
			printf '# END AETHERFLOW TRACKER BLOCK\n'
		} >> "${tmp_hosts}" || { rm -f "${tmp_hosts}"; return 1; }
		if ! chmod 0644 "${tmp_hosts}" || ! mv -fT -- "${tmp_hosts}" "${hosts_file}"; then
			rm -f -- "${tmp_hosts}"
			return 1
		fi
		_save_config denyhosts "yes"
		;;

	[nN] | [nN][Oo])
		echo "[ ${green}+  Allowing public trackers  +${normal} ]"
		_save_config denyhosts "no"
		;;
	esac
	echo
}

# Purge legacy sudoers drop-ins without overwriting /etc/sudoers (privileged actions use af-runner)
function _apachesudo() {
	if [[ -d /etc/sudoers.d && ! -L /etc/sudoers.d ]]; then
		find /etc/sudoers.d -maxdepth 1 \( -type f -o -type l \) -name 'aether*' -delete 2>/dev/null || true
	fi
	if [[ ! -L /etc/apache2 ]]; then
		mkdir -p /etc/apache2
		if [[ ! -L /etc/apache2/master.txt ]]; then
			install -o root -g root -m 0640 /dev/null /etc/apache2/master.txt
			printf '%s' "${username:-}" >/etc/apache2/master.txt
		fi
	fi
	cd || exit 1
}

# function to configure apache
function _apacheconf() {
	local apache_etc="${AF_APACHE_ETC_DIR:-/etc/apache2}"
	local legacy_aliases_conf="${AF_LEGACY_SEEDBOX_ALIASES_CONF:-${apache_etc}/sites-enabled/aliases-seedbox.conf}"
	local legacy_digest_file="${HTPASSWD:-/etc/htpasswd}"
	local basic_htpasswd="${AF_APACHE_HTPASSWD:-${apache_etc}/AetherFlow/htpasswd}"
	local default_docroot="${AF_DEFAULT_DOCROOT:-/var/www/aetherflow-default}"
	local legacy_srv_link="${AF_LEGACY_SRV_LINK:-/srv/aetherflow}"
	local php_etc="${AF_PHP_ETC_DIR:-/etc/php}"
	local outto="${OUTTO:-/dev/null}"

	if [[ "${AF_ENABLE_LEGACY_SEEDBOX_ALIASES:-0}" == "1" || -f "${legacy_aliases_conf}" || -f "${legacy_digest_file}" ]]; then
		\cp -f "${local_setup}templates/aliases-seedbox.conf.template" "${legacy_aliases_conf}"
		sed -i "s/USERNAME/${username}/g" "${legacy_aliases_conf}"
		a2enmod auth_digest >>"${outto}" 2>&1
	fi
	a2enmod ssl >>"${outto}" 2>&1
	if [[ -f "${apache_etc}/mods-available/scgi.load" ]]; then
		a2enmod scgi >>"${outto}" 2>&1 || true
	fi
	a2enmod rewrite >>"${outto}" 2>&1
	a2enmod proxy >>"${outto}" 2>&1
	a2enmod proxy_http >>"${outto}" 2>&1
	a2enmod proxy_wstunnel >>"${outto}" 2>&1
	if [[ -f "${apache_etc}/sites-enabled/000-default.conf" ]]; then
		mv "${apache_etc}/sites-enabled/000-default.conf" "${apache_etc}/" >>"${outto}" 2>&1
	fi
	\cp -f "${local_setup}templates/default-ssl.conf.template" "${apache_etc}/sites-enabled/default-ssl.conf"
	if [[ ! -s "${basic_htpasswd}" && -n "${username:-}" && -n "${passwd:-}" ]] && type _write_apache_htpasswd_files &>/dev/null; then
		_write_apache_htpasswd_files "${username}" "${passwd}" "${REALM:-Welcome to AetherFlow}" || true
	fi
	install -d -m 0755 "${default_docroot}"
	if [[ -L "${legacy_srv_link}" && "$(readlink "${legacy_srv_link}" 2>/dev/null)" == "/opt/AetherFlow" ]]; then
		rm -f "${legacy_srv_link}"
	fi
	if [[ -f "${apache_etc}/conf-enabled/security.conf" ]]; then
		sed -i "s/ServerTokens OS/ServerTokens Prod/g" "${apache_etc}/conf-enabled/security.conf"
		sed -i "s/ServerSignature On/ServerSignature Off/g" "${apache_etc}/conf-enabled/security.conf"
	fi
	rm -f "${apache_etc}/sites-enabled/fileshare.conf" 2>/dev/null || true

	# ── PHP ini hardening ─────────────────────────────────────────────────
	# Dynamically detect PHP version if the codename-mapped version is missing
	local _php_ver="${PHP_VER:-}"
	if [[ -z "${_php_ver}" ]] || [[ ! -d "${php_etc}/${_php_ver}" ]]; then
		# Fall back to the highest installed PHP version
		_php_ver="$(ls -1d "${php_etc}"/*/fpm 2>/dev/null | sort -V | tail -n1 | grep -oP '/php/\K[^/]+')" || true
		if [[ -z "${_php_ver}" ]]; then
			echo "[WARN] No PHP installation found under ${php_etc}/. Skipping PHP ini tuning."
		else
			echo "[INFO] PHP_VER=${PHP_VER:-unset} not found; using detected version: ${_php_ver}"
		fi
	fi

	local _php_ini_fpm="${php_etc}/${_php_ver}/fpm/php.ini"
	local _php_ini_apache="${php_etc}/${_php_ver}/apache2/php.ini"
	local _php_sed_args=(-i.bak -e "s/post_max_size = 8M/post_max_size = 64M/" -e "s/upload_max_filesize = 2M/upload_max_filesize = 92M/" -e "s/expose_php = On/expose_php = Off/" -e "s/128M/768M/" -e "s/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/" -e "s/;opcache.enable=0/opcache.enable=1/" -e "s/;opcache.memory_consumption=64/opcache.memory_consumption=128/" -e "s/;opcache.max_accelerated_files=2000/opcache.max_accelerated_files=4000/" -e "s/;opcache.revalidate_freq=2/opcache.revalidate_freq=240/")

	if [[ -n "${_php_ver}" ]]; then
		if [[ -f "${_php_ini_fpm}" ]]; then
			sed "${_php_sed_args[@]}" "${_php_ini_fpm}"
		else
			echo "[WARN] ${_php_ini_fpm} not found — skipping FPM php.ini tuning."
		fi

		if [[ -f "${_php_ini_apache}" ]]; then
			sed "${_php_sed_args[@]}" "${_php_ini_apache}"
		else
			echo "[WARN] ${_php_ini_apache} not found — skipping Apache php.ini tuning."
		fi

		# ensure opcache module is activated (only if phpenmod exists)
		if command -v phpenmod >/dev/null 2>&1; then
			phpenmod -v "${_php_ver}" opcache >>"${outto}" 2>&1 || true
		fi
	fi

	# these modules are purely experimental
	#a2enmod proxy_fcgi >>"${outto}" 2>&1
	#a2dismod mpm_prefork >>"${outto}" 2>&1
	#a2enmod mpm_worker >>"${outto}" 2>&1

	# ensure FCGI & event MPM + HTTP/2 modules are activated for high-concurrency proxy multiplexing
	a2enmod actions >>"${outto}" 2>&1 || true
	a2enmod headers >>"${outto}" 2>&1 || true
	a2enmod http2 >>"${outto}" 2>&1 || true
	a2enmod reqtimeout >>"${outto}" 2>&1 || true
	if [[ -f "${apache_etc}/mods-available/fastcgi.load" ]]; then
		a2enmod fastcgi >>"${outto}" 2>&1 || true
	elif [[ -f "${apache_etc}/mods-available/fcgid.load" ]]; then
		a2enmod fcgid >>"${outto}" 2>&1 || true
	fi
	a2enmod proxy_fcgi setenvif >>"${outto}" 2>&1 || true
	if [[ -n "${_php_ver}" ]]; then
		a2dismod "php${_php_ver}" >>"${outto}" 2>&1 || true
		a2enconf php"${_php_ver}"-fpm >>"${outto}" 2>&1 || echo "[WARN] php${_php_ver}-fpm Apache config not available."
	fi
	a2dismod mpm_prefork >>"${outto}" 2>&1 || true
	a2enmod mpm_event >>"${outto}" 2>&1 || true

	#sed -i 's/memory_limit = 128M/memory_limit = 768M/g' /etc/php/${PHP_VER}/apache2/php.ini
}

function _af_snakeoil_cert_subject() {
	local candidate="${1:-${FQDN:-}}"
	candidate="${candidate%.}"
	if [[ -n "${candidate}" && "${candidate}" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$ && "${candidate}" != *..* ]]; then
		printf '/CN=%s\n' "${candidate}"
	else
		printf '/CN=aetherflow.local\n'
	fi
}

# function to fix cert
# add by EFS
function _fix_cert() {
	local cert_path="${AF_SNAKEOIL_CERT:-/etc/ssl/certs/ssl-cert-snakeoil.pem}"
	local key_path="${AF_SNAKEOIL_KEY:-/etc/ssl/private/ssl-cert-snakeoil.key}"
	if [[ ! -f "${cert_path}" ]]; then
		local cert_subj
		cert_subj="$(_af_snakeoil_cert_subject "${FQDN:-}")"
		openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout "${key_path}" -out "${cert_path}" -subj "${cert_subj}" >>"${OUTTO:-/dev/null}" 2>&1
	fi
}
