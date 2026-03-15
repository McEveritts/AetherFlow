#!/bin/bash
# Module: 04-security.sh


# Strict firewall enforcement during bootstrap.
# Allows ONLY: SSH (22), HTTP (80), HTTPS (443), Next.js (3000).
# Uses UFW as preferred firewall, with iptables fallback.
#
# This replaces the old _ssdpblock() which only blocked port 1900.
function _ssdpblock() {
	# Retained as a no-op for backward compatibility with state files
	# that already have "ssdpblock" marked as done. Actual firewall
	# work is now handled by _setup_firewall.
	return 0
}

_fw_allowed_ports() {
	echo "22/tcp 80/tcp 443/tcp 3000/tcp"
}

_setup_firewall() {
	local allowed_ports
	allowed_ports="$(_fw_allowed_ports)"

	# Try UFW first
	if _setup_firewall_ufw "${allowed_ports}"; then
		echo "[$(date '+%Y-%m-%d %H:%M:%S')] Firewall configured via UFW" >> "${INSTALL_LOG}"
		return 0
	fi

	# Fallback to raw iptables
	echo "[INFO] UFW unavailable — falling back to iptables"
	_setup_firewall_iptables "${allowed_ports}"
	echo "[$(date '+%Y-%m-%d %H:%M:%S')] Firewall configured via iptables" >> "${INSTALL_LOG}"
}

_setup_firewall_ufw() {
	local allowed_ports="$1"

	# Install UFW if not present
	if ! command -v ufw >/dev/null 2>&1; then
		DEBIAN_FRONTEND=noninteractive apt-get -yqq install ufw >>"${OUTTO}" 2>&1 || return 1
	fi

	# Verify it installed
	command -v ufw >/dev/null 2>&1 || return 1

	# Set defaults — idempotent by nature in UFW
	ufw default deny incoming >>"${OUTTO}" 2>&1
	ufw default allow outgoing >>"${OUTTO}" 2>&1

	# Allow required ports — UFW handles duplicates gracefully
	local port_spec
	for port_spec in ${allowed_ports}; do
		ufw allow "${port_spec}" >>"${OUTTO}" 2>&1
	done

	# Block SSDP (port 1900 UDP) — migrated from old _ssdpblock()
	ufw deny 1900/udp >>"${OUTTO}" 2>&1

	# Enable non-interactively
	echo "y" | ufw enable >>"${OUTTO}" 2>&1

	# Verify
	ufw status verbose >>"${OUTTO}" 2>&1
	return 0
}

_setup_firewall_iptables() {
	local allowed_ports="$1"

	# Flush existing rules for a clean slate (only INPUT chain)
	# Preserve existing ESTABLISHED connections
	iptables -F INPUT 2>/dev/null || true

	# Default policies
	iptables -P INPUT DROP 2>/dev/null
	iptables -P FORWARD DROP 2>/dev/null
	iptables -P OUTPUT ACCEPT 2>/dev/null

	# Allow loopback
	iptables -A INPUT -i lo -j ACCEPT 2>/dev/null

	# Allow established connections
	iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null

	# Allow required ports
	local port_spec port proto
	for port_spec in ${allowed_ports}; do
		port="${port_spec%%/*}"
		proto="${port_spec##*/}"
		# Check if rule already exists before adding (true idempotency)
		if ! iptables -C INPUT -p "${proto}" --dport "${port}" -j ACCEPT 2>/dev/null; then
			iptables -A INPUT -p "${proto}" --dport "${port}" -j ACCEPT 2>/dev/null
		fi
	done

	# Block SSDP (port 1900 UDP) — migrated from old _ssdpblock()
	if ! iptables -C INPUT -p udp --dport 1900 -j DROP 2>/dev/null; then
		iptables -A INPUT -p udp --dport 1900 -j DROP 2>/dev/null
	fi

	# Persist iptables rules if possible
	if command -v iptables-save >/dev/null 2>&1; then
		iptables-save > /etc/iptables.rules 2>/dev/null || true
	fi
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
		cat "${local_setup}templates/hostsTrackers.template" >>/etc/hosts
		_save_config denyhosts "yes"
		;;

	[nN] | [nN][Oo])
		echo "[ ${green}+  Allowing public trackers  +${normal} ]"
		_save_config denyhosts "no"
		;;
	esac
	echo
}

# Setup LShell configuration file
function _lshell() {
	#apt-get -y install lshell >> /dev/null 2>&1
	#cp ${local_setup}templates/lshell.conf.template /etc/lshell.conf
	cd /root || { printf -- "%s" "Unable to enter /root" && return 1; }
	git clone https://github.com/ghantoos/lshell.git lshell >>/dev/null 2>&1
	cd lshell || { printf -- "%s" "Unable to enter lshell" && return 1; }
	python3 setup.py install --no-compile --install-scripts=/usr/bin/ >>/dev/null 2>&1
	if [[ "${CODENAME}" == "focal" || "${CODENAME}" == "bionic" ]]; then
		\cp -f ${local_setup}templates/lshell.conf-focal.template /etc/lshell.conf
	else
		\cp -f ${local_setup}templates/lshell.conf.template /etc/lshell.conf
	fi
	echo "/usr/bin/lshell" >>/etc/shells
	groupadd lshell
	mkdir -p /var/log/lshell
	chown :lshell /var/log/lshell
	chmod 770 /var/log/lshell
}

# function to enable sudo for www-data function
function _apachesudo() {
	rm -f /etc/sudoers
	\cp -f ${local_setup}templates/sudoers.template /etc/sudoers
	#if [[ $sudoers == "yes" ]]; then
	awk -v username=${username} '/^root/ && !x {print username    " ALL=(ALL:ALL) NOPASSWD: ALL"; x=1} 1' /etc/sudoers >/tmp/sudoers
	mv /tmp/sudoers /etc
	echo -n "${username}" >/etc/apache2/master.txt
	#fi
	cd || exit 1
}

# function to configure apache
function _apacheconf() {
	\cp -f ${local_setup}templates/aliases-seedbox.conf.template /etc/apache2/sites-enabled/aliases-seedbox.conf
	sed -i "s/USERNAME/${username}/g" /etc/apache2/sites-enabled/aliases-seedbox.conf
	a2enmod auth_digest >>"${OUTTO}" 2>&1
	a2enmod ssl >>"${OUTTO}" 2>&1
	a2enmod scgi >>"${OUTTO}" 2>&1
	a2enmod rewrite >>"${OUTTO}" 2>&1
	a2enmod proxy >>"${OUTTO}" 2>&1
	a2enmod proxy_http >>"${OUTTO}" 2>&1
	a2enmod proxy_wstunnel >>"${OUTTO}" 2>&1
	if [[ -f /etc/apache2/sites-enabled/000-default.conf ]]; then
		mv /etc/apache2/sites-enabled/000-default.conf /etc/apache2/ >>"${OUTTO}" 2>&1
	fi
	\cp -f ${local_setup}templates/default-ssl.conf.template /etc/apache2/sites-enabled/default-ssl.conf
	sed -i "s/USERNAME/${username}/g" /etc/apache2/sites-enabled/default-ssl.conf
	sed -i "s/\"REALM\"/\"${REALM}\"/g" /etc/apache2/sites-enabled/default-ssl.conf
	sed -i "s/HTPASSWD/\/etc\/htpasswd/g" /etc/apache2/sites-enabled/default-ssl.conf
	sed -i "s/PORT/${PORT}/g" /etc/apache2/sites-enabled/default-ssl.conf
	sed -i "s/ServerTokens OS/ServerTokens Prod/g" /etc/apache2/conf-enabled/security.conf
	sed -i "s/ServerSignature On/ServerSignature Off/g" /etc/apache2/conf-enabled/security.conf
	\cp -f ${local_setup}templates/fileshare.conf.template /etc/apache2/sites-enabled/fileshare.conf
	sed -i.bak -e "s/post_max_size = 8M/post_max_size = 64M/" -e "s/upload_max_filesize = 2M/upload_max_filesize = 92M/" -e "s/expose_php = On/expose_php = Off/" -e "s/128M/768M/" -e "s/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/" -e "s/;opcache.enable=0/opcache.enable=1/" -e "s/;opcache.memory_consumption=64/opcache.memory_consumption=128/" -e "s/;opcache.max_accelerated_files=2000/opcache.max_accelerated_files=4000/" -e "s/;opcache.revalidate_freq=2/opcache.revalidate_freq=240/" /etc/php/"${PHP_VER}"/fpm/php.ini
	sed -i.bak -e "s/post_max_size = 8M/post_max_size = 64M/" -e "s/upload_max_filesize = 2M/upload_max_filesize = 92M/" -e "s/expose_php = On/expose_php = Off/" -e "s/memory_limit = 128M/memory_limit = 768M/" -e "s/;cgi.fix_pathinfo=1/cgi.fix_pathinfo=0/" -e "s/;opcache.enable=0/opcache.enable=1/" -e "s/;opcache.memory_consumption=64/opcache.memory_consumption=128/" -e "s/;opcache.max_accelerated_files=2000/opcache.max_accelerated_files=4000/" -e "s/;opcache.revalidate_freq=2/opcache.revalidate_freq=240/" /etc/php/"${PHP_VER}"/apache2/php.ini

	# ensure opcache module is activated
	phpenmod -v "${PHP_VER}" opcache >>"${OUTTO}" 2>&1

	# these modules are purely experimental
	#a2enmod proxy_fcgi >>"${OUTTO}" 2>&1
	#a2dismod mpm_prefork >>"${OUTTO}" 2>&1
	#a2enmod mpm_worker >>"${OUTTO}" 2>&1

	# ensure fastcgi module is activated
	a2enmod actions >>"${OUTTO}" 2>&1
	a2enmod headers >>"${OUTTO}" 2>&1
	a2enmod fastcgi >>"${OUTTO}" 2>&1
	a2enmod proxy_fcgi setenvif >>"${OUTTO}" 2>&1
	a2enconf php"${PHP_VER}"-fpm >>"${OUTTO}" 2>&1

	#sed -i 's/memory_limit = 128M/memory_limit = 768M/g' /etc/php/${PHP_VER}/apache2/php.ini
}

# function to fix cert
# add by EFS
function _fix_cert() {
	if [[ ! -f /etc/ssl/certs/ssl-cert-snakeoil.pem ]]; then
		openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/ssl/private/ssl-cert-snakeoil.key -out /etc/ssl/certs/ssl-cert-snakeoil.pem -subj "/C=CN/ST=BJ/L=PRC/O=IT/CN=www.example.com" >>"${OUTTO}" 2>&1
	fi
}
