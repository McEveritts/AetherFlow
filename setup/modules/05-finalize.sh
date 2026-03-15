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

# The following function makes necessary changes to Network and TZ settings needed for
# the proper functionality of the AetherFlow Dashboard.
# NOTE: _quickstats function removed — legacy PHP dashboard sunset

# initializing console info
# shellcheck disable=2312
function _quickconsole() {
	PUBLICIP=$(ip route get 8.8.8.8 | awk 'NR==1 {print $7}')
	cat >/etc/profile<<EOF
echo " Welcome Back !"
echo "    * Dashboard:  https://${PUBLICIP}"
echo "    * Support:    https://plaza.AetherFlow.io"
echo "    * Donate:     https://AetherFlow.io/donate"
echo ""
EOF
	apt-get -y install shellinabox >>"${OUTTO}" 2>&1

	\cp -f ${local_setup}templates/sysd/shellinabox.template /etc/systemd/system/shellinabox.service
	\cp -f ${local_setup}templates/quickconsole/00_QuickConsole.css.template /etc/shellinabox/options-enabled/00_QuickConsole.css
	\cp -f ${local_setup}templates/web-console.conf.template /etc/apache2/sites-enabled/${username}.console.conf

	sed -i "s/PUBLICIP/${PUBLICIP}/g" /etc/apache2/sites-enabled/${username}.console.conf
	sed -i "s/USER/${username}/g" /etc/apache2/sites-enabled/${username}.console.conf

	chmod +x /etc/shellinabox/options-enabled/00_QuickConsole.css
	chmod 777 /etc/shellinabox/options-enabled/00_QuickConsole.css

	systemctl enable shellinabox.service >/dev/null 2>&1
	systemctl stop shellinabox.service >/dev/null 2>&1
	systemctl daemon-reload >/dev/null 2>&1
	systemctl start shellinabox.service >/dev/null 2>&1

}

# seedbox boot for first user
function _boot() {
	# Use safe overlay for all systemd unit files — preserves user modifications
	_safe_overlay_config "${local_setup}templates/sysd/rtorrent.template" \
		/etc/systemd/system/rtorrent@.service
	_safe_overlay_config "${local_setup}templates/sysd/autodlirssi.template" \
		/etc/systemd/system/irssi@.service
	_safe_overlay_config "${local_setup}templates/sysd/deluged.template" \
		/etc/systemd/system/deluged@.service
	_safe_overlay_config "${local_setup}templates/sysd/deluge-web.template" \
		/etc/systemd/system/deluge-web@.service
	_safe_overlay_config "${local_setup}templates/sysd/aetherflow-heal.service" \
		/etc/systemd/system/aetherflow-heal.service
	_safe_overlay_config "${local_setup}templates/sysd/aetherflow-heal.timer" \
		/etc/systemd/system/aetherflow-heal.timer

	# Install Next.js and Go API systemd service files
	_safe_overlay_config "${local_setup}templates/sysd/aetherflow-api.template" \
		/etc/systemd/system/aetherflow-api.service
	_safe_overlay_config "${local_setup}templates/sysd/aetherflow-frontend.template" \
		/etc/systemd/system/aetherflow-frontend.service

	systemctl daemon-reload >/dev/null 2>&1
	systemctl enable {rtorrent,irssi,deluged,deluge-web}@${username} >/dev/null 2>&1
	systemctl start {rtorrent,irssi,deluged,deluge-web}@${username} >/dev/null 2>&1
	systemctl enable --now aetherflow-heal.timer >/dev/null 2>&1 || true

	# Enable (but don't start) the modern stack services — they're managed by PM2
	# during initial install, but the units are available for manual switchover.
	systemctl enable aetherflow-api.service >/dev/null 2>&1 || true
	systemctl enable aetherflow-frontend.service >/dev/null 2>&1 || true

	echo "*/1 * * * * root bash /usr/local/bin/AetherFlow/system/set_interface" >/etc/cron.d/set_interface
	/usr/local/bin/AetherFlow/system/set_interface >/dev/null 2>&1
}

# function to set permissions on first user
function _perms() {
	chown -R ${username}.${username} /home/${username}/ >>"${OUTTO}" 2>&1
	sudo -u ${username} chmod 755 /home/${username}/ >>"${OUTTO}" 2>&1
	chmod +x /etc/cron.daily/denypublic >/dev/null 2>&1
	# Tightened from 777 → 770 (owner + group only, no world access)
	chmod 770 /home/${username}/.sessions >/dev/null 2>&1
	if [[ ${tr} == "yes" ]]; then
		chown -R ${username}:debian-transmission /home/${username}/torrents/transmission >/dev/null 2>&1
		service transmission-daemon reload >>"${OUTTO}" 2>&1
	fi
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
}

# Comprehensive permission hardening across /opt/AetherFlow
_harden_permissions() {
	local af_root="/opt/AetherFlow"

	# Ensure the service user exists
	_ensure_aetherflow_user

	# Ownership: aetherflow:aetherflow for the entire tree
	if [[ -d "${af_root}" ]]; then
		chown -R aetherflow:aetherflow "${af_root}" >>"${OUTTO}" 2>&1

		# Directories: 755 (rwxr-xr-x)
		find "${af_root}" -type d -exec chmod 755 {} + >>"${OUTTO}" 2>&1

		# Regular files: 644 (rw-r--r--)
		find "${af_root}" -type f -exec chmod 644 {} + >>"${OUTTO}" 2>&1

		# Executables: restore execute permission on known binaries
		if [[ -f "${af_root}/backend/aetherflow-api" ]]; then
			chmod 755 "${af_root}/backend/aetherflow-api"
		fi

		# Node binaries in node_modules/.bin need execute
		if [[ -d "${af_root}/frontend/node_modules/.bin" ]]; then
			find "${af_root}/frontend/node_modules/.bin" -type f -exec chmod 755 {} + 2>/dev/null || true
			find "${af_root}/frontend/node_modules/.bin" -type l -exec chmod 755 {} + 2>/dev/null || true
		fi

		# Shell scripts in setup need execute
		if [[ -d "${af_root}/setup" ]]; then
			find "${af_root}/setup" -name "*.sh" -type f -exec chmod 755 {} + 2>/dev/null || true
			if [[ -f "${af_root}/setup/AetherFlow-Setup" ]]; then
				chmod 755 "${af_root}/setup/AetherFlow-Setup"
			fi
		fi

		# Database directory: writable by the service user
		if [[ -d "${af_root}/dashboard/db" ]]; then
			chmod 750 "${af_root}/dashboard/db"
		fi

		# Remove any world-writable files
		find "${af_root}" -perm -002 -type f -exec chmod o-w {} + 2>/dev/null || true
		find "${af_root}" -perm -002 -type d -exec chmod o-w {} + 2>/dev/null || true
	fi

	echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✓ Permission hardening complete for ${af_root}" >> "${INSTALL_LOG}"
}

# Post-check: warn if any AetherFlow services are running as root
_validate_no_root_services() {
	local warnings=0

	# Check PM2 processes
	if command -v pm2 >/dev/null 2>&1; then
		local pm2_root_procs
		pm2_root_procs="$(pm2 jlist 2>/dev/null | grep -o '"pm_exec_path":"[^"]*aetherflow[^"]*"' | head -5)" || true
		if [[ -n "${pm2_root_procs}" ]] && [[ "$(whoami)" == "root" ]]; then
			echo ""
			echo -e "[ ${yellow:-\033[33m}WARN${normal:-\033[0m} ] AetherFlow PM2 processes are running as root."
			echo "         Consider switching to systemd units (aetherflow-api.service,"
			echo "         aetherflow-frontend.service) which run as the 'aetherflow' user."
			echo ""
			echo "[$(date '+%Y-%m-%d %H:%M:%S')] ⚠ WARNING: PM2 AetherFlow processes running as root" >> "${INSTALL_LOG}"
			((warnings++))
		fi
	fi

	# Check systemd units if active
	for unit in aetherflow-api.service aetherflow-frontend.service; do
		if systemctl is-active "${unit}" >/dev/null 2>&1; then
			local exec_user
			exec_user="$(systemctl show -p MainPID "${unit}" --value 2>/dev/null)"
			if [[ -n "${exec_user}" ]] && [[ "${exec_user}" != "0" ]]; then
				local running_user
				running_user="$(ps -o user= -p "${exec_user}" 2>/dev/null)" || true
				if [[ "${running_user}" == "root" ]]; then
					echo -e "[ ${yellow:-\033[33m}WARN${normal:-\033[0m} ] ${unit} is running as root!"
					echo "[$(date '+%Y-%m-%d %H:%M:%S')] ⚠ WARNING: ${unit} running as root" >> "${INSTALL_LOG}"
					((warnings++))
				fi
			fi
		fi
	done

	if [[ ${warnings} -eq 0 ]]; then
		echo "[$(date '+%Y-%m-%d %H:%M:%S')] ✓ No AetherFlow services running as root" >> "${INSTALL_LOG}"
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
	echo -e " │ 👉 ${bold}${magenta}http://${ip}:3000${normal}                              │"
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
	
	cat >/root/information.info <<EOF
AetherFlow Seedbox Initialized successfully.
Dashboard Onboarding: http://${ip}:3000
Admin Username: ${username}
Admin Password: ${passwd}
EOF
	rm -rf "$0" >>"${OUTTO}" 2>&1
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
