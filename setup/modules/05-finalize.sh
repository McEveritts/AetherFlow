#!/bin/bash
# Module: 05-finalize.sh


# function to configure pure-ftpd
function _ftpdconfig() {
	\cp -f ${local_setup}templates/openssl.cnf.template /root/.openssl.cnf

	#openssl req -config /root/.openssl.cnf -x509 -nodes -days 365 -newkey rsa:1024 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem >/dev/null 2>&1
	openssl req -config /root/.openssl.cnf -x509 -nodes -days 720 -newkey rsa:2048 -keyout /etc/ssl/private/vsftpd.pem -out /etc/ssl/private/vsftpd.pem >/dev/null 2>&1

	\cp -f ${local_setup}templates/vsftpd.conf.template /etc/vsftpd.conf

	# Enabling passive mode
	sed -i 's/^\(pasv_min_port=\).*/\110090/' /etc/vsftpd.conf
	sed -i 's/^\(pasv_max_port=\).*/\110100/' /etc/vsftpd.conf
	echo "pasv_address="${IP} >>/etc/vsftpd.conf
	/sbin/iptables -I INPUT -p tcp --destination-port 10090:10100 -j ACCEPT

	echo "" >/etc/vsftpd.chroot_list
}

# The following function makes necessary changes to Network and TZ settings needed for
# the proper functionality of the AetherFlow Dashboard.
function _quickstats() {
	# Dynamically adjust to use the servers active network adapter
	IFACE=$(ip route get 8.8.8.8 | awk 'NR==1 {print $5}')
	printf "${IFACE}" >/srv/dashboard/db/interface.txt
	sed -i "s/INETFACE/${IFACE}/g" /srv/dashboard/inc/config.php
	printf "${username}" >/srv/dashboard/db/master.txt
	# Use server timezone
	cd /usr/share/zoneinfo
	find ./* -type f -exec sh -c "diff -q /etc/localtime '{}' > /dev/null && echo {}" \; >~/tz.txt
	cd ~
	LOCALE=en_GB.UTF-8
	LANG=lang_en
	sed -i "s/LOCALE/${LOCALE}/g" /srv/dashboard/inc/localize.php
	sed -i "s/LANG/${LANG}/g" /srv/dashboard/inc/localize.php
	if [[ ${primaryroot} == "home" ]]; then
		cd /srv/dashboard/widgets && rm disk_data.php
		mv disk_datah.php disk_data.php
		chown -R www-data:www-data /srv/dashboard/widgets
	else
		rm /srv/dashboard/widgets/disk_datah.php
	fi
}

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
	#if [[ $cron == yes ]]; then
	#  touch /install/.cron.lock
	#  command1="*/1 * * * * /home/${username}/.startup >/dev/null 2>&1"
	#  cat <(fgrep -iv "${command1}" <(sh -c 'sudo -u ${username} crontab -l' >/dev/null 2>&1)) <(echo "${command1}") | sudo -u ${username} crontab -
	#elif [[ $cron == no ]]; then
	\cp -f ${local_setup}templates/sysd/rtorrent.template /etc/systemd/system/rtorrent@.service >/dev/null 2>&1
	\cp -f ${local_setup}templates/sysd/autodlirssi.template /etc/systemd/system/irssi@.service >/dev/null 2>&1
	\cp -f ${local_setup}templates/sysd/deluged.template /etc/systemd/system/deluged@.service >/dev/null 2>&1
	\cp -f ${local_setup}templates/sysd/deluge-web.template /etc/systemd/system/deluge-web@.service >/dev/null 2>&1
	systemctl enable {rtorrent,irssi,deluged,deluge-web}@${username} >/dev/null 2>&1
	systemctl start {rtorrent,irssi,deluged,deluge-web}@${username} >/dev/null 2>&1
	#fi

	echo "*/1 * * * * root bash /usr/local/bin/AetherFlow/system/set_interface" >/etc/cron.d/set_interface
	/usr/local/bin/AetherFlow/system/set_interface >/dev/null 2>&1
}

# function to set permissions on first user
function _perms() {
	chown -R ${username}.${username} /home/${username}/ >>"${OUTTO}" 2>&1
	sudo -u ${username} chmod 755 /home/${username}/ >>"${OUTTO}" 2>&1
	chmod +x /etc/cron.daily/denypublic >/dev/null 2>&1
	chmod 777 /home/${username}/.sessions >/dev/null 2>&1
	chown -R www-data:www-data /srv/dashboard >/dev/null 2>&1
	if [[ ${tr} == "yes" ]]; then
		chown -R ${username}:debian-transmission /home/${username}/torrents/transmission >/dev/null 2>&1
		service transmission-daemon reload >>"${OUTTO}" 2>&1
	fi
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
	echo -e " ${black}${on_green}    [AetherFlow] Seedbox & GUI Installation Completed    ${normal} "
	echo -e "        ${standout}    INSTALLATION COMPLETED in ${FIN}/min    ${normal}             "
	echo
	echo
	echo "  Valid Commands:  "
	echo '  -------------------'
	echo
	echo -e " ${green}createSeedboxUser${normal} - creates a shelled seedbox user"
	echo -e " ${green}deleteSeedboxUser${normal} - deletes a created seedbox user and their directories"
	echo -e " ${green}changeUserpass${normal} - change users SSH/FTP password"
	echo -e " ${green}setdisk${normal} - set your disk quota for any given user"
	echo -e " ${green}showspace${normal} - shows the amount of space used by all users on the server"
	echo -e " ${green}reload${normal} - restarts your seedbox services, i.e; rtorrent & irssi"
	echo -e " ${green}upgradeBTSync${normal} - upgrades BTSync when new version is available"
	echo -e " ${green}upgradeOmbi${normal} - upgrades Ombi when new version is available"
	echo -e " ${green}upgradePlex${normal} - upgrades Plex when new version is available"
	echo -e " ${green}box install letsencrypt${normal} - installs a valid SSL certificate to be used with "
	echo -e "                           a valid domain name. "
	echo -e " ${green}box${normal} - type 'box -h' for a summary of how to use box!"
	echo
	echo
	echo
	echo '################################################################################################'
	echo "#   Seedbox can be found at https://${username}:${passwd}@${ip} "
	echo "#   ${cyan}(Also works for FTP:5757/SSH:4747)${normal}"
	echo "#   If you need to restart rtorrent/irssi, you can type 'reload'"
	echo "#   https://${username}:${passwd}@${ip} (Also works for FTP:5757/SSH:4747)" >${username}.info
	echo "#   Reloading: ${green}sshd${normal}, ${green}apache${normal}, ${green}memcached${normal}, ${green}php${PHP_VER}${normal}, ${green}vsftpd${normal} and ${green}fail2ban${normal}"
	echo '################################################################################################'
	echo
	cat >/root/information.info <<EOF
  Seedbox can be found at https://${username}:${passwd}@${ip} (Also works for FTP:5757/SSH:4747)
  If you need to restart rtorrent/irssi, you can type 'reload'
  https://${username}:${passwd}@${ip} (Also works for FTP:5757/SSH:4747)
EOF
	rm -rf "$0" >>"${OUTTO}" 2>&1
	for i in ssh apache2 php"${PHP_VER}"-fpm vsftpd fail2ban quota memcached cron; do
		service "${i}" restart >>"${OUTTO}" 2>&1
		systemctl enable "${i}" >>"${OUTTO}" 2>&1
	done
	rm -rf /root/tmp/
	echo -ne "  Do you wish to reboot (recommended!): (Default ${green}Y${normal}) "
	read -r reboot_response
	case $reboot_response in
	[yY] | [yY][Ee][Ss] | "") systemctl reboot ;;
	[nN] | [nN][Oo]) echo "  ${cyan}Skipping reboot${normal} ... " ;;
	esac
}
