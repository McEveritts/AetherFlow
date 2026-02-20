#!/bin/bash
# Module: 04-security.sh


# This function blocks an insecure port 1900 that may lead to
# DDoS masked attacks. Only remove this function if you absolutely
# need port 1900. In most cases, this is a junk port.
function _ssdpblock() {
	iptables -I INPUT 1 -p udp -m udp --dport 1900 -j DROP
}

# ban public trackers [iptables option] (11)
# shellcheck disable=2249,2162
function _denyhosts() {
	echo -ne "${bold}${yellow}Block Public Trackers?${normal}: [${green}y${normal}]es or [n]o: "
	read response
	case ${response} in
	[yY] | [yY][Ee][Ss] | "")

		echo "[ ${red}-  Blocking public trackers  -${normal} ]"
		\cp -f ${local_setup}templates/trackers.template /etc/trackers
		\cp -f ${local_setup}templates/denypublic.template /etc/cron.daily/denypublic
		chmod +x /etc/cron.daily/denypublic
		cat ${local_setup}templates/hostsTrackers.template >>/etc/hosts
		;;

	[nN] | [nN][Oo])
		echo "[ ${green}+  Allowing public trackers  +${normal} ]"
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
	python2 setup.py install --no-compile --install-scripts=/usr/bin/ >>/dev/null 2>&1
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
	mv /etc/apache2/sites-enabled/000-default.conf /etc/apache2/ >>"${OUTTO}" 2>&1
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
	if [[ ! -f /etc/ssl/certs/ssl-cert-snakeoila.pem ]]; then
		openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/ssl/private/ssl-cert-snakeoil.key -out /etc/ssl/certs/ssl-cert-snakeoil.pem -subj "/C=CN/ST=BJ/L=PRC/O=IT/CN=www.example.com" >>"${OUTTO}" 2>&1
	fi
}
