#!/bin/bash
# Module: 03-services.sh


# xmlrpc-c function
function _xmlrpc() {
	mkdir -p /tmp && cd /tmp || exit 1
	if [[ -d /tmp/xmlrpc-c ]]; then rm -rf /tmp/xmlrpc-c; fi
	\cp -rf ${local_setup}sources/xmlrpc-c_1-39-13/ .
	cd xmlrpc-c_1-39-13 || exit 1
	chmod +x configure
	./configure --prefix=/usr --disable-cplusplus >>"${OUTTO}" 2>&1
	make >>"${OUTTO}" 2>&1
	chmod +x install-sh
	make install >>"${OUTTO}" 2>&1
}

# libtorrent function
# modify by EFS thanks to asuna's patch
# apt rtorrent handles the libtorrent install
# remember this is temporary until patched
function _libtorrent() {
	mkdir -p /tmp && cd /tmp || exit 1
	MAXCPUS=$(echo "$(nproc) / 2" | bc)
	rm -rf xmlrpc-c* >>"${OUTTO}" 2>&1
	if [[ -e /tmp/libtorrent-${LTORRENT}.tar.gz ]]; then rm -rf libtorrent-"${LTORRENT}".tar.gz; fi
	mkdir -p /tmp/libtorrent
	\cp -f ${local_setup}sources/libtorrent-"${LTORRENT}".tar.gz .
	tar -xvf "libtorrent-${LTORRENT}.tar.gz" -C /tmp/libtorrent --strip-components=1 >>"${OUTTO}" 2>&1
	cd libtorrent || exit 1
	./autogen.sh >>"${OUTTO}" 2>&1
	if [[ ${LTORRENT} == "0.13.4" ]]; then
		\cp -f ${local_setup}sources/libtorrent-0.13.4-tar.patch .
		patch -p1 <libtorrent-*-tar.patch >>"${OUTTO}" 2>&1
		# Check for custom OpenSSL 1.0.2p, otherwise use system
		if [[ -d "/root/openssl-1.0.2p" ]]; then
			./configure --disable-debug --prefix=/usr OPENSSL_LIBS="-L/root/openssl-1.0.2p -lssl -lcrypto" OPENSSL_CFLAGS="-I/root/openssl-1.0.2p/include" --enable-ipv6 >>"${OUTTO}" 2>&1
		else
			echo "Custom OpenSSL not found, attempting build with system OpenSSL..." >>"${OUTTO}" 2>&1
			./configure --disable-debug --prefix=/usr --enable-ipv6 >>"${OUTTO}" 2>&1
		fi
	elif [[ ${LTORRENT} == "0.13.6" ]]; then
		./configure --disable-debug --prefix=/usr --enable-ipv6 >>"${OUTTO}" 2>&1
	elif [[ ${LTORRENT} == "0.13.7" ]]; then
		\cp -f ${local_setup}sources/libtorrent-0.13.7-tar.patch .
		patch -p1 <libtorrent-*-tar.patch >>"${OUTTO}" 2>&1
		./configure --disable-debug --prefix=/usr >>"${OUTTO}" 2>&1
	else
		./configure --disable-debug --prefix=/usr >>"${OUTTO}" 2>&1
	fi
	make -j${MAXCPUS} >>"${OUTTO}" 2>&1
	make install >>"${OUTTO}" 2>&1
}

# rtorrent function
# commenting until patch comes for comp/build
# using apt install rtorrent in the meantime
# shellcheck disable=2215,2312,2250
function _rtorrent() {
	mkdir -p /tmp && cd /tmp || exit 1
	MAXCPUS=$(echo "$(nproc) / 2" | bc)
	rm -rf libtorrent* >>"${OUTTO}" 2>&1
	if [[ -e /tmp/libtorrent-${LTORRENT}.tar.gz ]]; then rm -rf /tmp/libtorrent-${LTORRENT}.tar.gz; fi
	mkdir -p /tmp/rtorrent
	\cp -f ${local_setup}sources/rtorrent-"${RTVERSION}".tar.gz .
	tar -xzvf rtorrent-"${RTVERSION}".tar.gz >>"${OUTTO}" 2>&1
	cd "rtorrent-${RTVERSION}" || exit 1
	./autogen.sh >>"${OUTTO}" 2>&1
	if [[ ${RTVERSION} == "0.9.4" ]]; then
		\cp -f ${local_setup}sources/rtorrent-0.9.4-tar.patch .
		patch -p1 <rtorrent-*-tar.patch >>"${OUTTO}" 2>&1
		./configure --disable-debug --prefix=/usr --with-xmlrpc-c --enable-ipv6 >>"${OUTTO}" 2>&1
	elif [[ ${RTVERSION} == "0.9.6" ]] || [[ ${RTVERSION} == "0.9.7" ]]; then
		./configure --disable-debug --prefix=/usr --with-xmlrpc-c --enable-ipv6 >>"${OUTTO}" 2>&1
	else
		./configure --disable-debug --prefix=/usr --with-xmlrpc-c >>"${OUTTO}" 2>&1
	fi
	make -j${MAXCPUS} >>"${OUTTO}" 2>&1
	make install >>"${OUTTO}" 2>&1
	cd /tmp || exit 1
	ldconfig >>"${OUTTO}" 2>&1
	rm -rf /tmp/rtorrent-"${RTVERSION}"* >>"${OUTTO}" 2>&1
	touch /install/.rtorrent.lock
}

# deluge function
# shellcheck disable=2215,2312,2250
function _deluge() {
	if [[ ${DELUGE} == REPO ]]; then
		apt-get -q -y update >>"${OUTTO}" 2>&1
		apt-get -q -y install deluged deluge-web >>"${OUTTO}" 2>&1
		systemctl stop deluged
		update-rc.d deluged remove
		rm /etc/init.d/deluged
	elif [[ ${DELUGE} == "1.0.11" ]] || [[ ${DELUGE} == "1.1.3" ]]; then
		if [[ ${DELUGE} == "1.0.11" ]]; then
			LTRC=RC_1_0
		elif [[ ${DELUGE} == "1.1.3" ]]; then
			LTRC=RC_1_1
		fi
		apt-get -qy update >/dev/null 2>&1
		LIST='build-essential checkinstall libgeoip-dev 
  python python-twisted python-openssl python-setuptools intltool python-xdg python-chardet geoip-database python-notify python-pygame
  python-glade2 librsvg2-common xdg-utils python-mako'
		for depend in ${LIST}; do
			apt-get -qq -y install "${depend}" >>"${OUTTO}" 2>&1
		done
		LIST='libboost-dev libboost-system-dev libboost-chrono-dev libboost-random-dev libboost-python-dev'
		for depend in ${LIST}; do
			apt-get -qq -y install "${depend}" >>"${OUTTO}" 2>&1
		done
		function version_qb() { test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1"; }
		if [[ ${QBVERSION} != "no" ]] && (version_qb "${QBVERSION}" 4.1.3); then
			LTRC=RC_1_1
		fi
		cd "${local_packages}" || exit 1
		git clone -b "${LTRC}" https://github.com/arvidn/libtorrent.git >>"${OUTTO}" 2>&1
		cd libtorrent || exit 1
		\cp -rf ${local_setup}sources/libtorrent-rasterbar-"${LTRC}".patch .
		patch -p1 <libtorrent-rasterbar-"${LTRC}".patch >>"${OUTTO}" 2>&1
		ltversion=$(cat configure.ac | grep -Eo "AC_INIT\(\[libtorrent-rasterbar\],.*" | grep -Eo "[0-9.]+" | head -n1)
		./autotool.sh >>"${OUTTO}" 2>&1
		./configure --enable-python-binding --disable-debug --enable-encryption --with-libgeoip=system --with-libiconv CXXFLAGS=-std=c++11 >>"${OUTTO}" 2>&1
		make -j$(nproc) >>"${OUTTO}" 2>&1
		checkinstall -y --pkgversion=${ltversion} >>"${OUTTO}" 2>&1
		ldconfig
		cd ..
		wget -q http://download.deluge-torrent.org/source/deluge-1.3.15.tar.gz
		tar -zxvf deluge-1.3.15.tar.gz >>"${OUTTO}" 2>&1
		cd deluge-1.3.15 || exit 1
		python setup.py build >>"${OUTTO}" 2>&1
		python setup.py install --install-layout=deb >>"${OUTTO}" 2>&1
		python setup.py install_data >>"${OUTTO}" 2>&1
		cd ..
		rm -r {deluge-1.3.15,libtorrent}
		rm -rf deluge-1.3.15.tar.gz
	fi
	n=$RANDOM
	DPORT=$((n % 59000 + 10024))
	DWSALT=$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
	DWP=$(python3 ${local_packages}/system/deluge.Userpass.py ${passwd} ${DWSALT})
	DUDID=$(python3 ${local_packages}/system/deluge.addHost.py)
	# -- Secondary awk command -- #
	#DPORT=$(awk -v min=59000 -v max=69024 'BEGIN{srand(); print int(min+rand()*(max-min+1))}')
	DWPORT=$(shuf -i 10001-11000 -n 1)
	mkdir -p /home/${username}/.config/deluge/plugins
	if [[ ! -f /home/${username}/.config/deluge/plugins/ltConfig-0.2.5.0-py2.7.egg ]]; then
		cd /home/${username}/.config/deluge/plugins/
		wget -q https://github.com/ratanakvlun/deluge-ltconfig/releases/download/v0.3.1/ltConfig-0.3.1-py2.7.egg
		wget -q https://bitbucket.org/bendikro/deluge-yarss-plugin/downloads/YaRSS2-1.4.3-py2.7.egg
	fi
	chmod 755 /home/${username}/.config
	chmod 755 /home/${username}/.config/deluge
	\cp -f ${local_setup}templates/core.conf.template /home/${username}/.config/deluge/core.conf
	\cp -f ${local_setup}templates/web.conf.template /home/${username}/.config/deluge/web.conf
	\cp -f ${local_setup}templates/hostlist.conf.1.2.template /home/${username}/.config/deluge/hostlist.conf.1.2
	\cp -f ${local_setup}templates/ltconfig.conf.template /home/${username}/.config/deluge/ltconfig.conf
	sed -i "s/USERNAME/${username}/g" /home/${username}/.config/deluge/core.conf
	sed -i "s/DPORT/${DPORT}/g" /home/${username}/.config/deluge/core.conf
	sed -i "s/XX/${ip}/g" /home/${username}/.config/deluge/core.conf
	sed -i "s/DWPORT/${DWPORT}/g" /home/${username}/.config/deluge/web.conf
	sed -i "s/DWSALT/${DWSALT}/g" /home/${username}/.config/deluge/web.conf
	sed -i "s/DWP/${DWP}/g" /home/${username}/.config/deluge/web.conf
	sed -i "s/DUDID/${DUDID}/g" /home/${username}/.config/deluge/hostlist.conf.1.2
	sed -i "s/DPORT/${DPORT}/g" /home/${username}/.config/deluge/hostlist.conf.1.2
	sed -i "s/USERNAME/${username}/g" /home/${username}/.config/deluge/hostlist.conf.1.2
	sed -i "s/PASSWD/${passwd}/g" /home/${username}/.config/deluge/hostlist.conf.1.2
	echo "${username}:${passwd}:10" >/home/${username}/.config/deluge/auth
	chmod 600 /home/${username}/.config/deluge/auth
	chown -R ${username}.${username} /home/${username}/.config/
	mkdir -p /home/${username}/dwatch
	chown ${username}: /home/${username}/dwatch
	mkdir -p /home/${username}/torrents/deluge
	chown ${username}: /home/${username}/torrents/deluge
}

# shellcheck disable=2312
function _insdwApache() {
	APPNAME='deluge'
	APPDPORT=$(cat /home/${username}/.config/deluge/web.conf | grep -E ".*port.*" | grep -Eo "[0-9]+")
	cat >/etc/apache2/sites-enabled/deluge.conf <<DELCONF
ProxyPass /${APPNAME} http://localhost:${APPDPORT}/

<Location /${APPNAME}>
	ProxyPassReverse /
	ProxyPassReverseCookiePath / /${APPNAME}
	RequestHeader set X-Deluge-Base "/${APPNAME}/"
	Order allow,deny
	Allow from all
</Location>
DELCONF
	touch /install/.deluge.lock
	chown www-data: /etc/apache2/sites-enabled/deluge.conf
}

# Transmission function
# shellcheck disable=2024
function _insTr() {
	sudo add-apt-repository -y ppa:transmissionbt/ppa >>"${OUTTO}" 2>&1
	apt-get -q -y update >>"${OUTTO}" 2>&1
	apt-get -q -y install transmission-daemon >>"${OUTTO}" 2>&1
	systemctl stop transmission-daemon >>"${OUTTO}" 2>&1
	systemctl disable transmission-daemon >>"${OUTTO}" 2>&1
	mkdir -p /home/${username}/.config/transmission/blocklists >/dev/null 2>&1
	mkdir -p /home/${username}/.config/transmission/resume >/dev/null 2>&1
	mkdir -p /home/${username}/.config/transmission/torrents >/dev/null 2>&1
	mkdir -p /home/${username}/torrents/transmission >/dev/null 2>&1
	\cp -f ${local_setup}templates/transmission.json.template /home/${username}/.config/transmission/settings.json
	sed -i "s/\/var\/lib\/transmission-daemon\/downloads/\/home\/${username}\/torrents\/transmission/g" /home/${username}/.config/transmission/settings.json
	sed -i "s/\/var\/lib\/transmission-daemon\/Downloads/\/home\/${username}\/torrents\/transmission\/incomplete/g" /home/${username}/.config/transmission/settings.json
	sed -i "s/\/var\/lib\/transmission-daemon\/trwatch/\/home\/${username}\/trwatch/g" /home/${username}/.config/transmission/settings.json
	sed -i "s/\"{.*/\"${passwd}\", /g" /home/${username}/.config/transmission/settings.json
	sed -i "s/\"transmission\",/\"${username}\",/g" /home/${username}/.config/transmission/settings.json
	mkdir -p /home/${username}/torrents/transmission
	mkdir -p /home/${username}/trwatch
	chmod -R 755 /home/${username}/.config
	chown -R ${username}.${username} /home/${username}/.config/
	chmod -R 755 /home/${username}/torrents/transmission
	chown -R ${username}.${username} /home/${username}/torrents/transmission
	chmod -R 755 /home/${username}/trwatch
	chown -R ${username}.${username} /home/${username}/trwatch
}

# shellcheck disable=2120,2312
function _insTrWeb() {
	#!/bin/sh
	ROOT_FOLDER="$1"
	WEB_FOLDER=""
	ORG_INDEX_FILE="index.original.html"
	INDEX_FILE="index.html"
	TMP_FOLDER="/tmp/tr-web-control"
	PACK_NAME="src.tar.gz"
	WEB_HOST="https://github.com/ronggang/twc-release/raw/master/"
	DOWNLOAD_URL="${WEB_HOST}${PACK_NAME}"
	INSTALL_TYPE=-1

	main() {
		if [[ ! -d "${TMP_FOLDER}" ]]; then
			mkdir -p "${TMP_FOLDER}"
		fi

		if [[ -d "${ROOT_FOLDER}" ]]; then
			echo "use arg: ${ROOT_FOLDER}" >>"${OUTTO}" 2>&1
			INSTALL_TYPE=3
			WEB_FOLDER="${ROOT_FOLDER}/web"
		else
			findWebFolder
		fi
		install
		clear
	}

	findWebFolder() {
		echo "Searching Transmission Web Folder..." >>"${OUTTO}" 2>&1
		ROOT_FOLDER="/usr/local/transmission/share/transmission"
		if [[ -f /etc/fedora-release ]] || [[ -f "/etc/debian_version" ]]; then
			ROOT_FOLDER="/usr/share/transmission"
		fi

		if [[ -n "${TRANSMISSION_WEB_HOME}" ]]; then
			echo "use TRANSMISSION_WEB_HOME: ${TRANSMISSION_WEB_HOME}" >>"${OUTTO}" 2>&1
			if [[ ! -d "${TRANSMISSION_WEB_HOME}" ]]; then
				mkdir -p "${TRANSMISSION_WEB_HOME}"
			fi
			INSTALL_TYPE=2
		else
			echo "Looking for folder: ${ROOT_FOLDER}/web" >>"${OUTTO}" 2>&1
			if [[ -d "${ROOT_FOLDER}/web" ]]; then
				WEB_FOLDER="${ROOT_FOLDER}/web"
				INSTALL_TYPE=1
				echo "Folder found. Using it." >>"${OUTTO}" 2>&1
			else
				echo "Folder not found. Will search the entire /. This will take a while..." >>"${OUTTO}" 2>&1
				ROOT_FOLDER=$(find / -name 'web' -type d 2>/dev/null | grep 'transmission/web' | sed 's/\/web$//g')

				if [[ -d "${ROOT_FOLDER}/web" ]]; then
					WEB_FOLDER="${ROOT_FOLDER}/web"
					INSTALL_TYPE=1
				fi
			fi
		fi
	}

	install() {
		if [[ ${INSTALL_TYPE} = 1 || ${INSTALL_TYPE} = 3 ]]; then
			download
			echo "Installing..." >>"${OUTTO}" 2>&1
			mkdir -p web
			tar -xzf "${PACK_NAME}" -C "web" >>"${OUTTO}" 2>&1
			if [[ ! -f "${WEB_FOLDER}/${ORG_INDEX_FILE}" ]]; then
				mv "${WEB_FOLDER}/${INDEX_FILE}" "${WEB_FOLDER}/${ORG_INDEX_FILE}"
			fi
			\cp -rf web "${ROOT_FOLDER}"

			find "${ROOT_FOLDER}" -type d -exec chmod o+rx {} \;
			find "${ROOT_FOLDER}" -type f -exec chmod o+r {} \;

			installed
		elif [[ ${INSTALL_TYPE} = 2 ]]; then
			download
			echo "Installing..." >>"${OUTTO}" 2>&1
			tar -xzf "${PACK_NAME}" -C "${TRANSMISSION_WEB_HOME}"

			find "${TRANSMISSION_WEB_HOME}" -type d -exec chmod o+rx {} \;
			find "${TRANSMISSION_WEB_HOME}" -type f -exec chmod o+r {} \;

			installed
		else
			#echo "##############################################"
			#echo "#"
			echo "# ERROR : Transmisson WEB UI Folder is missing." >>"${OUTTO}" 2>&1
		#echo "#"
		#echo "##############################################"
		fi
	}

	download() {
		cd "${TMP_FOLDER}"
		echo "Downloading Transmission Web Control..." >>"${OUTTO}" 2>&1
		wget -q "${DOWNLOAD_URL}" --no-check-certificate
	}

	installed() {
		echo "Transmission Web Control Installation completed!" >>"${OUTTO}" 2>&1
	}

	clear() {
		rm -f "${PACK_NAME}"
		rm -rf "${TMP_FOLDER}"
	}

	main

	rm -rf "${tmpFolder}"
	#touch /install/.transmission.lock
	#cd ${local_dashboard}/custom
	#patch -p1 < ${local_setup}templates/tr-php.patch >>"${OUTTO}" 2>&1
}

function _insTrApache() {
	APPNAME='transmission'
	APPDPORT='9091'
	cat >/etc/apache2/sites-enabled/transmission.conf <<EOF
<Location /${APPNAME}>
ProxyPass http://localhost:${APPDPORT}/${APPNAME}
ProxyPassReverse http://localhost:${APPDPORT}/${APPNAME}
</Location>
EOF
	touch /install/.transmission.lock
	chown www-data: /etc/apache2/sites-enabled/transmission.conf
	cat >/usr/share/transmission/web/.htaccess <<EOF
allow from all
EOF
	\cp -f ${local_setup}templates/sysd/transmission.template /etc/systemd/system/transmission@.service >/dev/null 2>&1
	systemctl enable transmission@${username} >/dev/null 2>&1
	systemctl start transmission@${username} >/dev/null 2>&1
}

# qBittorrent function
# shellcheck disable=2312
function _qbittorrent() {
	apt-get -qy update >>"${OUTTO}" 2>&1
	LIST='build-essential checkinstall pkg-config libgl1-mesa-dev libjpeg-dev libpng-dev automake libtool libgeoip-dev python3-dev python3-pip'
	for depend in ${LIST}; do
		apt-get -qq -y install "${depend}" >>"${OUTTO}" 2>&1
	done
	LIST='libboost-dev libboost-system-dev libboost-chrono-dev libboost-random-dev libboost-python-dev'
	for depend in ${LIST}; do
		apt-get -qq -y install "${depend}" >>"${OUTTO}" 2>&1
	done
	cd ${local_packages} || exit 1
	if [[ ! -e /usr/local/lib/libtorrent-rasterbar.so ]]; then
		function version_qb() { test "$(echo "$@" | tr " " "\n" | sort -V | head -n 1)" != "$1"; }
		if [[ ${QBVERSION} != "no" ]] && (version_qb "${QBVERSION}" 4.1.3); then
			LTRC=RC_1_1
		fi
		git clone -b "${LTRC}" https://github.com/arvidn/libtorrent.git >>"${OUTTO}" 2>&1
		cd libtorrent || exit 1
		\cp -f ${local_setup}sources/libtorrent-rasterbar-"${LTRC}".patch .
		patch -p1 <libtorrent-rasterbar-"${LTRC}".patch >>"${OUTTO}" 2>&1
		ltversion=$(cat configure.ac | grep -Eo "AC_INIT\(\[libtorrent-rasterbar\],.*" | grep -Eo "[0-9.]+" | head -n1)
		./autotool.sh >>"${OUTTO}" 2>&1
		./configure --enable-python-binding --disable-debug --enable-encryption --with-libgeoip=system --with-libiconv CXXFLAGS=-std=c++11 >>"${OUTTO}" 2>&1
		make -j$(nproc) >>"${OUTTO}" 2>&1
		checkinstall -y --pkgversion=${ltversion} >>"${OUTTO}" 2>&1
	fi
	ldconfig >>"${OUTTO}" 2>&1
	apt-get -qy update >>"${OUTTO}" 2>&1
	LIST='qtbase5-dev qttools5-dev-tools libqt5svg5-dev'
	for depend in ${LIST}; do
		apt-get -qq -y install "${depend}" >>"${OUTTO}" 2>&1
	done
	cd ${local_packages} || exit 1
	git clone https://github.com/qbittorrent/qBittorrent >>"${OUTTO}" 2>&1
	cd qBittorrent || exit 1
	git checkout release-"${QBVERSION}" >>"${OUTTO}" 2>&1
	./configure --disable-gui --disable-debug >>"${OUTTO}" 2>&1
	make -j$(nproc) >>"${OUTTO}" 2>&1
	checkinstall -y --pkgname=qbittorrent-headless --pkgversion="${QBVERSION}" --pkggroup qbittorrent >>"${OUTTO}" 2>&1
	export LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}
	if [[ ! -d /home/${username}/.config/qBittorrent ]]; then
		mkdir -p /home/${username}/.config/qBittorrent
	fi
	chmod -R 755 /home/${username}/.config
	chown -R ${username}.${username} /home/${username}/.config/
	\cp -f ${local_setup}templates/sysd/qbittorrent.template /etc/systemd/system/qbittorrent@.service >/dev/null 2>&1
	if [[ ! -d /home/${username}/.config/qBittorrent ]]; then
		mkdir -p /home/${username}/.config/qBittorrent
	fi
	\cp -f ${local_setup}templates/qBittorrent.conf.template /home/${username}/.config/qBittorrent/qBittorrent.conf
	sed -i "s/admin/${username}/g" /home/${username}/.config/qBittorrent/qBittorrent.conf
	sed -i "s/5ebe2294ecd0e0f08eab7690d2a6ee69/${ha1pass}/g" /home/${username}/.config/qBittorrent/qBittorrent.conf
	sed -i "s/mySavePath/\/home\/${username}\/torrents\/qbittorrent/g" /home/${username}/.config/qBittorrent/qBittorrent.conf
	chmod -R 755 /home/${username}/.config/
	chown -R ${username}.${username} /home/${username}/.config/
	mkdir -p /home/${username}/torrents/qbittorrent
	chown ${username}: /home/${username}/torrents/qbittorrent
	systemctl enable qbittorrent@${username} >/dev/null 2>&1
	systemctl start qbittorrent@${username} >/dev/null 2>&1
	cd ${local_packages} || exit 1
	rm -rf qBittorrent
}

function _insqBApache() {
	APPNAME='qbittorrent'
	APPDPORT='8086'
	cat >/etc/apache2/sites-enabled/qbittorrent.conf <<EOF
<Location /${APPNAME}>
ProxyPass http://localhost:${APPDPORT}
ProxyPassReverse http://localhost:${APPDPORT}
Require all granted
</Location>
EOF
	touch /install/.qbittorrent.lock
	chown www-data: /etc/apache2/sites-enabled/qbittorrent.conf
}

# scgi enable function (22-nixed)
# function _scgi() { ln -s /etc/apache2/mods-available/scgi.load /etc/apache2/mods-enabled/scgi.load >>"${OUTTO}" 2>&1 ; }

# mktorrent function
function _mktorrent() {
	if [[ -d /tmp ]]; then rm -r tmp; fi
	mkdir -p /tmp && cd /tmp || exit 1
	mktorrent_version=1.1
	wget --quiet https://github.com/Rudde/mktorrent/archive/v"${mktorrent_version}".zip -O mktorrent.zip >>"${OUTTO}" 2>&1
	unzip -o mktorrent.zip >>"${OUTTO}" 2>&1
	cd mktorrent-1.1 || exit 1
	make >>"${OUTTO}" 2>&1
	make install >>"${OUTTO}" 2>&1
	cd ..
	rm -rf mktorrent-1.1 && rm -f mktorrent.zip
}

# function to install rutorrent
function _rutorrent() {
	cd /srv
	if [[ -d /srv/rutorrent ]]; then rm -rf rutorrent; fi
	mkdir -p rutorrent
	\cp -rf ${local_rutorrent}/. rutorrent
}

function _rutorrent-plugins() {
	cd /srv/rutorrent
	if [[ -d /srv/rutorrent/plugins ]]; then rm -rf plugins; fi
	mkdir -p plugins
	\cp -rf ${local_rplugins}/. plugins
	apt-get install -y sox libsox-fmt-mp3 >>"${OUTTO}" 2>&1
}

# function to install dashboard
function _dashboard() {
	cd && mkdir -p /srv/rutorrent/home
	\cp -rf ${local_dashboard}. /srv/rutorrent/home
	touch /srv/rutorrent/home/db/output.log
	touch /srv/rutorrent/home/db/."${dash_theme}".lock
}

# function to install _h5ai file indexer
function _fileindexer() {
	cd /srv/rutorrent/home
	wget --quiet https://release.larsjung.de/h5ai/h5ai-0.29.0.zip >>"${OUTTO}" 2>&1
	unzip h5ai-0.29.0.zip >>"${OUTTO}" 2>&1
	rm -rf h5ai-0.29.0.zip >>"${OUTTO}" 2>&1
	chmod 775 -R _h5ai/private/cache && chmod 775 -R _h5ai/public/cache
	apt -y install imagemagick >>"${OUTTO}" 2>&1
	echo "#DirectoryIndex index.html index.php /_h5ai/public/index.php" >>/etc/apache2/apache2.conf
	ln -s /home/${username}/torrents/rtorrent/ ${username}.rtorrent.downloads
	if [[ ${DELUGE} != NO ]]; then
		ln -s /home/${username}/torrents/deluge/ ${username}.deluge.downloads
	fi
	if [[ ${tr} == "yes" ]]; then
		ln -s /home/${username}/torrents/transmission/ ${username}.transmission.downloads
	fi
	if [[ ${QBVERSION} != "no" ]]; then
		ln -s /home/${username}/torrents/qbittorrent/ ${username}.qbittorrent.downloads
	fi
}

# function to configure first user config
function _rconf() {
	if [[ ${RTVERSION} == 0.9.7 ]]; then
		\cp -f ${local_setup}templates/rtorrent.rc.new.template /home/${username}/.rtorrent.rc
	else
		\cp -f ${local_setup}templates/rtorrent.rc.template /home/${username}/.rtorrent.rc
	fi
	mkdir -p /home/${username}/torrents/rtorrent
	chown -R ${username}: /home/${username}/torrents
	sed -i "s/USERNAME/${username}/g" /home/${username}/.rtorrent.rc
	sed -i "s/XXX/${PORT}/g" /home/${username}/.rtorrent.rc
	sed -i "s/YYY/${PORTEND}/g" /home/${username}/.rtorrent.rc
	if [[ -f /install/.10g.lock ]]; then
		sed -i "s/throttle.max_peers.normal.set = 100/throttle.max_peers.normal.set = 300/g" /home/${username}/.rtorrent.rc
		sed -i "s/throttle.max_uploads.global.set = 100/throttle.max_uploads.global.set = 300/g" /home/${username}/.rtorrent.rc
	fi
}

# function to set proper diskspace plugin
function _plugins() {
	cd "${rutorrent}plugins/" || exit 1
	if [[ ${primaryroot} == "root" ]]; then
		rm -rf ${rutorrent}plugins/diskspaceh
	else
		rm -rf ${rutorrent}plugins/diskspace
	fi

	\cp -f /srv/rutorrent/home/fileshare/.htaccess /srv/rutorrent/plugins/fileshare/
	cd /srv/rutorrent/home/fileshare/
	rm -rf share.php
	ln -s ../../plugins/fileshare/share.php
	\cp -f ${local_setup}templates/rutorrent/plugins/fileshare/conf.php.template /srv/rutorrent/plugins/fileshare/conf.php

	sed -i 's/homeDirectory/topDirectory/g' /srv/rutorrent/plugins/filemanager/flm.class.php
	sed -i 's/homeDirectory/topDirectory/g' /srv/rutorrent/plugins/filemanager/settings.js.php
	sed -i 's/showhidden: true,/showhidden: false,/g' "${rutorrent}plugins/filemanager/init.js"
	chown -R www-data.www-data "${rutorrent}"
	cd ${rutorrent}plugins/theme/themes/
	git clone https://github.com/AetherFlow/club-AetherFlow club-AetherFlow >>"${OUTTO}" 2>&1
	chown -R www-data:www-data club-AetherFlow
	cd ${rutorrent}plugins
	perl -pi -e "s/\$defaultTheme \= \"\"\;/\$defaultTheme \= \"club-AetherFlow\"\;/g" ${rutorrent}plugins/theme/conf.php
	rm -rf ${rutorrent}plugins/tracklabels/labels/nlb.png

	# Needed for fileupload
	# wget http://ftp.nl.debian.org/debian/pool/main/p/plowshare/plowshare4_2.1.3-1_all.deb -O plowshare4.deb >>"${OUTTO}" 2>&1
	# wget http://ftp.nl.debian.org/debian/pool/main/p/plowshare/plowshare_2.1.3-1_all.deb -O plowshare.deb >>"${OUTTO}" 2>&1
	apt-get -y install plowshare >>"${OUTTO}" 2>&1
	dpkg -i plowshare*.deb >>"${OUTTO}" 2>&1
	rm -rf plowshare*.deb >>"${OUTTO}" 2>&1
	cd /root
	mkdir -p /root/bin
	git clone https://github.com/mcrapet/plowshare.git ~/.plowshare-source >>"${OUTTO}" 2>&1
	cd ~/.plowshare-source >>"${OUTTO}" 2>&1
	make install PREFIX=${HOME} >>"${OUTTO}" 2>&1
	cd && rm -rf .plowshare-source >>"${OUTTO}" 2>&1
	apt-get -f install >>"${OUTTO}" 2>&1

	mkdir -p /srv/rutorrent/conf/users/"${username}"/plugins/fileupload/
	chmod 775 /srv/rutorrent/plugins/fileupload/scripts/upload
	\cp -f /srv/rutorrent/plugins/fileupload/conf.php /srv/rutorrent/conf/users/"${username}"/plugins/fileupload/conf.php
	chown -R www-data: /srv/rutorrent/conf/users/"${username}"

	# Set proper permissions to filemanager so it may execute commands
	find /srv/rutorrent/plugins/filemanager/scripts -type f -exec chmod 755 {} \;
}

# function autodl to install autodl irssi scripts
# shellcheck disable=2312
function _autodl() {
	mkdir -p "/home/${username}/.irssi/scripts/autorun/" >>"${OUTTO}" 2>&1
	cd "/home/${username}/.irssi/scripts/"
	# Grab the most recent version of AutoDL-trackers
	curl -sL "http://git.io/vlcND" | grep -Po '(?<="browser_download_url": ")(.*-v[\d.]+.zip)' | xargs wget --quiet -O autodl-irssi.zip '{}'
	unzip -o autodl-irssi.zip >>"${OUTTO}" 2>&1
	rm autodl-irssi.zip
	\cp -f autodl-irssi.pl autorun/
	mkdir -p "/home/${username}/.autodl" >>"${OUTTO}" 2>&1
	touch "/home/${username}/.autodl/autodl.cfg"
	chown ${username}: /home/${username}/.autodl/autodl.cfg
	touch /install/.autodlirssi.lock
	cat >/home/${username}/.autodl/autodl2.cfg <<ADC
[options]
gui-server-port = ${AUTODLPORT}
gui-server-password = ${AUTODLPASSWORD}
ADC
	chown -R "${username}.${username}" "/home/${username}/.irssi/"
	chown -R "${username}.${username}" "/home/${username}"
}

# function to make dirs for first user
function _makedirs() {
	#mkdir /home/"${username}"/{torrents,.sessions,watch} >>"${OUTTO}" 2>&1
	\cp -rf /etc/skel/. /home/"${username}"
	chown -R "${username}".www-data /home/"${username}" >>"${OUTTO}" 2>&1 #/{torrents,.sessions,watch,.rtorrent.rc} >>"${OUTTO}" 2>&1
	/usr/sbin/usermod -a -G www-data "${username}" >>"${OUTTO}" 2>&1
	/usr/sbin/usermod -a -G "${username}" www-data >>"${OUTTO}" 2>&1
}

# function to make crontab .statup file
#function _cronfile() {
#  cp ${local_setup}templates/startup.template /home/${username}/.startup
#  chmod 775 /home/${username}/.startup
#  if [[ ${DELUGE} != NO ]]; then
#  sed -i 's/DELUGEWEB_CLIENT=no/DELUGEWEB_CLIENT=yes/g' /home/${username}/.startup
#  sed -i 's/DELUGED_CLIENT=no/DELUGED_CLIENT=yes/g' /home/${username}/.startup
#fi
#}

# function to configure first user config.php
function _ruconf() {
	mkdir -p ${rutorrent}conf/users/${username}/

	\cp -f ${local_setup}templates/rutorrent.users.config.template ${rutorrent}conf/users/${username}/config.php

	chown -R www-data.www-data "${rutorrent}conf/users/" >>"${OUTTO}" 2>&1
	if [[ ${primaryroot} == "root" ]]; then
		sed -i "/diskuser/c\$diskuser = \"\/\";" /srv/rutorrent/conf/users/${username}/config.php
	else
		sed -i "/diskuser/c\$diskuser = \"\/home\";" /srv/rutorrent/conf/users/${username}/config.php
	fi
	sed -i "/quotaUser/c\${quota}User = \"${username}\";" /srv/rutorrent/conf/users/${username}/config.php
	sed -i "s/USERNAME/${username}/g" /srv/rutorrent/conf/users/${username}/config.php
	sed -i "s/XXX/${PORT}/g" /srv/rutorrent/conf/users/${username}/config.php
	sed -i "s/YYY/${AUTODLPORT}/g" /srv/rutorrent/conf/users/${username}/config.php
	sed -i "s/ZZZ/\"${AUTODLPASSWORD}\"/g" /srv/rutorrent/conf/users/${username}/config.php
}

# function to install pure-ftpd
function _installftpd() {
	apt-get purge -y vsftpd pure-ftpd >>"${OUTTO}" 2>&1
	apt-get autoremove >>"${OUTTO}" 2>&1
	apt-get install -y vsftpd >>"${OUTTO}" 2>&1
}
