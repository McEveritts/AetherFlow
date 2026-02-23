#!/bin/bash
# Module: 02-packages.sh


# package and repo addition (silently add php7) _add respo sources_
# shellcheck disable=2312
function _repos() {
	apt-get update -y >>"${OUTTO}" 2>&1 || return 1
	apt-get install -y software-properties-common >>"${OUTTO}" 2>&1 || return 1
	apt-get -y install lsb-release sudo >>"${OUTTO}" 2>&1 || return 1
	if [[ ${DISTRO} == Ubuntu ]]; then
		LC_ALL=en_US.UTF-8 apt-add-repository ppa:ondrej/php -y >>"${OUTTO}" 2>&1 || return 1
	fi

	if [[ ${DISTRO} == Debian ]]; then
        wget -qO - https://packages.sury.org/php/apt.gpg | gpg --dearmor -o /usr/share/keyrings/deb.sury.org-php.gpg || return 1
        echo "deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list
	fi

}

# package and repo addition _update and upgrade_
# shellcheck disable=2312
function _updates() {
	if [[ ${DISTRO} == Debian ]]; then
		\cp -f ${local_setup}templates/apt.sources/debian.template /etc/apt/sources.list
		sed -i "s/RELEASE/${CODENAME}/g" /etc/apt/sources.list
		apt-get -o Acquire::AllowInsecureRepositories=true -o Acquire::AllowDowngradeToInsecureRepositories=true update >>"${OUTTO}" 2>&1
		yes '' | apt-get install --allow-unauthenticated -y build-essential debian-archive-keyring software-properties-common >>"${OUTTO}" 2>&1
		apt-get --allow-unauthenticated -y install deb-multimedia-keyring >>"${OUTTO}" 2>&1
	else
		\cp -f ${local_setup}templates/apt.sources/ubuntu.template /etc/apt/sources.list
		sed -i "s/RELEASE/${CODENAME}/g" /etc/apt/sources.list
		apt-get -y update >>"${OUTTO}" 2>&1
		apt-get -y -f install build-essential debian-archive-keyring software-properties-common >>"${OUTTO}" 2>&1
		#apt-get -y -f --allow-unauthenticated install deb-multimedia-keyring >>"${OUTTO}" 2>&1
	fi

	if [[ ${DISTRO} == Debian ]]; then
		export DEBIAN_FRONTEND=noninteractive
		yes '' | apt-get update >>"${OUTTO}" 2>&1
		apt-get -y purge samba samba-common >>"${OUTTO}" 2>&1
		apt-get -y full-upgrade >>"${OUTTO}" 2>&1
	else
		export DEBIAN_FRONTEND=noninteractive
		apt-get -y update >>"${OUTTO}" 2>&1
		apt-get -y purge samba samba-common >>"${OUTTO}" 2>&1
		apt-get -y full-upgrade >>"${OUTTO}" 2>&1
	fi

	if [[ -e /etc/ssh/sshd_config ]]; then
		sed -i 's/.*Port .*/Port 4747/g' /etc/ssh/sshd_config
		#sed -i 's/SendEnv LANG LC_*/#SendEnv LANG LC_*/g' /etc/ssh/ssh_config
		#sed -i 's/AcceptEnv LANG LC_*/#AcceptEnv LANG LC_*/g' /etc/ssh/sshd_config
		service ssh restart >>"${OUTTO}" 2>&1
	fi

	# Create the service lock file directory
	if [[ -d /install ]]; then cd /; else mkdir -p /install; fi
	if [[ -d /root/tmp ]]; then cd && rm -r tmp; fi

}

# package and repo addition _install softwares and packages_
# shellcheck disable=2312
function _depends() {
	if [[ ${DISTRO} == Debian ]]; then
		yes '' | apt-get install -y fail2ban bc build-essential ed sudo screen zip irssi unzip nano bwm-ng htop nethogs speedtest-cli iotop git dos2unix subversion dstat automake make mktorrent libtool libcppunit-dev libssl-dev pkg-config libxml2-dev libcurl4-openssl-dev libsigc++-2.0-dev apache2-utils autoconf cron curl libapache2-mod-fcgid libapache2-mod-php"${PHP_VER}" libxslt-dev libncurses5-dev yasm pcregrep apache2 php-net-socket libapache2-mod-php"${PHP_VER}" php-memcached memcached php"${PHP_VER}" php"${PHP_VER}"-cli php"${PHP_VER}"-curl php"${PHP_VER}"-fpm php"${PHP_VER}"-gd php"${PHP_VER}"-mbstring php"${PHP_VER}"-msgpack php"${PHP_VER}"-mysql php"${PHP_VER}"-opcache php"${PHP_VER}"-xml php"${PHP_VER}"-xmlrpc php"${PHP_VER}"-zip libfcgi0ldbl mcrypt libmcrypt-dev python3-lxml python3-lxml fontconfig comerr-dev ca-certificates libfontconfig1-dev libdbd-mysql-perl libdbi-perl libfontconfig1 rar unrar mediainfo ifstat ttf-mscorefonts-installer checkinstall dtach libarchive-zip-perl libnet-ssleay-perl ca-certificates-java libxslt1-dev libxslt1.1 libxml2 libffi-dev python3-pip python3-dev libhtml-parser-perl libxml-libxml-perl libjson-perl libjson-xs-perl libxml-libxslt-perl zlib1g-dev vnstat vnstati openvpn iptables iptables-persistent >>"${OUTTO}" 2>&1 || return 1
	elif [[ ${DISTRO} == Ubuntu ]]; then
		DEBIAN_FRONTEND=noninteractive apt-get -yqq --allow-unauthenticated -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" install build-essential debian-archive-keyring fail2ban bc sudo screen zip irssi unzip nano bwm-ng htop iotop git dos2unix subversion dstat automake make mktorrent libtool libcppunit-dev libssl-dev pkg-config libxml2-dev libcurl4-openssl-dev libsigc++-2.0-dev apache2-utils autoconf cron curl libapache2-mod-php"${PHP_VER}" libxslt-dev libncurses5-dev yasm pcregrep apache2 php-net-socket libdbd-mysql-perl libdbi-perl php-memcached memcached php"${PHP_VER}" php"${PHP_VER}"-cli php"${PHP_VER}"-curl php"${PHP_VER}"-fpm php"${PHP_VER}"-gd php"${PHP_VER}"-mbstring php"${PHP_VER}"-msgpack php"${PHP_VER}"-mysql php"${PHP_VER}"-opcache php"${PHP_VER}"-xml php"${PHP_VER}"-xmlrpc php"${PHP_VER}"-zip libfcgi0ldbl mcrypt libmcrypt-dev fontconfig comerr-dev ca-certificates libfontconfig1-dev libfontconfig1 rar unrar mediainfo ifstat libapache2-mod-php"${PHP_VER}" python3-lxml python3-lxml ttf-mscorefonts-installer checkinstall dtach libarchive-zip-perl libnet-ssleay-perl openjdk-8-jre-headless openjdk-8-jre openjdk-8-jdk libxslt1-dev libxslt1.1 libxml2 libffi-dev python3-pip python3-dev libhtml-parser-perl libxml-libxml-perl libjson-perl libjson-xs-perl libxml-libxslt-perl zlib1g-dev vnstat vnstati openvpn iptables iptables-persistent >>"${OUTTO}" 2>&1 || return 1
	fi
}

# build openssl from source to combat recent apt source updates
# shellcheck disable=2312
function _openssl() {
	echo "Using system OpenSSL. Skipping manual build of OpenSSL 1.0.2p."
}

# Pre-processing scripts,  giving permissions
# shellcheck disable=2312
function _syscommands() {
	mkdir -p /usr/local/bin/AetherFlow
	\cp -rf ${local_packages}/. /usr/local/bin/AetherFlow
	dos2unix $(find /usr/local/bin/AetherFlow -type f) >>"${OUTTO}" 2>&1
	chmod +x $(find /usr/local/bin/AetherFlow -type f) >>"${OUTTO}" 2>&1
	\cp -f /usr/local/bin/AetherFlow/system/reload /usr/bin/reload
}

# install skel template
function _skel() {
	if [[ -d /etc/skel ]]; then rm -r /etc/skel; fi
	mkdir -p /etc/skel
	\cp -rf ${local_setup}templates/skel/. /etc/skel
	tar xzf ${local_setup}sources/rarlinux-x64-5.5.0.tar.gz -C ./
	\cp -f ./rar/*rar /usr/bin
	\cp -f ./rar/*rar /usr/sbin
	rm -rf rarlinux*.tar.gz
	rm -rf ./rar
	# GeoLiteCity.dat.gz is no longer available from MaxMind
	# wget -q http://geolite.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
	# gunzip GeoLiteCity.dat.gz >>"${OUTTO}" 2>&1
	# mkdir -p /usr/share/GeoIP >>"${OUTTO}" 2>&1
	# rm -rf GeoLiteCity.dat.gz
	# mv GeoLiteCity.dat /usr/share/GeoIP/GeoIPCity.dat >>"${OUTTO}" 2>&1
	(
		echo y
		echo o conf prerequisites_policy follow
		echo o conf commit
	) >/dev/null 2>&1 | cpan Digest::SHA1 >>"${OUTTO}" 2>&1
	(
		echo y
		echo o conf prerequisites_policy follow
		echo o conf commit
	) >/dev/null 2>&1 | cpan Digest::SHA >>"${OUTTO}" 2>&1
	if [[ ${DELUGE} != NO ]]; then
		mkdir -p /etc/skel/.config/deluge/plugins/
		cd /etc/skel/.config/deluge/plugins/
		wget -q https://github.com/ratanakvlun/deluge-ltconfig/releases/download/v0.3.1/ltConfig-0.3.1-py2.7.egg
	fi
}

# Setup mount points for Quotas
function _qmount() {
	if [[ ${quota} == yes ]]; then
		if [[ ${DISTRO} == Ubuntu ]]; then
			if [[ ${primaryroot} == "root" ]]; then
				sed -ie '/\/ / s/defaults/usrjquota=aquota.user,jqfmt=vfsv1,defaults/' /etc/fstab
				sed -i 's/errors=remount-ro/usrjquota=aquota.user,jqfmt=vfsv1,errors=remount-ro/g' /etc/fstab
				apt-get install -y linux-image-extra-virtual quota >>"${OUTTO}" 2>&1
				mount -o remount / || mount -o remount /home >>"${OUTTO}" 2>&1
				quotacheck -auMF vfsv1 >>"${OUTTO}" 2>&1
				quotaon -uv / >>"${OUTTO}" 2>&1
				service quota start >>"${OUTTO}" 2>&1
			else
				sed -ie '/\/home/ s/defaults/usrjquota=aquota.user,jqfmt=vfsv1,defaults/' /etc/fstab
				sed -i 's/errors=remount-ro/usrjquota=aquota.user,jqfmt=vfsv1,errors=remount-ro/g' /etc/fstab
				apt-get install -y linux-image-extra-virtual quota >>"${OUTTO}" 2>&1
				mount -o remount /home >>"${OUTTO}" 2>&1
				quotacheck -auMF vfsv1 >>"${OUTTO}" 2>&1
				quotaon -uv /home >>"${OUTTO}" 2>&1
				service quota start >>"${OUTTO}" 2>&1
			fi
		elif [[ ${DISTRO} == Debian ]]; then
			if [[ ${primaryroot} == "root" ]]; then
				sed -ie '/\/ / s/defaults/usrjquota=aquota.user,jqfmt=vfsv1,defaults/' /etc/fstab
				sed -i 's/errors=remount-ro/usrjquota=aquota.user,jqfmt=vfsv1,errors=remount-ro/g' /etc/fstab
				apt-get install -y quota >>"${OUTTO}" 2>&1
				mount -o remount / || mount -o remount /home >>"${OUTTO}" 2>&1
				quotacheck -auMF vfsv1 >>"${OUTTO}" 2>&1
				quotaon -uv / >>"${OUTTO}" 2>&1
				service quota start >>"${OUTTO}" 2>&1
			else
				sed -ie '/\/home/ s/defaults/usrjquota=aquota.user,jqfmt=vfsv1,defaults/' /etc/fstab
				sed -i 's/errors=remount-ro/usrjquota=aquota.user,jqfmt=vfsv1,errors=remount-ro/g' /etc/fstab
				apt-get install -y quota >>"${OUTTO}" 2>&1
				mount -o remount /home >>"${OUTTO}" 2>&1
				quotacheck -auMF vfsv1 >>"${OUTTO}" 2>&1
				quotaon -uv /home >>"${OUTTO}" 2>&1
				service quota start >>"${OUTTO}" 2>&1
			fi
		fi
		touch /install/.quota.lock
	fi
}

# build function for ffmpeg
# shellcheck disable=2215,2312,2250
function _ffmpeg() {
	if [[ ${ffmpeg} == "yes" ]]; then
		apt-get -qy update >>"${OUTTO}" 2>&1
		LIST='autotools-dev autoconf automake cmake cmake-curses-gui build-essential mercurial libass-dev'
		apt-get -qq -y install ${LIST} >>"${OUTTO}" 2>&1
		MAXCPUS=$(echo "$(nproc) / 2" | bc)
		mkdir -p /tmp
		cd /tmp || exit 1
		if [[ -d /tmp/ffmpeg ]]; then rm -rf ffmpeg; fi
		git clone --depth 1 -b release/4.4 https://github.com/FFmpeg/FFmpeg.git ffmpeg >>"${OUTTO}" 2>&1
		git clone https://github.com/yasm/yasm.git ffmpeg/yasm >>"${OUTTO}" 2>&1
		git clone https://github.com/yixia/x264.git ffmpeg/x264 >>"${OUTTO}" 2>&1
		#hg clone https://bitbucket.org/multicoreware/x265 ffmpeg/x265 >>"${OUTTO}" 2>&1
		git clone https://bitbucket.org/multicoreware/x265_git.git ffmpeg/x265 >>"${OUTTO}" 2>&1
		############################################################################
		####---- Github Mirror source ----####
		#git clone https://git.ffmpeg.org/ffmpeg.git ffmpeg >>"${OUTTO}" 2>&1
		############################################################################
		cd ffmpeg || exit 1
		wget -q https://www.nasm.us/pub/nasm/releasebuilds/2.15.05/nasm-2.15.05.tar.gz
		tar zxvf nasm-2.15.05.tar.gz >>"${OUTTO}" 2>&1
		cd nasm-2.15.05 || exit 1
		./autogen.sh >>"${OUTTO}" 2>&1
		./configure >>"${OUTTO}" 2>&1
		make -j${MAXCPUS} >>"${OUTTO}" 2>&1
		make install >>"${OUTTO}" 2>&1
		cd ../yasm || exit 1
		./autogen.sh >>"${OUTTO}" 2>&1
		./configure >>"${OUTTO}" 2>&1
		make >>"${OUTTO}" 2>&1
		make install >>"${OUTTO}" 2>&1
		cd ../x264 || exit 1
		PKG_CONFIG_PATH="$PKG_CONFIG_PATH:/tmp/ffmpeg/lib/pkgconfig" ./configure --prefix="/tmp/ffmpeg" --enable-static --enable-pic >>"${OUTTO}" 2>&1
		make -j${MAXCPUS} >>"${OUTTO}" 2>&1
		make install >>"${OUTTO}" 2>&1
		cd ../x265/build/linux || exit 1
		#./make-Makefiles.bash >>"${OUTTO}" 2>&1
		cmake -G "Unix Makefiles" /tmp/ffmpeg/x265/source -DCMAKE_INSTALL_PREFIX="/tmp/ffmpeg" -DENABLE_SHARED:bool=off >>"${OUTTO}" 2>&1
		make -j${MAXCPUS} >>"${OUTTO}" 2>&1
		make install >>"${OUTTO}" 2>&1
		ldconfig >>"${OUTTO}" 2>&1
		cd /tmp/ffmpeg || exit 1
		export FC_CONFIG_DIR=/etc/fonts
		export FC_CONFIG_FILE=/etc/fonts/fonts.conf
		PKG_CONFIG_PATH="$PKG_CONFIG_PATH:/tmp/ffmpeg/lib/pkgconfig" \
		./configure --enable-libfreetype --enable-filter=drawtext --enable-fontconfig \
		--enable-libx265 --enable-libx264 --enable-gpl --enable-shared --enable-pic \
		--extra-libs="-lpthread -lm" \
		--extra-ldflags="-L/tmp/ffmpeg/lib -L/tmp/ffmpeg/lib/pkgconfig" \
		--extra-cflags="-I/tmp/ffmpeg/include" \
		--pkg-config-flags="--static" >>"${OUTTO}" 2>&1
		make -j${MAXCPUS} >>"${OUTTO}" 2>&1
		make install >>"${OUTTO}" 2>&1
		\cp -f /usr/local/bin/ffmpeg /usr/bin >>"${OUTTO}" 2>&1
		\cp -f /usr/local/bin/ffprobe /usr/bin >>"${OUTTO}" 2>&1
		cd /tmp || exit 1
		rm -rf /tmp/ffmpeg >>"${OUTTO}" 2>&1
	fi
}
