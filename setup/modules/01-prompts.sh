#!/bin/bash
# Module: 01-prompts.sh

# shellcheck disable=2162
function _askquota() {
	# Resume: use saved config if available
	local saved=$(_load_config quota)
	if [[ -n "${saved}" ]]; then
		quota="${saved}"
		echo "Using saved preference: quota=${quota}"
		return 0
	fi

	echo -ne "${bold}${yellow}Do you wish to use user quotas?${normal} (Default: ${green}${bold}Y${normal}) "
	read -r input
	case ${input} in
	[yY] | [yY][Ee][Ss] | "")
		quota="yes"
		echo "${bold}Quotas will be installed${normal}"
		;;
	[nN] | [nN][Oo])
		quota="no"
		echo "${cyan}Quotas will not be installed${normal}"
		;;
	*)
		quota="yes"
		echo "${bold}Quotas will be installed${normal}"
		;;
	esac
	_save_config quota "${quota}"
}

# shellcheck disable=2162
function _ask10g() {
	local saved=$(_load_config is10g)
	if [[ -n "${saved}" ]]; then
		if [[ "${saved}" == "yes" ]]; then
			mkdir -p /install
			touch /install/.10g.lock
		fi
		echo "Using saved preference: 10g=${saved}"
		return 0
	fi

	echo -ne "${bold}${yellow}Is this a 10 gigabit server?${normal} (Default: ${green}${bold}N${normal}) "
	read -r input
	case ${input} in
	[yY] | [yY][Ee][Ss])
		if [[ -d /install ]]; then cd /; else mkdir -p /install; fi
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

	echo
	echo "Press ${standout}${green}ENTER${normal} when you're ready to begin or ${standout}${red}Ctrl+Z${normal} to cancel"
	read -r input
	echo
	_save_config continued "yes"
}

# ask what theme version (8)
# shellcheck disable=2250,2162
# NOTE: _askdashtheme removed — legacy PHP dashboard sunset
# Default theme variable set for any remaining references
function _askdashtheme() {
	dash_theme=smoked
}

# ask what rtorrent version (9.1)
# shellcheck disable=2250,2162
function _askrtorrent() {
	local saved_rt=$(_load_config RTVERSION)
	local saved_lt=$(_load_config LTORRENT)
	if [[ -n "${saved_rt}" && -n "${saved_lt}" ]]; then
		RTVERSION="${saved_rt}"
		LTORRENT="${saved_lt}"
		echo "Using saved preference: rtorrent-${green}${RTVERSION}${normal}/libtorrent-${green}${LTORRENT}${normal}"
		return 0
	fi

	echo -e "1) rtorrent ${green}0.9.7 (with ipv6 support)${normal}"
	echo -e "2) rtorrent ${green}0.9.6 (with ipv6 support)${normal}"
	echo -e "3) rtorrent ${green}0.9.4 (with ipv6 support)${normal}"
	echo -e "4) rtorrent ${green}0.9.3${normal}"
	echo -ne "${bold}${yellow}What version of rtorrent do you want?${normal} (Default ${green}1${normal}): "
	read -r version
	case $version in
	1 | "")
		RTVERSION="0.9.7"
		LTORRENT="0.13.7"
		;;
	2)
		RTVERSION="0.9.6"
		LTORRENT="0.13.6"
		;;
	3)
		RTVERSION="0.9.4"
		LTORRENT="0.13.4"
		;;
	*)
		RTVERSION="0.9.7"
		LTORRENT="0.13.7"
		;;
	esac
	echo "We will be using rtorrent-${green}${RTVERSION}${normal}/libtorrent-${green}${LTORRENT}${normal}"
	echo
	_save_config RTVERSION "${RTVERSION}"
	_save_config LTORRENT "${LTORRENT}"
}



# install qBittorrent question (9.3)
# shellcheck disable=2215,2312,2250,2162
function _askqb() {
	local saved=$(_load_config QBVERSION)
	if [[ -n "${saved}" ]]; then
		QBVERSION="${saved}"
		echo "Using saved preference: qBittorrent=${QBVERSION}"
		return 0
	fi

	echo -e "${green}0)${normal} Do not install qBittorrent${normal}"
	echo -e "${green}1)${normal} Install qBittorrent (latest repo version)${normal}"
	echo -ne "${bold}${yellow}Which version of qBittorrent do you want?${normal} (Default ${green}0${normal}): "
	read -r -e version
	case $version in
	0) QBVERSION=no ;;
	1) QBVERSION=yes ;;
	* | "") QBVERSION=no ;;
	esac

	if [[ ${QBVERSION} == "yes" ]]; then
		echo "${bold}${green}qBittorrent ${normal} ${bold}will be installed from repositories${normal}"
	else
		echo "${bold}${green}qBittorrent ${normal} ${bold}will NOT be installed${normal}"
	fi
	echo
	_save_config QBVERSION "${QBVERSION}"
}

# install transmission question (9.4)
# shellcheck disable=2162
function _asktr() {
	local saved=$(_load_config tr)
	if [[ -n "${saved}" ]]; then
		tr="${saved}"
		echo "Using saved preference: transmission=${tr}"
		return 0
	fi

	echo -ne "${bold}${yellow}Would you like to install transmission? ${normal} [y]es or [${green}n${normal}]o: "
	read -r response
	case ${response} in
	[yY] | [yY][Ee][Ss]) tr="yes" ;;
	[nN] | [nN][Oo] | "") tr="no" ;;
	*) tr="no" ;;
	esac
	echo
	_save_config tr "${tr}"
}

# adduser function (10)
# shellcheck disable=2215,2312,2250,2162
function _adduser() {
	# Check for saved user credentials
	local saved_user=$(_load_config username)
	local saved_pass=$(_load_config passwd)
	local saved_ha1=$(_load_config ha1pass)
	if [[ -n "${saved_user}" && -n "${saved_pass}" ]]; then
		username="${saved_user}"
		passwd="${saved_pass}"
		ha1pass="${saved_ha1}"
		echo "Using saved user: ${username}"
		# Ensure user exists on system (idempotent)
		if ! id "${username}" &>/dev/null; then
			/usr/sbin/useradd "${username}" -m -G www-data -s "/bin/bash" 2>/dev/null
			echo "${username}:${passwd}" | /usr/sbin/chpasswd >>"${OUTTO}" 2>&1
		fi
		# Ensure htpasswd entry exists
		if ! grep -q "^${username}:" "${HTPASSWD}" 2>/dev/null; then
			local REALM="aetherflow"
			(echo -n "${username}:${REALM}:" && echo -n "${username}:${REALM}:${passwd}" | md5sum | awk '{print $1}') >>"${HTPASSWD}"
		fi
		return 0
	fi

	local REALM="aetherflow"
	local HTPASSWD="/etc/htpasswd"
	theshell="/bin/bash"
	echo "${bold}${yellow}Add a Master Account user to sudoers${normal}"
	echo -n "Username: "
	read -r user
	username=$(echo "${user}" | sed 's/.*/\L&/')
	/usr/sbin/useradd "${username}" -m -G www-data -s "${theshell}"
	echo -n "Password: (hit enter to generate a password) "
	read -r password
	if [[ -n "${password}" ]]; then
		echo "setting password to ${password}"
		passwd=${password}
		echo "${username}:${passwd}" | /usr/sbin/chpasswd >>"${OUTTO}" 2>&1
		(echo -n "${username}:${REALM}:" && echo -n "${username}:${REALM}:${passwd}" | md5sum | awk '{print $1}') >>"${HTPASSWD}"
	else
		echo "setting password to ${genpass}"
		passwd=${genpass}
		echo "${username}:${passwd}" | /usr/sbin/chpasswd >>"${OUTTO}" 2>&1
		(echo -n "${username}:${REALM}:" && echo -n "${username}:${REALM}:${passwd}" | md5sum | awk '{print $1}') >>"${HTPASSWD}"
	fi
	printf "${username}:${passwd}" >/root/"${username}".info.db
	echo
	ha1pass=$(echo -n "${passwd}" | md5sum | cut -f1 -d' ')

	# Persist credentials for resume
	_save_config username "${username}"
	_save_config passwd "${passwd}"
	_save_config ha1pass "${ha1pass}"
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
	DEFAULTIP=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1')
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
################################################################################
#   //BEGIN UNUSED FUNCTIONS//
################################################################################
# ask for bash or lshell function ()
# Heads Up: lshell is disabled for the initial user on install as your first user
# should not be limited in shell. Additional created users are automagically
# added to a limited shell environment.
# shellcheck disable=2250,2162
function _askshell() {
	#echo -ne "${yellow}Set user shell to lshell?${normal} (Default: ${red}N${normal}): "; read responce
	#case ${responce} in
	#  [yY] | [yY][Ee][Ss] ) theshell="/usr/bin/lshell" ;;
	#  [nN] | [nN][Oo] | "" ) theshell="/bin/bash" ;;
	#  *) theshell="yes" ;;
	#esac
	echo -ne "${bold}${yellow}Add user to /etc/sudoers${normal} [${green}y${normal}]es or [n]o: "
	read -r answer
	case $answer in
	[yY] | [yY][Ee][Ss] | "") sudoers="yes" ;;
	[nN] | [nN][Oo]) sudoers="no" ;;
	*) sudoers="yes" ;;
	esac
}
