#!/bin/bash
# Module: 01-prompts.sh

# shellcheck disable=2162
function _askquota() {
	echo -ne "${bold}${yellow}Do you wish to use user quotas?${normal} (Default: ${green}${bold}Y${normal}) "
	read input
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
}

# shellcheck disable=2162
function _ask10g() {
	echo -ne "${bold}${yellow}Is this a 10 gigabit server?${normal} (Default: ${green}${bold}N${normal}) "
	read input
	case ${input} in
	[yY] | [yY][Ee][Ss])
		if [[ -d /install ]]; then cd /; else mkdir -p /install; fi
		touch /install/.10g.lock
		echo "${bold}The devs are officially jealous${normal}"
		;;
	[nN] | [nN][Oo] | "") echo "${cyan}Who can afford that stuff anyway?${normal}" ;;
	*) echo "${cyan}Who can afford that stuff anyway?${normal}" ;;
	esac
	echo
}

# primary partition question
# shellcheck disable=2250,2162
function _askpartition() {
	if [[ ${quota} == yes ]]; then
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
		read version
		case $version in
		1 | "") primaryroot=root ;;
		2) primaryroot=home ;;
		*) primaryroot=root ;;
		esac
		echo "Using ${green}$primaryroot mount${normal} for quotas"
		echo
	fi
}

# shellcheck disable=2162
function _askcontinue() {
	echo
	echo "Press ${standout}${green}ENTER${normal} when you're ready to begin or ${standout}${red}Ctrl+Z${normal} to cancel"
	read input
	echo
}

# ask what theme version (8)
# shellcheck disable=2250,2162
function _askdashtheme() {
	echo -e "1) AetherFlow - ${green}smoked${normal} :: Dark theme"
	echo -e "2) AetherFlow - ${green}defaulted${normal} :: Light theme"
	echo -ne "${bold}${yellow}Pick your AetherFlow Dashboard Theme${normal} (Default ${green}1${normal}): "
	read version
	case $version in
	1 | "") dash_theme=smoked ;;
	2) dash_theme=defaulted ;;
	*) dash_theme=smoked ;;
	esac
	echo "We will be using AetherFlow Theme : ${green}$dash_theme${normal}"
	echo
}

# ask what rtorrent version (9.1)
# shellcheck disable=2250,2162
function _askrtorrent() {
	echo -e "1) rtorrent ${green}0.9.7 (with ipv6 support)${normal}"
	echo -e "2) rtorrent ${green}0.9.6 (with ipv6 support)${normal}"
	echo -e "3) rtorrent ${green}0.9.4 (with ipv6 support)${normal}"
	echo -e "4) rtorrent ${green}0.9.3${normal}"
	echo -ne "${bold}${yellow}What version of rtorrent do you want?${normal} (Default ${green}1${normal}): "
	read version
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
}

# ask deluge version (if wanted) (9.2)
# shellcheck disable=2250,2162
function _askdeluge() {
	if [[ "${CODENAME}" =~ ("bionic"|"focal"|"jammy"|"noble"|"bullseye"|"bookworm"|"trixie") ]]; then
		echo "Detected modern OS (${DISTRO} ${CODENAME}). Forcing Deluge installation from Repository (version 2.x) as source build requires Python 2."
		DELUGE="REPO"
	else
		echo -e "1) Deluge ${green}repo${normal} (fastest installing)"
		echo -e "2) Deluge with ${green}libtorrent 1.0.x (stable)${normal}"
		echo -e "3) Deluge with ${green}libtorrent 1.1.x (stable)${normal}"
		echo -e "4) Do not install Deluge"
		echo -ne "${bold}${yellow}What version of Deluge do you want?${normal} (Default ${green}1${normal}): "
		read version
		case $version in
		1 | "") DELUGE=REPO ;;
		2) DELUGE="1.0.11" ;;
		3) DELUGE="1.1.3" ;;
		4) DELUGE="NO" ;;
		*) DELUGE="REPO" ;;
		esac
	fi
	echo "We will be using Deluge: ${DELUGE}"
	echo
}

# install qbittorrent question (9.3)
# shellcheck disable=2215,2312,2250,2162
function _askqb() {
	echo -e "${green}00)${normal} Do not install qBittorrent${normal}"
	echo -e "${green}01)${normal} qBittorrent ${green}3.3.16${normal}"
	echo -e "${green}02)${normal} qBittorrent ${green}4.0.4${normal}"
	echo -e "${green}03)${normal} qBittorrent ${green}4.1.3${normal}"
	echo -e "${green}04)${normal} qBittorrent ${bold}${green}latest version${normal}"
	echo -ne "${bold}${yellow}Which version of qBittorrent do you want?${normal} (Default ${green}0${normal}): "
	read -e version
	# shellcheck disable=2221,2222
	case $version in
	00 | 0) QBVERSION=no ;;
	01 | 1)
		QBVERSION="3.3.16"
		qbburst="no"
		;;
	02 | 2)
		QBVERSION="4.0.4"
		qbburst="no"
		;;
	03 | 3)
		QBVERSION="4.1.3"
		qbburst="no"
		;;
	04 | 4)
		QBVERSION=$(curl -i -s https://www.qbittorrent.org/ | grep -Eo "Latest:.*" | grep -Eo "[0-9.]+")
		qbburst=no
		;;
	* | "") QBVERSION=no ;;
	esac

	echo "${bold}${green}qBittorrent ${QBVERSION}${normal} ${bold}will be installed${normal}"
	echo
}

# install transmission question (9.4)
# shellcheck disable=2162
function _asktr() {
	echo -ne "${bold}${yellow}Would you like to install transmission? ${normal} [y]es or [${green}n${normal}]o: "
	read response
	case ${response} in
	[yY] | [yY][Ee][Ss]) tr="yes" ;;
	[nN] | [nN][Oo] | "") tr="no" ;;
	*) tr="no" ;;
	esac
	echo
}

# adduser function (10)
# shellcheck disable=2215,2312,2250,2162
function _adduser() {
	local REALM="rutorrent"
	local HTPASSWD="/etc/htpasswd"
	theshell="/bin/bash"
	echo "${bold}${yellow}Add a Master Account user to sudoers${normal}"
	echo -n "Username: "
	read user
	username=$(echo "${user}" | sed 's/.*/\L&/')
	/usr/sbin/useradd "${username}" -m -G www-data -s "${theshell}"
	echo -n "Password: (hit enter to generate a password) "
	read 'password'
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
}

# install ffmpeg question (11)
# shellcheck disable=2162
function _askffmpeg() {
	echo -ne "${bold}${yellow}Would you like to install ffmpeg? (Used for screenshots)${normal} [${green}y${normal}]es or [n]o: "
	read response
	case ${response} in
	[yY] | [yY][Ee][Ss] | "") ffmpeg=yes ;;
	[nN] | [nN][Oo]) ffmpeg=no ;;
	*) ffmpeg=yes ;;
	esac
	echo
}

# ask user for vsftpd conf (12)
apt-get install -y net-tools
# shellcheck disable=2162,2312
function _askvsftpd() {
	local DEFAULTIP
	DEFAULTIP=$(ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0.1')
	echo -ne "${bold}${yellow}Please, write your public server IP (used for ftp)${normal} (Default: ${green}${bold}${DEFAULTIP}${normal}) "
	read input
	if [[ -z "${input}" ]]; then
		IP=${DEFAULTIP}
	else
		IP=${input}
	fi

	echo
}

# install bbr question (x)
# shellcheck disable=2162
function _askbbr() {
	echo -ne "${bold}${yellow}Would you like to install bbr? (Used for Congestion Control)${normal} [${green}y${normal}]es or [n]o: "
	read response
	case ${response} in
	[yY] | [yY][Ee][Ss] | "") bbr=yes ;;
	[nN] | [nN][Oo]) bbr=no ;;
	*) bbr=yes ;;
	esac
	echo
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
	read answer
	case $answer in
	[yY] | [yY][Ee][Ss] | "") sudoers="yes" ;;
	[nN] | [nN][Oo]) sudoers="no" ;;
	*) sudoers="yes" ;;
	esac
}
