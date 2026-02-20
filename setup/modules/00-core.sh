#!/bin/bash
# Module: 00-core.sh

function _string() { perl -le 'print map {(a..z,A..Z,0..9)[rand 62] } 0..pop' 15; }
#################################################################################
# shellcheck disable=2005,2034,2120,2215,2164,2312

function _bashrc() {
	\cp -f ${local_setup}templates/bashrc.template /root/.bashrc
	profile="/root/.profile"
	if [[ ! -f "${profile}" ]]; then
		\cp -f ${local_setup}templates/profile.template /root/.profile
	fi
}

# intro function (1)
# shellcheck disable=2005,2312
function _intro() {
	DISTRO=$(lsb_release -is)
	CODENAME=$(lsb_release -cs)
	SETNAME=$(lsb_release -rc)
	echo
	echo
	echo "[${repo_title}AetherFlow${normal}] ${title} AetherFlow Seedbox Installation ${normal}  "
	echo
	echo "   ${title}              Heads Up!              ${normal} "
	echo "   ${message_title}  AetherFlow works with the following  ${normal} "
	echo "   ${message_title}  Ubuntu 20.04+ / Debian 11+ ${normal} "
	echo
	echo
	echo "${green}Checking distribution ...${normal}"
	if [[ ! -x /usr/bin/lsb_release ]]; then
		echo "It looks like you are running ${DISTRO}, which is not supported by AetherFlow."
		echo "Exiting..."
		exit 1
	fi
	echo "$(lsb_release -a)"
	echo
	if [[ ! "${DISTRO}" =~ ("Ubuntu"|"Debian") ]]; then
		echo "${DISTRO}: ${alert} It looks like you are running ${DISTRO}, which is not supported by AetherFlow ${normal} "
		echo 'Exiting...'
		exit 1
	elif [[ ! "${CODENAME}" =~ ("bionic"|"focal"|"jammy"|"noble"|"bullseye"|"bookworm"|"trixie") ]]; then
		echo "Oh drats! You do not appear to be running a supported ${DISTRO} release."
		echo "${bold}${SETNAME}${normal}"
		echo 'Exiting...'
		exit 1
	fi

	# Set PHP Version based on OS
	if [[ "${CODENAME}" =~ ("bionic"|"buster") ]]; then
		PHP_VER="7.4"
	elif [[ "${CODENAME}" =~ ("bullseye") ]]; then
		PHP_VER="7.4"
	elif [[ "${CODENAME}" =~ ("bookworm") ]]; then
		PHP_VER="8.2"
	elif [[ "${CODENAME}" =~ ("trixie") ]]; then
		PHP_VER="8.3"
	elif [[ "${CODENAME}" =~ ("focal") ]]; then
		PHP_VER="7.4"
	elif [[ "${CODENAME}" =~ ("jammy") ]]; then
		PHP_VER="8.1"
	elif [[ "${CODENAME}" =~ ("noble") ]]; then
		PHP_VER="8.3"
	else
		PHP_VER="8.2"
	fi
	export PHP_VER
	echo "Selected PHP Version: ${PHP_VER}"
}

# check if root function (2)
function _checkroot() {
	if [[ ${EUID} != 0 ]]; then
		echo 'This script must be run with root privileges.'
		echo 'Exiting...'
		exit 1
	fi
	echo "${green}Congrats! You're running as root. Let's continue${normal} ... "
	echo
}

# check if distribution kernel function (3)
# shellcheck disable=2312,2162
function _checkkernel() {
	grsec=$(uname -a | grep -i grs)
	if [[ -n ${grsec} ]]; then
		echo -e "Your server is currently running with kernel version: $(uname -r)"
		echo -e "Kernels with ${bold}grsec${normal} are not supported"
		echo -ne "${bold}${yellow}Would you like AetherFlow to install the distribution kernel?${normal} (Default: ${green}${bold}Y${normal}) "
		read -r input
		case ${input} in
		[yY] | [yY][Ee][Ss] | "")
			kernel=yes
			echo "Your distribution's default kernel will be installed. A reboot will be ${bold}required${normal}."
			;;
		[nN] | [nN][Oo])
			echo "Installer will not continue. Exiting ... "
			exit 0
			;;
		*)
			kernel=yes
			echo "Your distribution's default kernel will be installed. A reboot will be ${bold}required${normal}."
			;;
		esac
		if [[ ${kernel} == yes ]]; then
			if [[ ${DISTRO} == Ubuntu ]]; then
				apt-get install -q -y linux-image-generic >>"${OUTTO}" 2>&1
			elif [[ ${DISTRO} == Debian ]]; then
				arch=$(uname -m)
				if [[ ${arch} =~ ("i686"|"i386") ]]; then
					apt-get install -q -y linux-image-686 >>"${OUTTO}" 2>&1
				elif [[ ${arch} == x86_64 ]]; then
					apt-get install -q -y linux-image-amd64 >>"${OUTTO}" 2>&1
				fi
			fi
			mv /etc/grub.d/06_OVHkernel /etc/grub.d/25_OVHkernel
			update-grub >>"${OUTTO}" 2>&1
		fi
	fi
}

# check if create log function (4)
# shellcheck disable=2162
function _logcheck() {
	echo -ne "${bold}${yellow}Do you wish to write to a log file?${normal} (Default: ${green}${bold}Y${normal}) "
	read -r input
	case ${input} in
	[yY] | [yY][Ee][Ss] | "")
		OUTTO="/root/AetherFlow.${PPID}.log"
		echo "${bold}Output is being sent to /root/AetherFlow.${magenta}${PPID}${normal}${bold}.log${normal}"
		;;
	[nN] | [nN][Oo])
		OUTTO="/dev/null 2>&1"
		echo "${cyan}NO output will be logged${normal}"
		;;
	*)
		OUTTO="/root/AetherFlow.${PPID}.log"
		echo "${bold}Output is being sent to /root/AetherFlow.${magenta}${PPID}${normal}${bold}.log${normal}"
		;;
	esac
	if [[ ! -d /root/tmp ]]; then
		sed -i 's/noexec,//g' /etc/fstab
		mount -o remount /tmp >>"${OUTTO}" 2>&1
	fi
}

# setting system hostname function (5)
# shellcheck disable=2162
function _hostname() {
	echo -ne "Please enter a hostname for this server (${bold}Hit ${standout}${green}ENTER${normal} to make no changes${normal}): "
	read -r input
	if [[ -z ${input} ]]; then
		echo "No hostname supplied, no changes made!!"
	else
		hostname ${input}
		echo "${input}" >/etc/hostname
		echo "127.0.0.1 ${input}" >/etc/hosts
		echo "Hostname set to ${input}"
	fi
	echo
}

# setting locale function
function _locale() {
	echo 'LANGUAGE="en_US.UTF-8"' >>/etc/default/locale
	echo 'LC_ALL="en_US.UTF-8"' >>/etc/default/locale
	echo "en_US.UTF-8 UTF-8" >/etc/locale.gen
	if [[ -e /usr/sbin/locale-gen ]]; then
		locale-gen >>"${OUTTO}" 2>&1
	else
		apt-get -y update >>"${OUTTO}" 2>&1
		apt-get install locales -y >>"${OUTTO}" 2>&1
		locale-gen >>"${OUTTO}" 2>&1
		export LANG="en_US.UTF-8"
		export LC_ALL="en_US.UTF-8"
		export LANGUAGE="en_US.UTF-8"
	fi
}
