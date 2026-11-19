#!/bin/bash
# Module: 01-prompts.sh



# shellcheck disable=2162
function _ask10g() {
	local saved=$(_load_config is10g)
	if [[ -n "${saved}" ]]; then
		if [[ "${saved}" == "yes" ]]; then
			if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
				install -d -m 0750 -o root -g "$(getent group aetherflow >/dev/null 2>&1 && echo aetherflow || echo root)" /install
			else
				mkdir -p /install
			fi
			touch /install/.10g.lock
		fi
		echo "Using saved preference: 10g=${saved}"
		return 0
	fi

	if [[ "${UNATTENDED:-false}" == "true" ]]; then
		echo "${cyan}Unattended mode: assuming this is not a 10 gigabit server.${normal}"
		_save_config is10g "no"
		echo
		return 0
	fi

	echo -ne "${bold}${yellow}Is this a 10 gigabit server?${normal} (Default: ${green}${bold}N${normal}) "
	read -r input
	case ${input} in
	[yY] | [yY][Ee][Ss])
		if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
			install -d -m 0750 -o root -g "$(getent group aetherflow >/dev/null 2>&1 && echo aetherflow || echo root)" /install
		else
			mkdir -p /install
		fi
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

		if [[ "${UNATTENDED:-false}" == "true" ]]; then
			primaryroot="root"
			echo "Unattended mode: using root mount for quotas."
			_save_config primaryroot "${primaryroot}"
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

	if [[ "${UNATTENDED:-false}" == "true" ]]; then
		_save_config continued "yes"
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

# NOTE: _askrtorrent, _askqb, and _asktr removed — torrent client installation deferred to AetherFlow Marketplace
function _askrtorrent() {
	return 0
}

function _askqb() {
	return 0
}

function _asktr() {
	return 0
}

# adduser function (10)
# shellcheck disable=2215,2312,2250,2162
function _adduser() {
	# Check for saved user credentials
	local saved_user=$(_load_config username)
	local saved_pass=$(_load_config passwd)
	local REALM="Welcome to AetherFlow"
	local HTPASSWD="/etc/htpasswd"
	local theshell="/bin/bash"

	if [[ "${UNATTENDED:-false}" == "true" ]]; then
		if [[ -z "${saved_user}" ]]; then
			saved_user="${username:-admin}"
		fi
		if [[ -z "${saved_pass}" ]]; then
			saved_pass="${passwd:-${password:-${genpass}}}"
		fi
		_save_config username "${saved_user}"
		_save_config passwd "${saved_pass}"
	fi

	if [[ -n "${saved_user}" && -n "${saved_pass}" ]]; then
		username="${saved_user}"
		passwd="${saved_pass}"
		echo "Using saved user: ${username}"
		# Ensure user exists on system (idempotent)
		if id "${username}" &>/dev/null; then
			/usr/sbin/usermod -a -G www-data,sudo -s "${theshell}" "${username}" 2>/dev/null || true
		else
			/usr/sbin/useradd "${username}" -m -G www-data,sudo -s "/bin/bash" 2>/dev/null
		fi
		echo "${username}:${passwd}" | /usr/sbin/chpasswd >>"${OUTTO}" 2>&1
		mkdir -p "$(dirname "${HTPASSWD}")"
		touch "${HTPASSWD}"
		chown root:www-data "${HTPASSWD}" 2>/dev/null || true
		chmod 0640 "${HTPASSWD}"
		sed -i "/^${username}:/d" "${HTPASSWD}" 2>/dev/null || true
		(echo -n "${username}:${REALM}:" && echo -n "${username}:${REALM}:${passwd}" | md5sum | awk '{print $1}') >>"${HTPASSWD}"
		rm -f /root/"${username}".info.db
		_save_config username "${username}"
		_save_config passwd "${passwd}"
		return 0
	fi

	echo ""
	echo " ╭──────────────────────────────────────────────────────────╮"
	echo " │ ${bold}${cyan}Administrator Account Setup${normal}                                │"
	echo " │──────────────────────────────────────────────────────────│"
	echo " │ Please enter a username for your master admin account.   │"
	echo " │ This user will have sudo privileges and access to the    │"
	echo " │ web dashboard.                                           │"
	echo " ╰──────────────────────────────────────────────────────────╯"
	while true; do
		echo -ne "   ${bold}${magenta}Username (Default: admin):${normal} "
		read -r user
		username=$(printf '%s' "${user:-admin}" | tr '[:upper:]' '[:lower:]')
		if [[ "${username}" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] && [[ "${username}" != "root" && "${username}" != "www-data" && "${username}" != "aetherflow" && "${username}" != "nobody" ]]; then
			break
		fi
		echo "   ${yellow}⚠ Invalid or reserved username. Use 1-32 lowercase alphanumeric/underscore/hyphen characters.${normal}"
	done
	if ! id "${username}" &>/dev/null; then
		/usr/sbin/useradd "${username}" -m -G www-data,sudo -s "${theshell}"
	else
		/usr/sbin/usermod -a -G www-data,sudo -s "${theshell}" "${username}" 2>/dev/null || true
	fi
	
	echo ""
	echo " ╭──────────────────────────────────────────────────────────╮"
	echo " │ ${bold}${cyan}Secure Password Configuration${normal}                              │"
	echo " │──────────────────────────────────────────────────────────│"
	echo " │ Type a strong password or press [ENTER] to autogenerate. │"
	echo " │ Security Requirements:                                   │"
	echo " │  • Minimum 8 characters in length                        │"
	echo " │  • Mix of uppercase, lowercase, and numbers              │"
	echo " ╰──────────────────────────────────────────────────────────╯"
	while true; do
		echo -ne "   ${bold}${magenta}Password:${normal} "
		read -rs password
		echo ""
		if [[ -z "${password}" ]]; then
			break
		elif [[ ${#password} -lt 8 ]]; then
			echo "   ${yellow}⚠ Password must be at least 8 characters long (or press [ENTER] to autogenerate).${normal}"
		else
			break
		fi
	done
	if [[ -n "${password}" ]]; then
		echo "   ${green}✓ Password manually provided.${normal}"
		passwd=${password}
		echo "${username}:${passwd}" | /usr/sbin/chpasswd >>"${OUTTO}" 2>&1
	else
		passwd=${genpass}
		echo "   ${green}✓ Password autogenerated:${normal} ${bold}${passwd}${normal}"
		echo "${username}:${passwd}" | /usr/sbin/chpasswd >>"${OUTTO}" 2>&1
	fi
	mkdir -p "$(dirname "${HTPASSWD}")"
	touch "${HTPASSWD}"
	chown root:www-data "${HTPASSWD}" 2>/dev/null || true
	chmod 0640 "${HTPASSWD}"
	sed -i "/^${username}:/d" "${HTPASSWD}" 2>/dev/null || true
	(echo -n "${username}:${REALM}:" && echo -n "${username}:${REALM}:${passwd}" | md5sum | awk '{print $1}') >>"${HTPASSWD}"
	rm -f /root/"${username}".info.db
	echo

	# Persist username and temporary passwd for resume (scrubbed once .master.creds is initialized)
	_save_config username "${username}"
	_save_config passwd "${passwd}"
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

	if [[ "${UNATTENDED:-false}" == "true" ]]; then
		ffmpeg="yes"
		echo
		_save_config ffmpeg "${ffmpeg}"
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
	DEFAULTIP=$(ip -4 addr show | grep -oP 'inet \K[0-9.]+' | grep -v '127.0.0.1' | head -1)
	if [[ "${UNATTENDED:-false}" == "true" ]]; then
		IP=${DEFAULTIP}
		echo "Unattended mode: using detected public IP ${IP}"
		echo
		_save_config IP "${IP}"
		return 0
	fi
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

	if [[ "${UNATTENDED:-false}" == "true" ]]; then
		bbr="yes"
		echo
		_save_config bbr "${bbr}"
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
