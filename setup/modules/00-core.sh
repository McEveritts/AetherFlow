#!/bin/bash
# Module: 00-core.sh

function _string() { perl -le 'print map {(a..z,A..Z,0..9)[rand 62] } 0..pop' 15; }

function _version_ge() {
	[[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" == "$2" ]]
}

function _af_parallel_wait() {
	local exit_code=0
	local pid
	for pid in "$@"; do
		if ! wait "${pid}"; then
			exit_code=1
		fi
	done
	return "${exit_code}"
}

function _af_build_jobs() {
	local cpu_count=2
	if command -v nproc >/dev/null 2>&1; then
		cpu_count="$(nproc)"
	fi
	if [[ "${cpu_count}" -lt 2 ]]; then
		echo 1
		return
	fi
	echo $((cpu_count / 2))
}

AF_RUNTIME_CACHE_DIR="${AF_RUNTIME_CACHE_DIR:-/tmp/aetherflow-runtime-cache}"
AF_GO_VERSION="${AF_GO_VERSION:-1.25.0}"
AF_GO_ARCHIVE="${AF_RUNTIME_CACHE_DIR}/go${AF_GO_VERSION}.linux-amd64.tar.gz"
AF_GO_URL="${AF_GO_URL:-https://go.dev/dl/go${AF_GO_VERSION}.linux-amd64.tar.gz}"
AF_NODE_VERSION="${AF_NODE_VERSION:-20.18.0}"
AF_NODE_ARCHIVE="${AF_RUNTIME_CACHE_DIR}/node-v${AF_NODE_VERSION}-linux-x64.tar.xz"
AF_NODE_URL="${AF_NODE_URL:-https://nodejs.org/dist/v${AF_NODE_VERSION}/node-v${AF_NODE_VERSION}-linux-x64.tar.xz}"

function _af_truthy() {
	case "${1,,}" in
	1 | true | yes | y | on) return 0 ;;
	*) return 1 ;;
	esac
}

function _af_normalize_yes_no() {
	local value="${1:-}"
	local default_value="${2:-no}"

	if [[ -z "${value}" ]]; then
		printf '%s' "${default_value}"
		return 0
	fi

	if _af_truthy "${value}"; then
		printf '%s' "yes"
		return 0
	fi

	case "${value,,}" in
	0 | false | no | n | off) printf '%s' "no" ;;
	*) printf '%s' "${default_value}" ;;
	esac
}

function _af_apt_install() {
	local output="${OUTTO:-/dev/null}"
	DEBIAN_FRONTEND=noninteractive apt-get -yqq \
		-o Dpkg::Options::="--force-confdef" \
		-o Dpkg::Options::="--force-confold" \
		install "$@" >>"${output}" 2>&1
}

function _af_download() {
	local url="$1"
	local destination="$2"

	mkdir -p "$(dirname "${destination}")"
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 3 --output "${destination}" "${url}"
	else
		wget -qO "${destination}" "${url}"
	fi
}

function _af_prefetch_runtime_archives() {
	local pids=()

	mkdir -p "${AF_RUNTIME_CACHE_DIR}"

	if [[ ! -x /usr/local/go/bin/go ]] && [[ ! -s "${AF_GO_ARCHIVE}" ]]; then
		(_af_download "${AF_GO_URL}" "${AF_GO_ARCHIVE}") &
		pids+=("$!")
	fi

	if ! command -v node >/dev/null 2>&1 && [[ ! -s "${AF_NODE_ARCHIVE}" ]]; then
		(_af_download "${AF_NODE_URL}" "${AF_NODE_ARCHIVE}") &
		pids+=("$!")
	fi

	if [[ ${#pids[@]} -gt 0 ]]; then
		_af_parallel_wait "${pids[@]}" || return 1
	fi
}

function _af_cleanup_runtime_cache() {
	rm -rf "${AF_RUNTIME_CACHE_DIR}"
}
#################################################################################
# shellcheck disable=2005,2034,2120,2215,2164,2312

function _bashrc() {
	\cp -f "${local_setup}templates/bashrc.template" /root/.bashrc
	local profile="/root/.profile"
	if [[ ! -f "${profile}" ]]; then
		\cp -f "${local_setup}templates/profile.template" /root/.profile
	fi
}

# intro function (1)
# shellcheck disable=2005,2312
function _intro() {
	DISTRO=$(lsb_release -is)
	CODENAME=$(lsb_release -cs)
	SETNAME=$(lsb_release -rc)
	VERSION_ID=$(lsb_release -rs)
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
	if [[ "${DISTRO}" != "Ubuntu" && "${DISTRO}" != "Debian" ]]; then
		echo "${DISTRO}: ${alert} It looks like you are running ${DISTRO}, which is not supported by AetherFlow ${normal}"
		echo 'Exiting...'
		exit 1
	fi

	if [[ "${DISTRO}" == "Ubuntu" ]] && ! _version_ge "${VERSION_ID}" "20.04"; then
		echo "Unsupported Ubuntu release: ${SETNAME}."
		echo "AetherFlow requires Ubuntu 20.04 or newer."
		echo 'Exiting...'
		exit 1
	fi

	if [[ "${DISTRO}" == "Debian" ]] && ! _version_ge "${VERSION_ID}" "11"; then
		echo "Unsupported Debian release: ${SETNAME}."
		echo "AetherFlow requires Debian 11 or newer."
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
	_save_config PHP_VER "${PHP_VER}"
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
	local grsec
	local saved_kernel
	grsec="$(uname -a | grep -i grs || true)"
	if [[ -n ${grsec} ]]; then
		echo -e "Your server is currently running with kernel version: $(uname -r)"
		echo -e "Kernels with ${bold}grsec${normal} are not supported"
		saved_kernel="$(_load_config kernel)"
		if [[ -n "${saved_kernel}" ]]; then
			kernel="$(_af_normalize_yes_no "${saved_kernel}" "yes")"
			echo "Using saved preference: distribution_kernel=${kernel}"
		elif [[ "${UNATTENDED:-false}" == "true" ]]; then
			kernel="yes"
			echo "Unattended mode: installing the distribution kernel."
			_save_config kernel "${kernel}"
		else
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
			_save_config kernel "${kernel}"
		fi
		if [[ ${kernel} == no ]]; then
			echo "Installer will not continue. Exiting ... "
			exit 0
		fi
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
	local saved_outto
	saved_outto="$(_load_config OUTTO)"
	if [[ -n "${saved_outto}" ]]; then
		OUTTO="${saved_outto}"
		echo "${bold}Output is being sent to ${magenta}${OUTTO}${normal}"
	elif [[ "${UNATTENDED:-false}" == "true" ]]; then
		OUTTO="/root/AetherFlow.${PPID}.log"
		echo "${bold}Unattended mode: output is being sent to ${magenta}${OUTTO}${normal}"
		_save_config OUTTO "${OUTTO}"
	else
		echo -ne "${bold}${yellow}Do you wish to write to a log file?${normal} (Default: ${green}${bold}Y${normal}) "
		read -r input
		case ${input} in
		[yY] | [yY][Ee][Ss] | "")
			OUTTO="/root/AetherFlow.${PPID}.log"
			echo "${bold}Output is being sent to /root/AetherFlow.${magenta}${PPID}${normal}${bold}.log${normal}"
			;;
		[nN] | [nN][Oo])
			OUTTO="/dev/null"
			echo "${cyan}NO output will be logged${normal}"
			;;
		*)
			OUTTO="/root/AetherFlow.${PPID}.log"
			echo "${bold}Output is being sent to /root/AetherFlow.${magenta}${PPID}${normal}${bold}.log${normal}"
			;;
		esac

		_save_config OUTTO "${OUTTO}"
	fi

	if [[ ! -d /root/tmp ]]; then
		sed -i 's/noexec,//g' /etc/fstab
		mount -o remount /tmp >>"${OUTTO}" 2>&1
	fi
}

# setting system hostname function (5)
# shellcheck disable=2162
function _hostname() {
	local saved_hostname
	local requested_hostname
	saved_hostname="$(_load_config hostname_value)"
	if [[ -z "${saved_hostname}" ]]; then
		saved_hostname="$(_load_config domain)"
	fi

	if [[ -n "${saved_hostname}" ]]; then
		requested_hostname="${saved_hostname}"
	elif [[ "${UNATTENDED:-false}" == "true" ]]; then
		echo "Unattended mode: no hostname supplied, leaving the current hostname unchanged."
		echo
		return 0
	else
		echo ""
		echo " ╭──────────────────────────────────────────────────────────╮"
		echo " │ ${bold}${cyan}Server Domain / Hostname${normal}                                 │"
		echo " │──────────────────────────────────────────────────────────│"
		echo " │ Enter the Fully Qualified Domain Name (FQDN) to map      │"
		echo " │ to this server (e.g., box.example.com).                  │"
		echo " │ Or press [ENTER] to keep current hostname.               │"
		echo " ╰──────────────────────────────────────────────────────────╯"
		echo -ne "   ${bold}${magenta}Domain:${normal} "
		read -r requested_hostname
	fi

	if [[ -z "${requested_hostname}" ]]; then
		echo "   ${yellow}→ No hostname supplied, keeping current setting.${normal}"
	else
		hostname "${requested_hostname}"
		echo "${requested_hostname}" >/etc/hostname
		echo "127.0.0.1 ${requested_hostname}" >/etc/hosts
		_save_config hostname_value "${requested_hostname}"
		echo "   ${green}✓ Hostname successfully set to:${normal} ${bold}${requested_hostname}${normal}"
	fi
	echo ""
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
		_af_apt_install locales || return 1
		locale-gen >>"${OUTTO}" 2>&1
		export LANG="en_US.UTF-8"
		export LC_ALL="en_US.UTF-8"
		export LANGUAGE="en_US.UTF-8"
	fi
}
