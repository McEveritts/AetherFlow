#!/bin/bash
# Module: 02-packages.sh


# package and repo addition (silently add php7) _add respo sources_
# shellcheck disable=2312
function _repos() {
	if type _ensure_distro_vars &>/dev/null; then _ensure_distro_vars; fi
	local apt_etc_dir="${AF_APT_ETC_DIR:-/etc/apt}"
	local keyrings_dir="${AF_KEYRINGS_DIR:-/usr/share/keyrings}"
	local outto="${OUTTO:-/dev/null}"
	_af_ensure_apt_sources || return 1
	# Fix #1: Gracefully handle broken / unsigned third-party APT lists.
	# Try a clean update first. If it fails, disable offending third-party
	# source lists (e.g., php.list, deb-multimedia.list) that Kali or other
	# Debian derivatives may ship, then retry.
	if ! DEBIAN_FRONTEND=noninteractive apt-get -yqq update >>"${outto}" 2>&1; then
		echo "Initial apt-get update failed — disabling broken third-party lists and retrying..." >>"${outto}" 2>&1
		for bad_list in "${apt_etc_dir}/sources.list.d/php.list" \
		               "${apt_etc_dir}/sources.list.d/deb-multimedia.list"; do
			if [[ -f "${bad_list}" && ! -L "${bad_list}" ]]; then
				mv "${bad_list}" "${bad_list}.disabled" 2>>"${outto}" || true
			fi
		done
		DEBIAN_FRONTEND=noninteractive apt-get -yqq \
			--allow-releaseinfo-change \
			update >>"${outto}" 2>&1 || return 1
	fi
	if [[ ${DISTRO} == Ubuntu ]]; then
		_af_apt_install software-properties-common lsb-release sudo ca-certificates gnupg wget || return 1
		LC_ALL=en_US.UTF-8 apt-add-repository ppa:ondrej/php -y >>"${outto}" 2>&1 || return 1
	elif [[ ${DISTRO} == Debian ]]; then
		_af_apt_install lsb-release sudo ca-certificates gnupg curl wget || return 1
		if [[ "${OS_ID:-}" != "kali" && "${CODENAME:-}" != "kali-rolling" ]]; then
			local expected_sury_fpr="${AF_SURY_APT_FPR:-15058500A0235D97F5D10063B188E2B695BD4743}"
			expected_sury_fpr="${expected_sury_fpr^^}"
			if [[ ! "${expected_sury_fpr}" =~ ^[0-9A-F]{40}$ ]]; then
				echo "[ERROR] Invalid AF_SURY_APT_FPR fingerprint: ${expected_sury_fpr}" >>"${outto}" 2>&1
				return 1
			fi
			local sury_tmp_dir sury_gpg_raw sury_keyring_tmp sury_gnupg_home actual_sury_fpr
			sury_tmp_dir="$(umask 0077 && mktemp -d /var/tmp/aetherflow-sury-key.XXXXXXXXXX)" || return 1
			sury_gpg_raw="${sury_tmp_dir}/apt.gpg"
			sury_keyring_tmp="${sury_tmp_dir}/deb.sury.org-php.gpg"
			sury_gnupg_home="${sury_tmp_dir}/gnupg"
			install -d -m 0700 "${sury_gnupg_home}" || { rm -rf "${sury_tmp_dir}"; return 1; }
			if ! curl --proto '=https' --tlsv1.2 -fsSL "${AF_SURY_APT_GPG_URL:-https://packages.sury.org/php/apt.gpg}" -o "${sury_gpg_raw}"; then
				rm -rf "${sury_tmp_dir}"
				return 1
			fi
			actual_sury_fpr="$(
				GNUPGHOME="${sury_gnupg_home}" gpg --batch --with-colons --import-options show-only --import "${sury_gpg_raw}" 2>/dev/null | awk -F: '
					$1 == "pub" { pub_count++; in_pub = 1; next }
					$1 == "sub" { in_pub = 0; next }
					in_pub && $1 == "fpr" { print toupper($10); in_pub = 0 }
					END { if (pub_count != 1) exit 1 }
				'
			)" || {
				echo "[ERROR] Failed to inspect Sury PHP APT signing key fingerprint." >>"${outto}" 2>&1
				rm -rf "${sury_tmp_dir}"
				return 1
			}
			if [[ "${actual_sury_fpr}" != "${expected_sury_fpr}" ]]; then
				echo "[ERROR] Sury PHP APT key fingerprint mismatch (expected=${expected_sury_fpr}, actual=${actual_sury_fpr:-none})." >>"${outto}" 2>&1
				rm -rf "${sury_tmp_dir}"
				return 1
			fi
			if grep -q "BEGIN PGP PUBLIC KEY BLOCK" "${sury_gpg_raw}" 2>/dev/null; then
				if ! gpg --dearmor --batch --yes -o "${sury_keyring_tmp}" "${sury_gpg_raw}"; then
					rm -rf "${sury_tmp_dir}"
					return 1
				fi
			else
				cp -f "${sury_gpg_raw}" "${sury_keyring_tmp}" || { rm -rf "${sury_tmp_dir}"; return 1; }
			fi
			install -d -m 0755 "${keyrings_dir}" "${apt_etc_dir}/sources.list.d" || { rm -rf "${sury_tmp_dir}"; return 1; }
			install -m 0644 "${sury_keyring_tmp}" "${keyrings_dir}/deb.sury.org-php.gpg" || { rm -rf "${sury_tmp_dir}"; return 1; }
			rm -rf "${sury_tmp_dir}"
			echo "deb [signed-by=${keyrings_dir}/deb.sury.org-php.gpg] https://packages.sury.org/php/ ${CODENAME} main" > "${apt_etc_dir}/sources.list.d/php.list"
			chmod 0644 "${apt_etc_dir}/sources.list.d/php.list"
		fi
	fi

}

function _af_apt_arch() {
	local arch=""
	if [[ -n "${AF_APT_ARCH:-}" ]]; then
		arch="${AF_APT_ARCH}"
	elif command -v dpkg >/dev/null 2>&1; then
		arch="$(dpkg --print-architecture 2>/dev/null || true)"
	fi
	if [[ -z "${arch}" ]]; then
		case "$(uname -m 2>/dev/null || true)" in
			x86_64) arch="amd64" ;;
			aarch64|arm64) arch="arm64" ;;
			*) arch="$(uname -m 2>/dev/null || true)" ;;
		esac
	fi
	printf '%s' "${arch}"
}

function _af_apt_has_valid_base_sources() {
	local apt_etc_dir="$1" target_arch="$2" targets
	local -a apt_options=(-o Debug::NoLocking=1 -o "APT::Architecture=$target_arch")
	if [[ "$apt_etc_dir" != /etc/apt ]]; then
		apt_options+=(-o "Dir::Etc::sourcelist=$apt_etc_dir/sources.list" -o "Dir::Etc::sourceparts=$apt_etc_dir/sources.list.d")
	fi
	# APT expands both source formats, Enabled, and architecture filters without downloading.
	targets="$(LC_ALL=C apt-get "${apt_options[@]}" --print-uris update)" || return 2
	awk -v arch="$target_arch" '
		{
			uri = substr(tolower($1), 2)
			if (uri ~ /^cdrom:/) next
			sub("^https?://", "", uri)
			split(uri, parts, "/")
			if (parts[1] ~ /^(packages[.]sury[.]org|ppa[.]launchpad(content)?[.]net|(www[.])?deb-multimedia[.]org)$/) next
			if ($2 ~ ("_binary-" arch "_Packages$") || ($2 !~ /_binary-/ && $2 ~ /_Packages$/)) found = 1
		}
		END { exit !found }
	' <<< "$targets"
}

function _af_resolve_distro_keyring() {
	local keyrings_dir="${AF_KEYRINGS_DIR:-/usr/share/keyrings}"
	local candidate=""
	local -a candidates=()

	if [[ "${DISTRO:-}" == "Ubuntu" ]]; then
		candidates=(
			"${keyrings_dir}/ubuntu-archive-keyring.gpg"
			"${keyrings_dir}/ubuntu-archive-keyring.pgp"
		)
	elif [[ "${DISTRO:-}" == "Debian" ]]; then
		if [[ "${OS_ID:-}" == "kali" || "${CODENAME:-}" == "kali-rolling" ]]; then
			candidates=(
				"${keyrings_dir}/kali-archive-keyring.gpg"
				"${keyrings_dir}/kali-archive-keyring.pgp"
			)
		else
			candidates=(
				"${keyrings_dir}/debian-archive-keyring.gpg"
				"${keyrings_dir}/debian-archive-keyring.pgp"
			)
		fi
	else
		return 1
	fi

	for candidate in "${candidates[@]}"; do
		if [[ -r "${candidate}" && -s "${candidate}" ]]; then
			printf '%s' "${candidate}"
			return 0
		fi
	done
	return 1
}

function _af_distro_keyring_package() {
	if [[ "${DISTRO:-}" == "Ubuntu" ]]; then
		printf '%s' "ubuntu-keyring"
		return 0
	elif [[ "${DISTRO:-}" == "Debian" ]]; then
		if [[ "${OS_ID:-}" == "kali" || "${CODENAME:-}" == "kali-rolling" ]]; then
			printf '%s' "kali-archive-keyring"
		else
			printf '%s' "debian-archive-keyring"
		fi
		return 0
	fi
	return 1
}

function _af_ensure_apt_sources() {
	local apt_etc_dir="${AF_APT_ETC_DIR:-/etc/apt}"
	local outto="${OUTTO:-/dev/null}"
	local arch=""
	local keyring_path=""
	local template_file=""
	local setup_dir="${local_setup:-}"

	if [[ -z "${setup_dir}" ]]; then
		setup_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/"
	fi

	if [[ "${DISTRO:-}" != "Debian" && "${DISTRO:-}" != "Ubuntu" ]]; then
		echo "[ERROR] Refusing APT source configuration for unsupported distribution '${DISTRO:-unknown}'." >>"${outto}" 2>&1
		return 1
	fi

	arch="$(_af_apt_arch)"

	# Leave vendor and operator source files in place.
	if _af_apt_has_valid_base_sources "${apt_etc_dir}" "${arch}" 2>>"${outto}"; then
		return 0
	elif [[ $? -eq 2 ]]; then
		echo "[ERROR] APT could not parse the configured source files." >>"${outto}"
		return 1
	fi

	# Missing base APT sources: generate signed architecture defaults only for supported platforms.
	if [[ "${OS_ID:-}" == "kali" || "${CODENAME:-}" == "kali-rolling" ]]; then
		echo "[ERROR] No valid base APT sources found for Kali Linux; refusing to synthesize Debian defaults." >>"${outto}" 2>&1
		return 1
	fi

	if [[ ! "${CODENAME:-}" =~ ^[a-z][a-z0-9._-]*$ ]]; then
		echo "[ERROR] Refusing to generate default APT sources with invalid codename '${CODENAME:-}'." >>"${outto}" 2>&1
		return 1
	fi

	case "${DISTRO}:${arch}" in
		Debian:amd64|Debian:arm64)
			template_file="${setup_dir}templates/apt.sources/debian.template"
			;;
		Ubuntu:amd64)
			template_file="${setup_dir}templates/apt.sources/ubuntu.template"
			;;
		Ubuntu:arm64)
			template_file="${setup_dir}templates/apt.sources/ubuntu-ports.template"
			;;
		*)
			echo "[ERROR] Unsupported architecture '${arch:-unknown}' for default ${DISTRO} APT source generation." >>"${outto}" 2>&1
			return 1
			;;
	esac

	if [[ ! -f "${template_file}" || ! -r "${template_file}" ]]; then
		echo "[ERROR] Missing APT source template: ${template_file}" >>"${outto}" 2>&1
		return 1
	fi

	if ! keyring_path="$(_af_resolve_distro_keyring)"; then
		echo "[ERROR] Missing official release signing keyring for ${DISTRO}; refusing unsigned APT source configuration." >>"${outto}" 2>&1
		return 1
	fi

	local source_dir="${apt_etc_dir}/sources.list.d"
	local managed_list="$source_dir/aetherflow-base.list"
	if [[ -L "${apt_etc_dir}" || -L "${apt_etc_dir}/sources.list" || -L "$source_dir" || -e "$managed_list" || -L "$managed_list" ]]; then
		echo "[ERROR] Refusing unsafe symlinked APT sources path under ${apt_etc_dir}." >>"${outto}" 2>&1
		return 1
	fi

	install -d -m 0755 "$source_dir" || return 1
	local tmp_sources=""
	local keyring_esc="${keyring_path//\\/\\\\}"
	keyring_esc="${keyring_esc//&/\\&}"
	tmp_sources="$(mktemp "$source_dir/.aetherflow-base.XXXXXX")" || return 1
	if ! awk -v release="${CODENAME}" -v keyring="${keyring_esc}" '
		{
			gsub(/RELEASE/, release)
			gsub(/\/usr\/share\/keyrings\/(debian|ubuntu)-archive-keyring\.gpg/, keyring)
			print
		}
	' "${template_file}" > "${tmp_sources}" || ! chmod 0644 "${tmp_sources}" || ! ln -T -- "$tmp_sources" "$managed_list"; then
		rm -f -- "${tmp_sources}"
		return 1
	fi

	rm -f -- "$tmp_sources"
	echo "[INFO] Wrote signed default ${DISTRO} (${arch}) APT sources for '${CODENAME}' using ${keyring_path}." >>"${outto}" 2>&1
	return 0
}

# package and repo addition _update and upgrade_
# shellcheck disable=2312
function _updates() {
	if type _ensure_distro_vars &>/dev/null; then _ensure_distro_vars; fi
	local outto="${OUTTO:-/dev/null}"
	local install_dir="${AF_INSTALL_DIR:-/install}"
	local keyring_pkg=""

	_af_ensure_apt_sources || return 1
	keyring_pkg="$(_af_distro_keyring_package)" || {
		echo "[ERROR] Unable to determine archive keyring package for distribution '${DISTRO:-unknown}'." >>"${outto}" 2>&1
		return 1
	}

	if [[ "${DISTRO}" == "Debian" ]]; then
		DEBIAN_FRONTEND=noninteractive apt-get -yqq update >>"${outto}" 2>&1 || return 1
		_af_apt_install build-essential "${keyring_pkg}" || return 1
	elif [[ "${DISTRO}" == "Ubuntu" ]]; then
		DEBIAN_FRONTEND=noninteractive apt-get -yqq update >>"${outto}" 2>&1 || return 1
		_af_apt_install build-essential "${keyring_pkg}" software-properties-common || return 1
	else
		echo "[ERROR] Unsupported distribution '${DISTRO:-unknown}' in _updates." >>"${outto}" 2>&1
		return 1
	fi

	export DEBIAN_FRONTEND=noninteractive
	apt-get -yqq update >>"${outto}" 2>&1 || return 1
	apt-get -yqq purge samba samba-common >>"${outto}" 2>&1 || true
	apt-get -yqq full-upgrade >>"${outto}" 2>&1 || return 1

	# Create the service lock file directory
	if [[ "${EUID:-$(id -u)}" -eq 0 && "${install_dir}" == "/install" ]]; then
		install -d -m 0750 -o root -g "$(getent group aetherflow >/dev/null 2>&1 && echo aetherflow || echo root)" "${install_dir}"
	else
		mkdir -p "${install_dir}"
	fi

}

# package and repo addition _install softwares and packages_
# shellcheck disable=2312
function _depends() {
	if type _ensure_distro_vars &>/dev/null; then _ensure_distro_vars; fi
	if [[ ${DISTRO} == Debian ]]; then
		_af_apt_install fail2ban bc build-essential ed sudo screen zip irssi unzip nano bwm-ng htop nethogs iotop git dos2unix subversion automake make mktorrent libtool libcppunit-dev libssl-dev pkg-config libxml2-dev libcurl4-openssl-dev libsigc++-2.0-dev apache2-utils autoconf cron curl sqlite3 libapache2-mod-fcgid libapache2-mod-php"${PHP_VER}" libncurses-dev yasm pcre2-utils apache2 certbot python3-certbot-apache php-net-socket php-memcached memcached php"${PHP_VER}" php"${PHP_VER}"-cli php"${PHP_VER}"-curl php"${PHP_VER}"-fpm php"${PHP_VER}"-gd php"${PHP_VER}"-mbstring php"${PHP_VER}"-msgpack php"${PHP_VER}"-mysql php"${PHP_VER}"-opcache php"${PHP_VER}"-xml php"${PHP_VER}"-zip python3-lxml fontconfig comerr-dev ca-certificates libfontconfig1-dev libdbd-mysql-perl libdbi-perl libfontconfig1 mediainfo ifstat checkinstall dtach libarchive-zip-perl libnet-ssleay-perl ca-certificates-java libxslt1-dev libxml2 libffi-dev python3-pip python3-dev libhtml-parser-perl libxml-libxml-perl libjson-perl libjson-xs-perl libxml-libxslt-perl zlib1g-dev vnstat vnstati openvpn iptables iptables-persistent xz-utils || return 1
		for opt_pkg in clang mold dool dstat speedtest-cli rar unrar ttf-mscorefonts-installer; do
			_af_apt_install "${opt_pkg}" >>"${OUTTO}" 2>&1 || true
		done
	elif [[ ${DISTRO} == Ubuntu ]]; then
		local stat_pkg="dstat"
		if [[ "${CODENAME}" =~ ("noble") ]] || ! apt-cache show dstat >/dev/null 2>&1; then
			stat_pkg="dool"
		fi
		_af_apt_install build-essential ubuntu-keyring fail2ban bc sudo screen zip irssi unzip nano bwm-ng htop iotop git dos2unix subversion "${stat_pkg}" automake make mktorrent libtool libcppunit-dev libssl-dev pkg-config libxml2-dev libcurl4-openssl-dev libsigc++-2.0-dev apache2-utils autoconf cron curl sqlite3 libapache2-mod-php"${PHP_VER}" libncurses-dev yasm pcre2-utils apache2 certbot python3-certbot-apache php-net-socket libdbd-mysql-perl libdbi-perl php-memcached memcached php"${PHP_VER}" php"${PHP_VER}"-cli php"${PHP_VER}"-curl php"${PHP_VER}"-fpm php"${PHP_VER}"-gd php"${PHP_VER}"-mbstring php"${PHP_VER}"-msgpack php"${PHP_VER}"-mysql php"${PHP_VER}"-opcache php"${PHP_VER}"-xml php"${PHP_VER}"-zip fontconfig comerr-dev ca-certificates libfontconfig1-dev libfontconfig1 mediainfo ifstat python3-lxml checkinstall dtach libarchive-zip-perl libnet-ssleay-perl libxslt1-dev libxml2 libffi-dev python3-pip python3-dev libhtml-parser-perl libxml-libxml-perl libjson-perl libjson-xs-perl libxml-libxslt-perl zlib1g-dev vnstat vnstati openvpn iptables iptables-persistent xz-utils || return 1
		local avail_opt_pkgs=()
		if apt-cache show default-jre-headless >/dev/null 2>&1; then
			avail_opt_pkgs+=("default-jre-headless")
		elif apt-cache show openjdk-8-jre-headless >/dev/null 2>&1; then
			avail_opt_pkgs+=("openjdk-8-jre-headless")
		fi
		for opt_pkg in clang mold rar unrar ttf-mscorefonts-installer; do
			if apt-cache show "${opt_pkg}" >/dev/null 2>&1; then
				avail_opt_pkgs+=("${opt_pkg}")
			fi
		done
		if (( ${#avail_opt_pkgs[@]} > 0 )); then
			_af_apt_install "${avail_opt_pkgs[@]}" >>"${OUTTO}" 2>&1 || {
				for opt_pkg in "${avail_opt_pkgs[@]}"; do
					_af_apt_install "${opt_pkg}" >>"${OUTTO}" 2>&1 || true
				done
			}
		fi
	fi
}

# Pre-processing scripts,  giving permissions
# shellcheck disable=2312
function _syscommands() {
	mkdir -p /usr/local/bin/AetherFlow
	\cp -rf "${local_packages}/." /usr/local/bin/AetherFlow
	find /usr/local/bin/AetherFlow -type f -print0 | xargs -0 dos2unix >>"${OUTTO}" 2>&1
	find /usr/local/bin/AetherFlow -type f -print0 | xargs -0 chmod +x >>"${OUTTO}" 2>&1
	\cp -f /usr/local/bin/AetherFlow/system/reload /usr/bin/reload
	rm -f /usr/bin/af-heal /usr/local/bin/AetherFlow/system/af-heal
	\cp -f /usr/local/bin/AetherFlow/system/af-systemd-sandbox /usr/bin/af-systemd-sandbox
	\cp -f /usr/local/bin/AetherFlow/system/af-certbot-sync /usr/local/bin/af-certbot-sync
	\cp -f /usr/local/bin/AetherFlow/system/af-certbot-sync /usr/bin/af-certbot-sync
	rm -f /usr/local/bin/af /usr/bin/af
	cat > /usr/local/bin/af <<'EOF'
#!/bin/bash
if [[ "${1:-}" == "--tui" ]]; then
	shift
	exec /usr/local/bin/AetherFlow/system/af "$@"
fi
if [[ $# -eq 0 && -t 0 && -t 1 && -x /usr/local/bin/AetherFlow/system/af ]]; then
	exec /usr/local/bin/AetherFlow/system/af
fi
for candidate in /opt/AetherFlow/current/af /opt/AetherFlow/current/bin/af /opt/AetherFlow/backend-rs/target/release/af; do
	if [[ -x "${candidate}" ]]; then
		exec "${candidate}" "$@"
	fi
done
exec /usr/local/bin/AetherFlow/system/af "$@"
EOF
	chmod 0755 /usr/local/bin/af
	ln -sf /usr/local/bin/af /usr/bin/af
	cat > /usr/local/bin/aetherflow <<'EOF'
#!/bin/bash
case "${1:-}" in
	logs)
		shift
		exec journalctl -u aetherflow-api -u aetherflow-runner -f "$@"
		;;
	restart)
		shift
		exec systemctl restart aetherflow-runner aetherflow-api "$@"
		;;
	status)
		shift
		if [[ $# -eq 0 && -x /opt/AetherFlow/current/bin/af ]]; then
			exec /opt/AetherFlow/current/bin/af status
		elif [[ $# -eq 0 && -x /opt/AetherFlow/current/af ]]; then
			exec /opt/AetherFlow/current/af status
		fi
		exec systemctl status aetherflow-api aetherflow-runner "$@"
		;;
	*)
		exec /usr/local/bin/af "$@"
		;;
esac
EOF
	chmod 0755 /usr/local/bin/aetherflow
	ln -sf /usr/local/bin/aetherflow /usr/bin/aetherflow
}

# install skel template
function _skel() {
	if [[ -d /etc/skel ]]; then rm -r /etc/skel; fi
	mkdir -p /etc/skel
	\cp -rf "${local_setup}templates/skel/." /etc/skel
	_af_apt_install libdigest-sha-perl >>"${OUTTO}" 2>&1 || true
	cd /root || true
}



# install function for ffmpeg via verified APT packages
# shellcheck disable=2215,2312,2250
function _ffmpeg() {
	if [[ ${ffmpeg} == "yes" ]]; then
		apt-get -qy update >>"${OUTTO}" 2>&1
		if _af_apt_install ffmpeg; then
			if command -v ffmpeg >/dev/null 2>&1; then
				mkdir -p /usr/local/bin
				[[ -x /usr/bin/ffmpeg && ! -e /usr/local/bin/ffmpeg ]] && ln -sf /usr/bin/ffmpeg /usr/local/bin/ffmpeg
				[[ -x /usr/bin/ffprobe && ! -e /usr/local/bin/ffprobe ]] && ln -sf /usr/bin/ffprobe /usr/local/bin/ffprobe
				return 0
			fi
		fi
		echo "[ERROR] Failed to install verified ffmpeg APT package; refusing unverified source build." >>"${OUTTO}" 2>&1
		return 1
	fi
}
