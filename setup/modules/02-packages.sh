#!/bin/bash
# Module: 02-packages.sh


# package and repo addition (silently add php7) _add respo sources_
# shellcheck disable=2312
function _repos() {
	if type _ensure_distro_vars &>/dev/null; then _ensure_distro_vars; fi
	# Fix #1: Gracefully handle broken / unsigned third-party APT lists.
	# Try a clean update first. If it fails, disable offending third-party
	# source lists (e.g., php.list, deb-multimedia.list) that Kali or other
	# Debian derivatives may ship, then retry.
	if ! DEBIAN_FRONTEND=noninteractive apt-get -yqq update >>"${OUTTO}" 2>&1; then
		echo "Initial apt-get update failed — disabling broken third-party lists and retrying..." >>"${OUTTO}" 2>&1
		for bad_list in /etc/apt/sources.list.d/php.list \
		               /etc/apt/sources.list.d/deb-multimedia.list; do
			if [[ -f "${bad_list}" ]]; then
				mv "${bad_list}" "${bad_list}.disabled" 2>>"${OUTTO}" || true
			fi
		done
		DEBIAN_FRONTEND=noninteractive apt-get -yqq \
			--allow-releaseinfo-change \
			update >>"${OUTTO}" 2>&1 || return 1
	fi
	if [[ ${DISTRO} == Ubuntu ]]; then
		_af_apt_install software-properties-common lsb-release sudo ca-certificates gnupg wget || return 1
		LC_ALL=en_US.UTF-8 apt-add-repository ppa:ondrej/php -y >>"${OUTTO}" 2>&1 || return 1
	elif [[ ${DISTRO} == Debian ]]; then
		_af_apt_install lsb-release sudo ca-certificates gnupg curl wget || return 1
		if [[ "${OS_ID:-}" != "kali" && "${CODENAME:-}" != "kali-rolling" ]]; then
			local expected_sury_fpr="${AF_SURY_APT_FPR:-15058500A0235D97F5D10063B188E2B695BD4743}"
			expected_sury_fpr="${expected_sury_fpr^^}"
			if [[ ! "${expected_sury_fpr}" =~ ^[0-9A-F]{40}$ ]]; then
				echo "[ERROR] Invalid AF_SURY_APT_FPR fingerprint: ${expected_sury_fpr}" >>"${OUTTO}" 2>&1
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
				echo "[ERROR] Failed to inspect Sury PHP APT signing key fingerprint." >>"${OUTTO}" 2>&1
				rm -rf "${sury_tmp_dir}"
				return 1
			}
			if [[ "${actual_sury_fpr}" != "${expected_sury_fpr}" ]]; then
				echo "[ERROR] Sury PHP APT key fingerprint mismatch (expected=${expected_sury_fpr}, actual=${actual_sury_fpr:-none})." >>"${OUTTO}" 2>&1
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
			install -d -m 0755 /usr/share/keyrings
			install -m 0644 "${sury_keyring_tmp}" /usr/share/keyrings/deb.sury.org-php.gpg || { rm -rf "${sury_tmp_dir}"; return 1; }
			rm -rf "${sury_tmp_dir}"
			echo "deb [signed-by=/usr/share/keyrings/deb.sury.org-php.gpg] https://packages.sury.org/php/ ${CODENAME} main" > /etc/apt/sources.list.d/php.list
			chmod 0644 /etc/apt/sources.list.d/php.list
		fi
	fi

}

# package and repo addition _update and upgrade_
# shellcheck disable=2312
function _updates() {
	if type _ensure_distro_vars &>/dev/null; then _ensure_distro_vars; fi
	if [[ ${DISTRO} == Debian ]]; then
		if [[ "${OS_ID:-}" != "kali" && "${CODENAME:-}" != "kali-rolling" && ! -f /etc/apt/sources.list.d/debian.sources ]]; then
			\cp -f "${local_setup}templates/apt.sources/debian.template" /etc/apt/sources.list
			sed -i "s/RELEASE/${CODENAME}/g" /etc/apt/sources.list
		fi
		DEBIAN_FRONTEND=noninteractive apt-get -yqq update >>"${OUTTO}" 2>&1 || return 1
		_af_apt_install build-essential debian-archive-keyring || return 1
	else
		if [[ ! -f /etc/apt/sources.list.d/ubuntu.sources ]]; then
			\cp -f "${local_setup}templates/apt.sources/ubuntu.template" /etc/apt/sources.list
			sed -i "s/RELEASE/${CODENAME}/g" /etc/apt/sources.list
		fi
		DEBIAN_FRONTEND=noninteractive apt-get -yqq update >>"${OUTTO}" 2>&1 || return 1
		_af_apt_install build-essential debian-archive-keyring software-properties-common || return 1
	fi

	export DEBIAN_FRONTEND=noninteractive
	apt-get -yqq update >>"${OUTTO}" 2>&1 || return 1
	apt-get -yqq purge samba samba-common >>"${OUTTO}" 2>&1 || true
	apt-get -yqq full-upgrade >>"${OUTTO}" 2>&1 || return 1

	# Create the service lock file directory
	if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
		install -d -m 0750 -o root -g "$(getent group aetherflow >/dev/null 2>&1 && echo aetherflow || echo root)" /install
	else
		mkdir -p /install
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
		_af_apt_install build-essential debian-archive-keyring fail2ban bc sudo screen zip irssi unzip nano bwm-ng htop iotop git dos2unix subversion "${stat_pkg}" automake make mktorrent libtool libcppunit-dev libssl-dev pkg-config libxml2-dev libcurl4-openssl-dev libsigc++-2.0-dev apache2-utils autoconf cron curl sqlite3 libapache2-mod-php"${PHP_VER}" libncurses-dev yasm pcre2-utils apache2 certbot python3-certbot-apache php-net-socket libdbd-mysql-perl libdbi-perl php-memcached memcached php"${PHP_VER}" php"${PHP_VER}"-cli php"${PHP_VER}"-curl php"${PHP_VER}"-fpm php"${PHP_VER}"-gd php"${PHP_VER}"-mbstring php"${PHP_VER}"-msgpack php"${PHP_VER}"-mysql php"${PHP_VER}"-opcache php"${PHP_VER}"-xml php"${PHP_VER}"-zip fontconfig comerr-dev ca-certificates libfontconfig1-dev libfontconfig1 mediainfo ifstat python3-lxml checkinstall dtach libarchive-zip-perl libnet-ssleay-perl libxslt1-dev libxml2 libffi-dev python3-pip python3-dev libhtml-parser-perl libxml-libxml-perl libjson-perl libjson-xs-perl libxml-libxslt-perl zlib1g-dev vnstat vnstati openvpn iptables iptables-persistent xz-utils || return 1
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
