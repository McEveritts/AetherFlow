#!/bin/bash
# Module: 03-services.sh

# NOTE: Torrent client installation functions (_xmlrpc, _libtorrent, _rtorrent,
#       _insTr, _insTrWeb, _insTrApache, _qbittorrent, _insqBApache, _rconf,
#       _autodl) removed — torrent client provisioning is deferred to the
#       AetherFlow Marketplace.

# NOTE: _rutorrent and _rutorrent-plugins functions removed — ruTorrent integration sunset

# NOTE: _dashboard and _fileindexer functions removed — legacy PHP dashboard sunset
# The Leptos Rust WASM dashboard served by aetherflow-api is the primary UI

# Add application directories to the account already created by useradd.
function _makedirs() {
	local user_home="/home/${username}"
	runuser -u "${username}" -- mkdir -p -m 0750 -- \
		"$user_home"/{.sessions,Media,rwatch,torrents,torrents/{rtorrent,deluge,qbittorrent}}
}

# NOTE: _ruconf function removed — ruTorrent user config sunset

# function to install vsftpd (explicit opt-in via AETHERFLOW_ENABLE_FTPD=yes)
function _installftpd() {
	local ftpd_flag="${AETHERFLOW_ENABLE_FTPD:-no}"
	case "${ftpd_flag,,}" in
		1|true|yes|y|on) ;;
		*) return 0 ;;
	esac
	local outto="${OUTTO:-/dev/null}"
	DEBIAN_FRONTEND=noninteractive apt-get purge -y vsftpd pure-ftpd >>"${outto}" 2>&1 || true
	if type _af_apt_install &>/dev/null; then
		_af_apt_install vsftpd || return 1
	else
		DEBIAN_FRONTEND=noninteractive apt-get -yqq install vsftpd >>"${outto}" 2>&1 || return 1
	fi
}
