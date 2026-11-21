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
	case "${AETHERFLOW_ENABLE_FTPD:-no}" in
		1|true|TRUE|yes|YES|y|Y|on|ON) ;;
		*) return 0 ;;
	esac
	apt-get purge -y vsftpd pure-ftpd >>"${OUTTO}" 2>&1
	apt-get install -y vsftpd >>"${OUTTO}" 2>&1
}
