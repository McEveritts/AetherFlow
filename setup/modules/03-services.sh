#!/bin/bash
# Module: 03-services.sh

# NOTE: Torrent client installation functions (_xmlrpc, _libtorrent, _rtorrent,
#       _insTr, _insTrWeb, _insTrApache, _qbittorrent, _insqBApache, _rconf,
#       _autodl) removed — torrent client provisioning is deferred to the
#       AetherFlow Marketplace.

# NOTE: _rutorrent and _rutorrent-plugins functions removed — ruTorrent integration sunset

# NOTE: _dashboard and _fileindexer functions removed — legacy PHP dashboard sunset
# The Leptos Rust WASM dashboard served by aetherflow-api is the primary UI

# function to make dirs for first user
function _makedirs() {
	\cp -rf /etc/skel/. /home/"${username}"
	chown -R "${username}:${username}" /home/"${username}" >>"${OUTTO}" 2>&1
}

# NOTE: _ruconf function removed — ruTorrent user config sunset

# function to install vsftpd (explicit opt-in via AETHERFLOW_ENABLE_FTPD=yes)
function _installftpd() {
	case "${AETHERFLOW_ENABLE_FTPD:-no}" in
		1|true|TRUE|yes|YES|y|Y|on|ON) ;;
		*) return 0 ;;
	esac
	apt-get purge -y vsftpd pure-ftpd >>"${OUTTO}" 2>&1
	apt-get autoremove >>"${OUTTO}" 2>&1
	apt-get install -y vsftpd >>"${OUTTO}" 2>&1
}
