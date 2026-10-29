#!/bin/bash
# Module: 03-services.sh

# NOTE: Torrent client installation functions (_xmlrpc, _libtorrent, _rtorrent,
#       _insTr, _insTrWeb, _insTrApache, _qbittorrent, _insqBApache, _rconf,
#       _autodl) removed — torrent client provisioning is deferred to the
#       AetherFlow Marketplace.

# NOTE: _rutorrent and _rutorrent-plugins functions removed — ruTorrent integration sunset

# NOTE: _dashboard and _fileindexer functions removed — legacy PHP dashboard sunset
# The Next.js frontend now serves as the primary UI

# function to make dirs for first user
function _makedirs() {
	\cp -rf /etc/skel/. /home/"${username}"
	chown -R "${username}".www-data /home/"${username}" >>"${OUTTO}" 2>&1
	/usr/sbin/usermod -a -G www-data "${username}" >>"${OUTTO}" 2>&1
	/usr/sbin/usermod -a -G "${username}" www-data >>"${OUTTO}" 2>&1
}

# NOTE: _ruconf function removed — ruTorrent user config sunset

# function to install vsftpd
function _installftpd() {
	apt-get purge -y vsftpd pure-ftpd >>"${OUTTO}" 2>&1
	apt-get autoremove >>"${OUTTO}" 2>&1
	apt-get install -y vsftpd >>"${OUTTO}" 2>&1
}
