"""Execute catalog lifecycle entry points with synthetic releases and isolated paths."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import threading
import unittest
from unittest import mock
import urllib.error
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from installer_test_helpers import common_functions


CATALOG_APPS = (
    "plex", "jellyfin", "emby", "sonarr", "radarr", "lidarr", "readarr", "prowlarr",
    "bazarr", "overseerr", "ombi", "maintainerr", "tautulli", "jackett", "flaresolverr",
    "navidrome", "threadfin", "qbittorrent", "deluge", "transmission", "sabnzbd", "nzbget",
    "flood", "autobrr", "qui", "nextcloud", "syncthing", "filebrowser", "wireguard",
    "tailscale", "pihole", "fail2ban", "vaultwarden", "grafana", "prometheus", "netdata",
    "uptimekuma", "homeassistant", "jellyseerr", "adguardhome", "rtorrent", "rutorrent",
    "rclone", "mergerfs", "cloudplow", "unpackerr", "autoscan", "recyclarr", "audiobookshelf",
    "kavita", "calibreweb", "librespeed", "thelounge", "znc", "scrutiny", "paperless-ngx",
    "n8n", "palate", "gitea", "organizr", "dispatcharr", "duplicati", "filebot", "listenarr",
    "notifiarr", "novnc", "kasmvnc", "mcvnc", "pyload", "quassel", "requestrr", "seedcross",
    "unmanic", "xrdp", "x2go", "piped", "invidious",
)
CATALOG = {entry["name"]: entry for entry in json.loads((ROOT / "config/packages.json").read_text())}
PORT_CONFIG_EXPECTATIONS = {
    "plex": (("commands.jsonl", r"http://127\.0\.0\.1:{port}/identity"),),
    "jellyfin": (("etc/jellyfin/network.xml", r"<InternalHttpPort>{port}</InternalHttpPort>"),),
    "emby": (("var/lib/emby/config/system.xml", r"<HttpServerPortNumber>{port}</HttpServerPortNumber>"),),
    "sonarr": (("var/lib/sonarr/config.xml", r"<Port>{port}</Port>"),),
    "radarr": (("var/lib/radarr/config.xml", r"<Port>{port}</Port>"),),
    "lidarr": (("var/lib/lidarr/config.xml", r"<Port>{port}</Port>"),),
    "readarr": (("var/lib/readarr/config.xml", r"<Port>{port}</Port>"),),
    "prowlarr": (("var/lib/prowlarr/config.xml", r"<Port>{port}</Port>"),),
    "bazarr": (("var/lib/bazarr/config/config.yaml", r"(?m)^\s*port:\s*{port}\s*$"),),
    "overseerr": (("etc/systemd/system/overseerr.service", r"(?m)^Environment=PORT={port}$"),),
    "ombi": (("etc/systemd/system/ombi.service", r"http://[^\s]+:{port}\b"),),
    "maintainerr": (("etc/systemd/system/af-maintainerr.service", r"(?m)^Environment=UI_PORT={port}$"),),
    "tautulli": (("var/lib/tautulli/config.ini", r"(?m)^http_port\s*=\s*{port}\s*$"),),
    "jackett": (("var/lib/jackett/Jackett/ServerConfig.json", r"\"Port\"\s*:\s*{port}\b"),),
    "flaresolverr": (("etc/systemd/system/flaresolverr.service", r"(?m)^Environment=PORT={port}$"),),
    "navidrome": (("var/lib/navidrome/navidrome.toml", r"(?m)^Port\s*=\s*{port}\s*$"),),
    "threadfin": (
        ("etc/systemd/system/threadfin.service", r"-port={port}\b"),
        ("etc/systemd/system/threadfin.service", r"-bind=(?:0\.0\.0\.0|127\.0\.0\.1)\b"),
    ),
    "qbittorrent": (("var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf", r"(?m)^WebUI\\Port\s*=\s*{port}\s*$"),),
    "deluge": (("var/lib/deluge/.config/deluge/web.conf", r"\"port\"\s*:\s*{port}\b"),),
    "transmission": (
        ("var/lib/transmission-daemon/.config/transmission-daemon/settings.json", r"\"rpc-port\"\s*:\s*{port}\b"),
        ("var/lib/transmission-daemon/.config/transmission-daemon/settings.json", r"\"rpc-bind-address\"\s*:\s*\"(?:0\.0\.0\.0|127\.0\.0\.1)\""),
        ("var/lib/transmission-daemon/.config/transmission-daemon/settings.json", r"\"rpc-host-whitelist-enabled\"\s*:\s*(?:true|false)"),
        ("var/lib/transmission-daemon/.config/transmission-daemon/settings.json", r"\"rpc-whitelist-enabled\"\s*:\s*(?:true|false)"),
        ("var/lib/transmission-daemon/.config/transmission-daemon/settings.json", r"\"rpc-whitelist\"\s*:\s*\"[^\"]*127\.0\.0\.1[^\"]*\""),
    ),
    "sabnzbd": (("var/lib/sabnzbd/sabnzbd.ini", r"(?m)^port\s*=\s*{port}\s*$"),),
    "nzbget": (("var/lib/nzbget/nzbget.conf", r"(?m)^ControlPort\s*=\s*{port}\s*$"),),
    "flood": (("etc/systemd/system/flood.service", r"--port {port}\b"),),
    "autobrr": (("var/lib/autobrr/config.toml", r"(?m)^port\s*=\s*{port}\s*$"),),
    "qui": (("var/lib/qui/config.toml", r"(?m)^port\s*=\s*{port}\s*$"),),
    "nextcloud": (("etc/apache2/conf-available/aetherflow-nextcloud-listen.conf", r"(?m)^Listen {port}$"),),
    "syncthing": (("etc/systemd/system/syncthing.service", r"--gui-address=(?:0\.0\.0\.0|127\.0\.0\.1):{port}\b"),),
    "filebrowser": (("commands.jsonl", r"\"config\", \"set\"[^\n]*\"--address\", \"(?:0\.0\.0\.0|127\.0\.0\.1)\"[^\n]*\"--port\", \"{port}\"(?:[^\n]*\"--minimum-password-length\", \"(?:1|12)\")?"),),
    "wireguard": (("etc/wireguard/wg0.conf", r"(?m)^ListenPort\s*=\s*51820\s*$"),),
    "tailscale": (("etc/sysctl.d/99-tailscale.conf", r"(?m)^net\.ipv4\.ip_forward=1$"),),
    "pihole": (("etc/lighttpd/external.conf", r"server\.port\s*:?=\s*{port}\b"),),
    "fail2ban": (("etc/fail2ban/jail.d/10-aetherflow.local", r"(?ms)\[sshd\].*?enabled\s*=\s*true"),),
    "vaultwarden": (
        ("etc/vaultwarden/vaultwarden.env", r"(?m)^ROCKET_PORT={port}$"),
        ("etc/vaultwarden/vaultwarden.env", r"(?m)^ROCKET_ADDRESS=(?:0\.0\.0\.0|127\.0\.0\.1)$"),
    ),
    "grafana": (("etc/grafana/grafana.ini", r"(?m)^http_port\s*=\s*{port}\s*$"),),
    "prometheus": (("etc/systemd/system/prometheus.service", r"--web\.listen-address=(?:0\.0\.0\.0|127\.0\.0\.1):{port}\b"),),
    "netdata": (("etc/netdata/netdata.conf", r"(?m)^\s*default port\s*=\s*{port}\s*$"),),
    "uptimekuma": (("etc/systemd/system/uptime-kuma.service", r"(?m)^Environment=UPTIME_KUMA_PORT={port}$"),),
    "homeassistant": (("home/homeassistant/.homeassistant/configuration.yaml", r"(?m)^\s*server_port:\s*{port}\s*$"),),
    "jellyseerr": (("etc/systemd/system/jellyseerr.service", r"(?m)^Environment=PORT={port}$"),),
    "adguardhome": (("opt/AdGuardHome/AdGuardHome.yaml", r"address:\s*127\.0\.0\.1:{port}\b"),),
    "rtorrent": (("etc/systemd/system/rtorrent.service", r"rtorrent -n -o import=[^\n]*/var/lib/rtorrent/\.rtorrent\.rc"),),
    "rutorrent": (("etc/apache2/sites-available/rutorrent.conf", r"<VirtualHost \*:{port}>"),),
    "rclone": (("etc/systemd/system/rclone.service", r"--rc-addr=(?:0\.0\.0\.0|127\.0\.0\.1):{port}\b"),),
    "mergerfs": (("etc/systemd/system/mergerfs.service", r"mergerfs -o defaults,allow_other,use_ino,category\.create=epmfs"),),
    "cloudplow": (("etc/systemd/system/cloudplow.service", r"cloudplow/cloudplow\.py run"),),
    "unpackerr": (("etc/systemd/system/unpackerr.service", r"unpackerr --config [^\n]*/etc/unpackerr/unpackerr\.conf"),),
    "autoscan": (("etc/autoscan/config.yml", r"(?m)^port:\s*{port}\s*$"),),
    "recyclarr": (("etc/systemd/system/recyclarr.timer", r"(?m)^OnCalendar=\*-\*-\* 04:00:00$"), ("etc/systemd/system/recyclarr.service", r"recyclarr sync --config [^\n]*/var/lib/recyclarr/recyclarr\.yml")),
    "audiobookshelf": (("etc/systemd/system/audiobookshelf.service", r"(?:PORT=|--port[= ]){port}\b"),),
    "kavita": (("etc/systemd/system/kavita.service", r"http://[^\s]+:{port}\b"),),
    "calibreweb": (("etc/systemd/system/calibreweb.service", r"(?m)^Environment=CALIBRE_PORT={port}$"),),
    "librespeed": (("opt/librespeed/settings.toml", r"(?m)^\s*listen_port\s*=\s*{port}\s*$"),),
    "thelounge": (("var/lib/thelounge/config.js", r"(?m)^\s*port:\s*{port}\b"),),
    "znc": (("var/lib/znc/configs/znc.conf", r"(?m)^\s*Port\s*=\s*{port}\s*$"),),
    "scrutiny": (("etc/scrutiny/scrutiny.yaml", r"(?m)^\s*port:\s*{port}\s*$"),),
    "paperless-ngx": (("etc/systemd/system/paperless-webserver.service", r"gunicorn -b 127\.0\.0\.1:{port}\b"),),
    "n8n": (("etc/systemd/system/n8n.service", r"(?m)^Environment=N8N_PORT={port}$"),),
    "palate": (("etc/palate/palate.env", r"(?m)^PORT={port}$"),),
    "gitea": (("etc/gitea/app.ini", r"(?m)^HTTP_PORT\s*=\s*{port}\s*$"),),
    "organizr": (("etc/apache2/conf-available/aetherflow-organizr-listen.conf", r"(?m)^Listen {port}$"),),
    "dispatcharr": (("etc/dispatcharr/dispatcharr.env", r"(?m)^DISPATCHARR_PORT={port}$"),),
    "duplicati": (("etc/duplicati/duplicati.env", r"(?m)^DUPLICATI_PORT={port}$"),),
    "filebot": (("var/lib/filebot/filebot-node.env", r"(?m)^FILEBOT_NODE_HTTP_PORT={port}$"),),
    "listenarr": (("etc/systemd/system/listenarr.service", r"http://[^\s]+:{port}\b"),),
    "notifiarr": (("etc/notifiarr/notifiarr.conf", r"bind_addr\s*=\s*\"[^\"]*:{port}\""),),
    "novnc": (("etc/systemd/system/novnc.service", r"(?:0\.0\.0\.0|127\.0\.0\.1):{port} 127\.0\.0\.1:5901"),),
    "kasmvnc": (("var/lib/kasmvnc/.vnc/kasmvnc.yaml", r"(?m)^\s*websocket_port:\s*{port}\s*$"),),
    "mcvnc": (("etc/mcvnc/mcvnc.env", r"(?m)^MCVNC_BIND=127\.0\.0\.1:{port}$"),),
    "pyload": (("var/lib/pyload/settings/pyload.cfg", r"(?m)^\s*int port\s*:\s*\"Port\"\s*=\s*{port}\s*$"),),
    "quassel": (("etc/default/quasselcore", r"(?m)^PORT\s*=\s*\"4242\"$"),),
    "requestrr": (("etc/systemd/system/requestrr.service", r"http://[^\s]+:{port}\b"),),
    "seedcross": (("opt/seedcross/start-seedcross.sh", r"--bind 127\.0\.0\.1:{port}\b"),),
    "unmanic": (("var/lib/unmanic/.unmanic/config/settings.json", r"\"ui_port\"\s*:\s*{port}\b"),),
    "xrdp": (("etc/xrdp/startwm.sh", r"(?m)^exec dbus-run-session -- startxfce4$"),),
    "x2go": (("commands.jsonl", r"\"systemctl\", \"enable\", \"--now\", \"x2goserver\.service\""),),
    "piped": (("etc/piped/httpd.conf", r"(?m)^Listen 127\.0\.0\.1:{port}$"),),
    "invidious": (("etc/invidious/config.yml", r"(?m)^port:\s*{port}\s*$"),),
}

VERSION_RECEIPT_EXPECTATIONS = {
    "plex": ("var/lib/plexmediaserver/.af-version",), "jellyfin": ("var/lib/jellyfin/.af-version",),
    "emby": ("opt/emby-server/.af-version",), "sonarr": ("opt/Sonarr/.af-version",),
    "radarr": ("opt/Radarr/.af-version",), "lidarr": ("opt/Lidarr/.af-version",),
    "readarr": ("opt/Readarr/.af-version",), "prowlarr": ("opt/Prowlarr/.af-version",),
    "bazarr": ("opt/bazarr/.af-version",), "overseerr": ("opt/overseerr/.af-version",),
    "ombi": ("opt/Ombi/.af-version",), "maintainerr": ("opt/maintainerr/.af-version",),
    "tautulli": ("opt/Tautulli/.af-version",), "jackett": ("opt/Jackett/.af-version",),
    "flaresolverr": ("opt/flaresolverr/.af-version",), "navidrome": ("opt/navidrome/.af-version",),
    "threadfin": ("var/lib/threadfin/.af-version",), "qbittorrent": ("var/lib/qbittorrent/.af-version",),
    "deluge": ("var/lib/deluge/.af-version",), "transmission": ("var/lib/transmission-daemon/.af-version",),
    "sabnzbd": ("opt/SABnzbd/.af-version",), "nzbget": ("opt/nzbget/.af-version",),
    "flood": ("var/lib/flood/.af-version",), "autobrr": ("var/lib/autobrr/.af-version",),
    "qui": ("var/lib/qui/.af-version",), "nextcloud": ("var/www/nextcloud/.af-version",),
    "syncthing": ("var/lib/syncthing/.af-version",), "filebrowser": ("opt/filebrowser/.af-version",),
    "wireguard": ("etc/wireguard/.af-version",), "tailscale": ("var/lib/tailscale/.af-version",),
    "pihole": ("etc/pihole/.af-version",), "fail2ban": ("etc/fail2ban/.af-version",),
    "vaultwarden": ("opt/vaultwarden/.af-version",), "grafana": ("var/lib/grafana/.af-version",),
    "prometheus": ("etc/prometheus/.af-version",), "netdata": ("etc/netdata/.af-version",),
    "uptimekuma": ("opt/uptime-kuma/.af-version",), "homeassistant": ("srv/homeassistant/.af-version",),
    "jellyseerr": ("opt/jellyseerr/.af-version",), "adguardhome": ("opt/AdGuardHome/.af-version",),
    "rtorrent": ("var/lib/rtorrent/.af-version",), "rutorrent": ("var/www/rutorrent/.af-version",),
    "rclone": ("var/lib/rclone/.af-version",), "mergerfs": ("var/lib/mergerfs/.af-version",),
    "cloudplow": ("opt/cloudplow/.af-version",), "unpackerr": ("opt/unpackerr/.af-version",),
    "autoscan": ("opt/autoscan/.af-version",), "recyclarr": ("opt/recyclarr/.af-version",),
    "audiobookshelf": ("opt/audiobookshelf/.af-version",), "kavita": ("opt/Kavita/.af-version",),
    "calibreweb": ("opt/calibre-web/.af-version",), "librespeed": ("opt/librespeed/.af-version",),
    "thelounge": ("var/lib/thelounge/.af-version",), "znc": ("var/lib/znc/.af-version",),
    "scrutiny": ("opt/scrutiny/.af-version",), "paperless-ngx": ("opt/paperless/.af-version",),
    "n8n": ("var/lib/n8n/.af-version",), "palate": ("opt/palate/.af-version",),
    "gitea": ("var/lib/gitea/.af-version",), "organizr": ("var/www/organizr/.af-version",),
    "dispatcharr": ("opt/dispatcharr/.af-version",), "duplicati": ("var/lib/duplicati/.af-version",),
    "filebot": ("opt/filebot-node/.af-version", "opt/filebot/.af-version"), "listenarr": ("opt/Listenarr/.af-version",),
    "notifiarr": ("etc/notifiarr/.af-version",), "novnc": ("etc/novnc/.af-version",),
    "kasmvnc": ("var/lib/kasmvnc/.af-version",), "mcvnc": ("var/lib/mcvnc/.af-version",),
    "pyload": ("opt/pyload/.af-version",), "quassel": ("var/lib/quassel/.af-version",),
    "requestrr": ("opt/requestrr/.af-version",), "seedcross": ("opt/seedcross/.af-version",),
    "unmanic": ("opt/unmanic/.af-version",), "xrdp": ("var/lib/xrdp/.af-version",),
    "x2go": ("var/lib/x2go/.af-version",), "piped": ("opt/piped/.af-version",),
    "invidious": ("opt/invidious/.af-version",),
}

CANONICAL_APP_STATE_SENTINELS: dict[str, tuple[str, ...]] = {
    "plex": (
        "var/lib/plex/operator-data.sentinel",
        "var/lib/plexmediaserver/operator-data.sentinel",
        "etc/plexmediaserver/operator-data.sentinel",
    ),
    "jellyfin": ("var/lib/jellyfin/operator-data.sentinel", "etc/jellyfin/operator-data.sentinel"),
    "emby": (
        "var/lib/emby/operator-data.sentinel",
        "var/lib/emby-server/operator-data.sentinel",
        "etc/emby/operator-data.sentinel",
        "etc/emby-server/operator-data.sentinel",
    ),
    "sonarr": ("var/lib/sonarr/operator-data.sentinel",),
    "radarr": ("var/lib/radarr/operator-data.sentinel",),
    "lidarr": ("var/lib/lidarr/operator-data.sentinel",),
    "readarr": ("var/lib/readarr/operator-data.sentinel",),
    "prowlarr": ("var/lib/prowlarr/operator-data.sentinel",),
    "bazarr": ("var/lib/bazarr/operator-data.sentinel",),
    "overseerr": ("var/lib/overseerr/operator-data.sentinel",),
    "ombi": ("var/lib/ombi/operator-data.sentinel",),
    "maintainerr": ("var/lib/maintainerr/operator-data.sentinel",),
    "tautulli": ("var/lib/tautulli/operator-data.sentinel",),
    "jackett": ("var/lib/jackett/operator-data.sentinel",),
    "flaresolverr": ("var/lib/flaresolverr/operator-data.sentinel",),
    "navidrome": ("var/lib/navidrome/operator-data.sentinel",),
    "threadfin": ("var/lib/threadfin/operator-data.sentinel",),
    "qbittorrent": ("var/lib/qbittorrent/operator-data.sentinel",),
    "deluge": ("var/lib/deluge/operator-data.sentinel",),
    "transmission": (
        "var/lib/transmission/operator-data.sentinel",
        "var/lib/transmission-daemon/operator-data.sentinel",
        "etc/transmission-daemon/operator-data.sentinel",
    ),
    "sabnzbd": ("var/lib/sabnzbd/operator-data.sentinel",),
    "nzbget": ("var/lib/nzbget/operator-data.sentinel",),
    "flood": ("var/lib/flood/operator-data.sentinel",),
    "autobrr": ("var/lib/autobrr/operator-data.sentinel",),
    "qui": ("var/lib/qui/operator-data.sentinel",),
    "nextcloud": ("var/lib/nextcloud/operator-data.sentinel",),
    "syncthing": ("var/lib/syncthing/operator-data.sentinel",),
    "filebrowser": (
        "var/lib/filebrowser/operator-data.sentinel",
        "opt/filebrowser/operator-data.sentinel",
        "etc/filebrowser/operator-data.sentinel",
    ),
    "wireguard": ("var/lib/wireguard/operator-data.sentinel", "etc/wireguard/operator-data.sentinel"),
    "tailscale": ("var/lib/tailscale/operator-data.sentinel",),
    "pihole": (
        "var/lib/pihole/operator-data.sentinel",
        "etc/pihole/operator-data.sentinel",
        "opt/pihole/operator-data.sentinel",
    ),
    "fail2ban": ("var/lib/fail2ban/operator-data.sentinel",),
    "vaultwarden": ("var/lib/vaultwarden/operator-data.sentinel",),
    "grafana": ("var/lib/grafana/operator-data.sentinel",),
    "prometheus": ("var/lib/prometheus/operator-data.sentinel",),
    "netdata": ("var/lib/netdata/operator-data.sentinel",),
    "uptimekuma": ("var/lib/uptimekuma/operator-data.sentinel",),
    "homeassistant": (
        "var/lib/homeassistant/operator-data.sentinel",
        "srv/homeassistant/operator-data.sentinel",
        "home/homeassistant/.homeassistant/operator-data.sentinel",
    ),
    "jellyseerr": ("var/lib/jellyseerr/operator-data.sentinel",),
    "adguardhome": (
        "var/lib/adguardhome/operator-data.sentinel",
        "opt/AdGuardHome/operator-data.sentinel",
        "opt/AdGuardHome/work/operator-data.sentinel",
    ),
    "rtorrent": ("var/lib/rtorrent/operator-data.sentinel",),
    "rutorrent": (
        "var/lib/rutorrent/operator-data.sentinel",
        "var/www/rutorrent/share/operator-data.sentinel",
        "var/www/rutorrent/conf/operator-data.sentinel",
    ),
    "rclone": ("var/lib/rclone/operator-data.sentinel",),
    "mergerfs": ("var/lib/mergerfs/operator-data.sentinel",),
    "cloudplow": ("var/lib/cloudplow/operator-data.sentinel", "opt/cloudplow/operator-data.sentinel"),
    "unpackerr": ("var/lib/unpackerr/operator-data.sentinel",),
    "autoscan": ("var/lib/autoscan/operator-data.sentinel",),
    "recyclarr": ("var/lib/recyclarr/operator-data.sentinel",),
    "audiobookshelf": ("var/lib/audiobookshelf/operator-data.sentinel",),
    "kavita": ("var/lib/kavita/operator-data.sentinel",),
    "calibreweb": (
        "var/lib/calibreweb/operator-data.sentinel",
        "var/lib/calibre-web/operator-data.sentinel",
        "var/lib/calibre-library/operator-data.sentinel",
    ),
    "librespeed": (
        "var/lib/librespeed/operator-data.sentinel",
        "opt/librespeed/operator-data.sentinel",
        "var/www/librespeed/operator-data.sentinel",
    ),
    "thelounge": ("var/lib/thelounge/operator-data.sentinel",),
    "znc": ("var/lib/znc/operator-data.sentinel",),
    "scrutiny": ("var/lib/scrutiny/operator-data.sentinel",),
    "paperless-ngx": (
        "var/lib/paperless-ngx/operator-data.sentinel",
        "var/lib/paperless/operator-data.sentinel",
        "var/lib/paperless/data/operator-data.sentinel",
        "var/lib/paperless/media/operator-data.sentinel",
        "var/lib/paperless/consume/operator-data.sentinel",
        "var/lib/paperless/export/operator-data.sentinel",
    ),
    "n8n": ("var/lib/n8n/operator-data.sentinel",),
    "palate": ("var/lib/palate/operator-data.sentinel",),
    "gitea": ("var/lib/gitea/operator-data.sentinel",),
    "organizr": (
        "var/lib/organizr/operator-data.sentinel",
        "var/www/organizr/operator-data.sentinel",
        "var/www/organizr/api/config/operator-data.sentinel",
        "var/www/organizr/api/db/operator-data.sentinel",
    ),
    "dispatcharr": ("var/lib/dispatcharr/operator-data.sentinel",),
    "duplicati": ("var/lib/duplicati/operator-data.sentinel",),
    "filebot": ("var/lib/filebot/operator-data.sentinel",),
    "listenarr": ("var/lib/listenarr/operator-data.sentinel",),
    "notifiarr": ("var/lib/notifiarr/operator-data.sentinel",),
    "novnc": ("var/lib/novnc/operator-data.sentinel",),
    "kasmvnc": ("var/lib/kasmvnc/operator-data.sentinel",),
    "mcvnc": ("var/lib/mcvnc/operator-data.sentinel",),
    "pyload": ("var/lib/pyload/operator-data.sentinel",),
    "quassel": ("var/lib/quassel/operator-data.sentinel",),
    "requestrr": ("var/lib/requestrr/operator-data.sentinel",),
    "seedcross": ("var/lib/seedcross/operator-data.sentinel",),
    "unmanic": ("var/lib/unmanic/operator-data.sentinel",),
    "xrdp": ("var/lib/xrdp/operator-data.sentinel",),
    "x2go": ("var/lib/x2go/operator-data.sentinel",),
    "piped": (
        "var/lib/piped/operator-data.sentinel",
        "opt/piped/operator-data.sentinel",
        "etc/piped/operator-data.sentinel",
    ),
    "invidious": (
        "var/lib/invidious/operator-data.sentinel",
        "opt/invidious/operator-data.sentinel",
        "etc/invidious/operator-data.sentinel",
    ),
}


def canonical_state_sentinels_for_app(root: Path, catalog_name: str) -> list[Path]:
    return [root / relative for relative in CANONICAL_APP_STATE_SENTINELS[catalog_name]]


PIHOLE_BOOTSTRAP_SCRIPT = '''#!/bin/bash
printf 'bootstrap https://install.pi-hole.net %s\\n' "$*" >> "$AF_FIXTURE_ROOT/bootstrap.log"
[[ "${AF_FIXTURE_FAILURE:-}" != bootstrap ]]
'''
NODESOURCE_BOOTSTRAP_SCRIPT = '''#!/bin/bash
printf 'nodesource bootstrap\\n' >> "$AF_FIXTURE_ROOT/bootstrap.log"
[[ "${AF_FIXTURE_FAILURE:-}" != bootstrap ]]
'''
NETDATA_BOOTSTRAP_SCRIPT = '''#!/bin/bash
printf 'netdata bootstrap\\n' >> "$AF_FIXTURE_ROOT/bootstrap.log"
[[ "${AF_FIXTURE_FAILURE:-}" != bootstrap ]]
'''

HOST_COMMAND = r'''#!/usr/bin/python3
import base64, hashlib, json, os, pathlib, re, shutil, subprocess, sys
root = pathlib.Path(os.environ['AF_FIXTURE_ROOT'])
command, arguments = pathlib.Path(sys.argv[0]).name, sys.argv[1:]
if re.fullmatch(r'python3\.1[0-3]', command): command = 'python3'
app = os.environ['AF_FIXTURE_APP']
version = os.environ.get('AF_FIXTURE_VERSION', '2.1.0')
failure = os.environ.get('AF_FIXTURE_FAILURE', '')
with (root / 'commands.jsonl').open('a') as output:
    output.write(json.dumps([command, *arguments]) + '\n')
migration_state = os.environ.get('AF_FIXTURE_MIGRATION_STATE')
migration_runtime = os.environ.get('AF_FIXTURE_MIGRATION_RUNTIME')
runtime_is_new = not migration_runtime or (root / migration_runtime).read_bytes() == (root / 'host-command').read_bytes()
if migration_state and runtime_is_new and not (root / 'service-failed').exists():
    explicit_migration = command in ('runuser', 'su', 'sudo', 'python', 'python3') and (
        any('migrate' in argument for argument in arguments) or ('db' in arguments and 'push' in arguments))
    activation_migration = command == 'systemctl' and arguments[0] in ('start', 'restart') and any(
        app in argument for argument in arguments[1:])
    if explicit_migration or activation_migration:
        (root / migration_state).write_text('schema-v2-migrated\n')
        if migration_runtime:
            with (root / 'migration-writes.jsonl').open('a') as output:
                output.write(json.dumps([command, *arguments]) + '\n')
def write_file(target, content, executable=False):
    target = pathlib.Path(target)
    if not target.resolve().is_relative_to(root.resolve()):
        raise RuntimeError('Fixture write escaped root: ' + str(target))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content)
    if executable: target.chmod(0o755)
def install_stub(target):
    target = pathlib.Path(target)
    if not target.resolve().is_relative_to(root.resolve()):
        raise RuntimeError('Fixture executable escaped root: ' + str(target))
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(root / 'host-command', target)
    target.chmod(0o755)
def units():
    return [entry if entry.endswith(('.service', '.timer', '.socket')) else entry + '.service'
            for entry in arguments[1:] if not entry.startswith('-')]
if command == 'systemctl':
    operation = arguments[0]
    names = units()
    if operation == 'enable':
        for unit in names: (root / ('enabled-' + unit)).touch()
    elif operation == 'disable':
        for unit in names: (root / ('enabled-' + unit)).unlink(missing_ok=True)
    if operation == 'stop' and failure == 'stop':
        sys.exit(73)
    if operation in ('restart', 'start', 'enable'):
        failure_unit = os.environ.get('AF_FIXTURE_FAILURE_UNIT')
        if failure == 'service' and (not failure_unit or failure_unit in names) and not (root / 'service-failed').exists():
            (root / 'service-failed').touch()
            sys.exit(73)
        if operation != 'enable' or '--now' in arguments:
            for unit in names:
                (root / ('active-' + unit)).touch()
                path = root / 'etc/systemd/system' / unit
                if path.exists():
                    for line in path.read_text().splitlines():
                        if line.startswith(('Wants=', 'Requires=')):
                            for dependency in line.split('=', 1)[1].split():
                                if dependency.endswith('.service'): (root / ('active-' + dependency)).touch()
    elif operation == 'stop' or operation == 'disable' and '--now' in arguments:
        for unit in names: (root / ('active-' + unit)).unlink(missing_ok=True)
    elif operation == 'is-active':
        sys.exit(0 if failure != 'readiness' and all((root / ('active-' + unit)).exists() for unit in names) else 3)
    elif operation == 'is-enabled':
        sys.exit(0 if all((root / ('enabled-' + unit)).exists() for unit in names) else 1)
    elif operation == 'show':
        active = any((root / ('active-' + unit)).exists() for unit in names)
        print('LoadState=loaded\nActiveState=' + ('active' if active else 'inactive') + '\nMainPID=0\nUnitFileState=disabled')
    elif operation == 'cat':
        if failure == 'missing-unit': sys.exit(4)
        print('[Service]\nExecStart=/fixture/service')
elif command in ('python3', 'python'):
    if arguments[:2] == ['-m', 'venv']:
        if failure == 'build': sys.exit(74)
        directory = pathlib.Path(arguments[-1]) / 'bin'
        for name in ('python', 'python3', 'pip', 'pip3', 'gunicorn', 'unmanic', 'pyload', 'cps'):
            install_stub(directory / name)
    elif '-m' in arguments and 'pip' in arguments:
        if failure == 'build': sys.exit(74)
    elif arguments and arguments[0] == '-c' and 'importlib.metadata' in arguments[1]:
        print(version)
    elif any('manage.py' in entry for entry in arguments):
        if failure == 'migration': sys.exit(75)
    elif '-' in arguments:
        program = sys.stdin.read()
        if failure == 'bootstrap-python' and ('urllib.request' in program or 'import requests' in program):
            sys.exit(79)
        if 'urllib.request' not in program and 'import requests' not in program:
            sys.exit(subprocess.run(['/usr/bin/python3', *arguments], input=program, text=True).returncode)
    else:
        os.execv('/usr/bin/python3', ['/usr/bin/python3', *arguments])
elif command in ('curl', 'wget'):
    config_sources = []
    for position, argument in enumerate(arguments):
        if argument in ('--config', '-K') and position + 1 < len(arguments):
            config_sources.append(arguments[position + 1])
        elif argument.startswith('--config='):
            config_sources.append(argument.split('=', 1)[1])
        elif argument.startswith('-K') and len(argument) > 2:
            config_sources.append(argument[2:])
    for config_source in config_sources:
        if config_source == '-':
            sys.stdin.read()
        else:
            pathlib.Path(config_source).read_text()
    target = None
    for option in ('-o', '-O', '-qO', '--output'):
        if option in arguments: target = arguments[arguments.index(option) + 1]
    url = next((entry for entry in arguments if entry.startswith('http')), '')
    def checksum_opt_out():
        return os.environ.get('AF_TEST_DISABLE_CHECKSUM_URLS', '') not in ('', '0') or failure in ('checksum', 'missing-checksum', 'corrupt-checksum')
    def artifact_bytes(source_url):
        source_url = source_url.split('?', 1)[0]
        if source_url.endswith('.sha256'): source_url = source_url[:-len('.sha256')]
        elif source_url.endswith('.sha256sum'): source_url = source_url[:-len('.sha256sum')]
        if source_url == 'https://install.pi-hole.net': return (root / 'pihole-bootstrap.sh').read_bytes()
        if source_url.startswith('https://deb.nodesource.com/setup_'): return (root / 'nodesource-bootstrap.sh').read_bytes()
        if source_url == 'https://get.netdata.cloud/kickstart.sh': return (root / 'netdata-bootstrap.sh').read_bytes()
        if 'SHASUMS256.txt' in source_url:
            node_version = '26.12.1' if 'latest-v26' in source_url else '22.14.0'
            return (hashlib.sha256((root / 'node.tar.xz').read_bytes()).hexdigest() + '  node-v' + node_version + '-linux-x64.tar.xz\n').encode()
        if 'nodejs.org' in source_url and source_url.endswith('.tar.xz'): return (root / 'node.tar.xz').read_bytes()
        if 'node_exporter' in source_url: return (root / 'node-exporter.tar.gz').read_bytes()
        if 'prometheus-' in source_url: return (root / 'prometheus.tar.gz').read_bytes()
        if 'librespeed' in source_url or 'speedtest' in source_url:
            return (root / ('librespeed-src.tar.gz' if '/archive/' in source_url else 'release.tar.gz')).read_bytes()
        if source_url.endswith('.tar.xz'): return (root / 'release.tar.xz').read_bytes()
        if source_url.endswith('.zip'): return (root / 'release.zip').read_bytes()
        if source_url.endswith('.run'):
            return ('#!/bin/sh\nwhile [ "$1" != "--destdir" ]; do shift; done\nshift\nmkdir -p "$1"\ncp "$AF_FIXTURE_ROOT/host-command" "$1/nzbget"\nchmod 755 "$1/nzbget"\nprintf "ControlPort=6789\\nControlUsername=default\\nControlPassword=default\\n" > "$1/nzbget.conf"\n').encode()
        if app == 'gitea': return pathlib.Path('/usr/bin/true').read_bytes()
        if app in ('threadfin', 'scrutiny'): return (root / 'host-command').read_bytes()
        return (root / 'release.tar.gz').read_bytes()
    def publish(destination, payload, source_url):
        destination = pathlib.Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload)
        bare_url = source_url.split('?', 1)[0]
        if checksum_opt_out() or os.environ.get('AF_TEST_CHECKSUM_MANIFEST') or os.environ.get('AF_TEST_NO_LOCAL_SHA256') or failure == 'archive' or bare_url.endswith(('.sha256', '.sha256sum')) or 'SHASUMS256.txt' in bare_url:
            return
        pathlib.Path(str(destination) + '.sha256').write_text(hashlib.sha256(payload).hexdigest() + '\n')
    if target and target != '/dev/null':
        if failure == 'download': sys.exit(22)
        bare = url.split('?', 1)[0]
        checksum_name = bare.rsplit('/', 1)[-1]
        selected_manifest = os.environ.get('AF_TEST_CHECKSUM_MANIFEST')
        if checksum_name in ('checksums.txt', 'sha256sums.txt', 'SHA256SUMS', 'SHA256SUMS.txt') or selected_manifest and checksum_name == selected_manifest:
            if checksum_opt_out() or selected_manifest and checksum_name != selected_manifest:
                sys.exit(22)
            asset_name = os.environ.get('AF_TEST_CHECKSUM_ASSET', 'release.tar.gz')
            payload = artifact_bytes(bare.rsplit('/', 1)[0] + '/' + asset_name)
            digest = hashlib.sha256(payload).hexdigest()
            pathlib.Path(target).parent.mkdir(parents=True, exist_ok=True)
            pathlib.Path(target).write_text(os.environ.get('AF_TEST_CHECKSUM_LISTING', digest + '  ' + asset_name + '\n'))
        elif bare.endswith(('.sha256', '.sha256sum')):
            if selected_manifest: sys.exit(22)
            if failure == 'corrupt-checksum':
                payload = artifact_bytes(url)
                digest = '0' * 64
            elif checksum_opt_out():
                sys.exit(22)
            else:
                payload = artifact_bytes(url)
                digest = hashlib.sha256(payload).hexdigest()
            name = bare.rsplit('/', 1)[-1]
            name = name[:-len('.sha256')] if name.endswith('.sha256') else name[:-len('.sha256sum')]
            pathlib.Path(target).parent.mkdir(parents=True, exist_ok=True)
            pathlib.Path(target).write_text(digest + '\n' + digest + '  ' + name + '\n')
        elif failure == 'archive':
            pathlib.Path(target).parent.mkdir(parents=True, exist_ok=True)
            pathlib.Path(target).write_text('corrupt release')
        else:
            publish(target, artifact_bytes(url), url)
    elif any('ifconfig.me' in entry for entry in arguments): print('192.0.2.2')
    elif any('http_code' in entry for entry in arguments): print('200')
    elif any('127.0.0.1' in entry for entry in arguments):
        if failure == 'readiness': sys.exit(22)
        print(json.dumps({'status': 'ok' if app == 'maintainerr' else 'OK', 'database': 'ok', 'version': version, 'apiKey': 'retained-api-key'}))
    elif url.split('?', 1)[0].endswith(('.tar.gz', '.tgz', '.tar.xz', '.zip')):
        sys.stdout.buffer.write(artifact_bytes(url))
    else:
        print(json.dumps({'tag_name': 'v' + version, 'token': 'fixture-token', 'assets': [], 'fixture_url': url}))
elif command == 'jq':
    incoming = sys.stdin.read()
    query = next((entry for entry in arguments if entry.startswith(('.', 'if ', '['))), '')
    if 'token' in query: print('fixture-token')
    elif '.layers' in query or '.manifests' in query: print('sha256:' + hashlib.sha256((root / 'release.tar.gz').read_bytes()).hexdigest())
    elif 'digest' in query: print('sha256:' + hashlib.sha256((root / 'release.tar.gz').read_bytes()).hexdigest())
    elif 'browser_download_url' in query:
        if app == 'invidious':
            metadata = json.loads(incoming)
            repository = metadata['fixture_url'].split('/repos/', 1)[1].split('/releases/', 1)[0]
            name = arguments[arguments.index('name') + 1] if 'name' in arguments else 'fixture.tar.gz'
            print('https://github.com/' + repository + '/releases/download/v2.1.0/' + name)
        elif app == 'kasmvnc': print('https://github.com/kasmtech/KasmVNC/releases/download/v' + version + '/fixture.deb')
        else: print('https://fixture.invalid/release.' + ('zip' if app == 'listenarr' else 'tar.gz'))
    elif 'tag_name' in query or '.[0].name' in query: print(version if 'ltrimstr' in query else 'v' + version)
    elif '.name' in query: print('fixture.tar.gz')
    else:
        sys.exit(subprocess.run(['/usr/bin/jq', *arguments], input=incoming, text=True).returncode)
elif command == 'git':
    if 'clone' in arguments:
        if failure in ('clone', 'build'): sys.exit(76)
        destination = pathlib.Path(arguments[-1])
        shutil.copytree(root / 'repository', destination, dirs_exist_ok=True)
    elif 'pull' in arguments and failure == 'pull': sys.exit(76)
    elif 'ls-remote' in arguments: print('abcdef123456\trefs/tags/v' + version)
    elif 'rev-parse' in arguments or 'rev-list' in arguments: print('abcdef123456')
    else: print('v' + version)
elif command in ('npm', 'yarn', 'pnpm'):
    if failure == 'build': sys.exit(74)
    if '--prefix' in arguments:
        directory = pathlib.Path(arguments[arguments.index('--prefix') + 1]) / 'node_modules'
        for name in ('n8n', 'thelounge', 'pnpm', 'flood'):
            install_stub(directory / '.bin' / name)
            install_stub(directory / name / 'bin' / name)
    else:
        directory = pathlib.Path.cwd()
        if directory.is_relative_to(root):
            for name in ('node_modules/.bin/vite', 'dist/index.html', 'build/index.js'):
                write_file(directory / name, 'built fixture\n', True)
elif command == 'node':
    if '-v' in arguments or '--version' in arguments: print('v24.1.0')
    elif '-p' in arguments: print('pnpm@10.5.0' if 'packageManager' in arguments[-1] else version)
    elif any('process.argv' in entry for entry in arguments) and arguments:
        username = arguments[-1]
        write_file(root / 'var/lib/thelounge/users' / (username + '.json'), '{"password":"fixture-hash"}\n')
    elif any('thelounge' in entry for entry in arguments) and '-v' in arguments: print(version)
elif command in ('sudo', 'runuser', 'su'):
    program = sys.stdin.read()
    if app == 'seedcross' and 'operator_settings = importlib.import_module' in program:
        assert command == 'su' and arguments[:3] == ['-s', '/bin/bash', 'seedcross']
        sys.exit(subprocess.run(['/usr/bin/python3', '-c', program], cwd=root / 'opt/seedcross').returncode)
    if failure == 'build' and app == 'invidious' and any('make' in entry for entry in arguments): sys.exit(74)
    if failure == 'migration' and any('migrate' in entry for entry in arguments): sys.exit(75)
    if app == 'seedcross' and any('manage.py shell' in entry for entry in arguments):
        import types
        account_path = root / 'seedcross-account.json'
        class FixtureUser:
            def __init__(self, record): self.__dict__.update(record)
            def set_password(self, password): self.password = password
            def save(self): write_file(account_path, json.dumps(self.__dict__))
        class FixtureUsers:
            @staticmethod
            def filter(**criteria):
                record = json.loads(account_path.read_text()) if account_path.exists() else {}
                return types.SimpleNamespace(exists=lambda: bool(record) and all(record.get(key) == value for key, value in criteria.items()))
            @staticmethod
            def get_or_create(username):
                created = not account_path.exists()
                record = {'username': username} if created else json.loads(account_path.read_text())
                assert record['username'] == username
                return FixtureUser(record), created
        class FixtureUserModel:
            objects = FixtureUsers()
        for name in ('django', 'django.contrib', 'django.contrib.auth'):
            sys.modules[name] = types.ModuleType(name)
        sys.modules['django.contrib.auth'].get_user_model = lambda: FixtureUserModel
        exec(compile(program, '<seedcross-account-bootstrap>', 'exec'), {'__name__': '__main__'})
    if any(pathlib.Path(argument).name == 'rustc' for argument in arguments) and '--version' in arguments:
        selected_version = os.environ.get('AF_FIXTURE_RUST_TOOLCHAIN_VERSION', '1.90.0') if any('rust-toolchain-' in argument for argument in arguments) else os.environ.get('AF_FIXTURE_RUST_VERSION', '1.89.0')
        print('rustc ' + selected_version + ' (fixture)')
    if app == 'homeassistant' and 'bash' in arguments:
        for name in ('python', 'pip', 'hass'): install_stub(root / 'srv/homeassistant/bin' / name)
    if any('thelounge' in entry for entry in arguments):
        write_file(root / 'var/lib/thelounge/users/admin.json', '{"password":"fixture-hash"}\n')
    if any('syncthing' in entry for entry in arguments) and 'generate' in arguments:
        write_file(root / 'var/lib/syncthing/config.xml', '<configuration><gui><user>admin</user><password>fixture-hash</password></gui></configuration>\n')
    if '--' in arguments:
        inner = arguments[arguments.index('--') + 1:]
        if inner and inner[0] == 'env':
            inner = inner[1:]
            while inner and (inner[0].startswith('-') or '=' in inner[0]): inner = inner[1:]
        if inner and inner[0] in ('git', 'cp', 'mkdir', 'tar'):
            sys.exit(subprocess.run(inner).returncode)
    if app == 'gitea' and 'create' in arguments and '--random-password' in arguments:
        import sqlite3
        database_path = root / 'var/lib/gitea/data/gitea.db'
        database_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(database_path) as database:
            database.execute('CREATE TABLE IF NOT EXISTS user (lower_name TEXT PRIMARY KEY, passwd TEXT, salt TEXT, passwd_hash_algo TEXT)')
            username = arguments[arguments.index('--username') + 1].lower()
            if database.execute('SELECT 1 FROM user WHERE lower_name=?', (username,)).fetchone(): sys.exit(1)
            database.execute('INSERT INTO user(lower_name) VALUES(?)', (username,))
    if any('maintenance:install' == entry for entry in arguments):
        database_config = {
            'dbtype': 'mysql', 'dbname': 'nextcloud', 'dbhost': 'localhost',
            'dbuser': 'nextclouduser', 'dbpassword': os.environ['AF_NEXTCLOUD_DB_PASS'],
            'datadirectory': str(root / 'var/lib/nextcloud/data'),
        }
        write_file(root / 'var/www/nextcloud/config/config.php', '<?php $CONFIG = [' +
                   ', '.join(json.dumps(key) + ' => ' + json.dumps(value) for key, value in database_config.items()) + '];\n')
    if any('SHOW port' in entry for entry in arguments): print('5432')
    for entry in arguments:
        if entry.startswith(str(root)) and pathlib.Path(entry).is_dir():
            directory = pathlib.Path(entry)
            if 'palate-build' in entry: write_file(directory / '.next/BUILD_ID', 'fixture-build\n')
            if 'backend-build' in entry: write_file(directory / 'build/libs/piped-1.0-all.jar', 'fixture-jar\n')
elif command == 'install':
    selected = []
    position = 0
    while position < len(arguments):
        if arguments[position] in ('-o', '-g'):
            position += 2
        else:
            selected.append(arguments[position])
            position += 1
    os.execv('/usr/bin/install', ['/usr/bin/install', *selected])
elif command == 'apt-get':
    if failure == 'apt' and arguments[-1] == 'netdata': sys.exit(100)
    if os.environ.get('AF_FIXTURE_PERSISTENT_APT') == '1':
        state_file = root / 'dpkg-state.json'
        state = json.loads(state_file.read_text()) if state_file.exists() else {}
        for argument in arguments[1:]:
            package, separator, requested = argument.partition('=')
            if package not in ('grafana', 'wireguard', 'wireguard-tools'):
                continue
            if arguments[0] == 'remove':
                state.pop(package, None)
                if package == 'grafana': (root / 'usr/share/grafana/bin/grafana-server').unlink(missing_ok=True)
            elif arguments[0] == 'install':
                if separator and os.environ.get('AF_FIXTURE_APT_ROLLBACK_FAILURE') == '1':
                    sys.exit(100)
                selected = requested if separator else version
                if state.get(package) != selected or '--reinstall' in arguments:
                    if package == 'grafana': write_file(root / 'usr/share/grafana/bin/grafana-server', 'package-runtime-' + selected + '\n')
                    state[package] = selected
        state_file.write_text(json.dumps(state))
elif command == 'dpkg':
    if '--compare-versions' in arguments:
        sys.exit(subprocess.run(['/usr/bin/dpkg', *arguments]).returncode)
    print('amd64' if '--print-architecture' in arguments else '')
elif command == 'dpkg-deb': print(version)
elif command == 'dpkg-query':
    selected = version
    if os.environ.get('AF_FIXTURE_PERSISTENT_APT') == '1':
        state_file = root / 'dpkg-state.json'
        state = json.loads(state_file.read_text()) if state_file.exists() else {}
        selected = state.get(arguments[-1])
        if selected is None:
            sys.exit(1)
    print(('installed ' if any('db:Status-Status' in argument for argument in arguments) else '') + selected)
elif command == 'uname': print('x86_64')
elif command == 'id':
    if arguments and arguments[-1] == 'af-maintainerr-build' and not (root / 'builder-user').exists(): sys.exit(1)
    print('1000')
elif command == 'getent': sys.exit(2)
elif command in ('pgrep', 'pkill'): sys.exit(1)
elif command == 'useradd':
    if arguments[-1] == 'af-maintainerr-build': (root / 'builder-user').touch()
elif command == 'userdel':
    if arguments[-1] == 'af-maintainerr-build': (root / 'builder-user').unlink(missing_ok=True)
elif command == 'openssl':
    for option in ('-keyout', '-out'):
        if option in arguments: write_file(arguments[arguments.index(option) + 1], 'fixture-certificate\n')
    if 'rand' in arguments: print('ab' * int(arguments[-1]))
elif command == 'gpg':
    sys.stdin.read()
    if '-o' in arguments: write_file(arguments[arguments.index('-o') + 1], 'fixture-signing-key')
elif command == 'wg':
    sys.stdin.read()
    if arguments == ['genkey']: print(base64.b64encode(bytes([7]) * 32).decode())
    else: print(base64.b64encode(bytes([8]) * 32).decode())
elif command == 'ip':
    print('4: wg0: <POINTOPOINT,UP,LOWER_UP> mtu 1420' if '-o' in arguments else 'default via 192.0.2.1 dev eth0')
elif command == 'pihole-FTL':
    if '--config' in arguments:
        target = root / 'etc/pihole/pihole.toml'
        text = target.read_text()
        key = 'pwhash' if arguments[-2] == 'webserver.api.pwhash' else 'port'
        pattern = r'(?m)^' + key + r'\s*=.*$'
        replacement = key + ' = "' + arguments[-1] + '"'
        write_file(target, re.sub(pattern, replacement, text) if re.search(pattern, text) else text + '\n' + replacement + '\n')
    else: print(version)
elif command == 'pihole':
    if failure == 'bootstrap': sys.exit(77)
    print(version)
elif command in ('chown', 'usermod', 'useradd', 'userdel', 'groupdel', 'flock', 'sysctl', 'a2enmod', 'a2dismod', 'a2ensite', 'a2dissite', 'apache2ctl', 'update-alternatives', 'setcap', 'mount', 'umount', 'fusermount', 'hostnamectl', 'sleep', 'pip', 'pip3', 'cargo', 'loginctl', 'ufw', 'crontab'):
    if command in ('pip', 'pip3', 'cargo') and failure in ('build', 'pip-build'): sys.exit(74)
elif command == 'hostname': print('192.0.2.2' if '-I' in arguments else 'fixture.example')
elif command == 'mysql':
    query = arguments[arguments.index('-Nse') + 1] if '-Nse' in arguments else arguments[arguments.index('-e') + 1] if '-e' in arguments else sys.stdin.read()
    database = root / 'mysql-nextcloud-present'
    if 'INFORMATION_SCHEMA.SCHEMATA' in query and database.exists(): print('nextcloud')
    if 'CREATE DATABASE nextcloud' in query: database.touch()
    if 'DROP DATABASE IF EXISTS nextcloud' in query: database.unlink(missing_ok=True)
elif command in ('mysqldump', 'pg_dump'):
    print('-- fixture database backup')
elif command == 'htpasswd': print('admin:fixture-password-hash')
elif command == 'vncpasswd':
    sys.stdin.read()
    print('fixture-vnc-hash')
elif command == 'kasmvncpasswd': write_file(arguments[-1], 'fixture-kasm-password-hash\n')
elif command == 'netdata': print('netdata v' + version)
elif command == 'znc': print('ZNC ' + version)
elif command == 'rclone': print('rclone v' + version)
elif command == 'qui':
    if 'create-user' in arguments and failure in ('account-create', 'account-rotate', 'account-exists'): sys.exit(76)
    if 'change-password' in arguments and failure == 'account-rotate': sys.exit(77)
    if 'create-user' in arguments:
        directory = next(entry.split('=', 1)[1] for entry in arguments if entry.startswith('--config-dir='))
        write_file(pathlib.Path(directory) / 'qui.db', 'fixture-user-database')
    else: print(version)
elif command == 'filebrowser':
    for option in ('-d', '--database'):
        if option in arguments: write_file(arguments[arguments.index(option) + 1], 'fixture-filebrowser-database')
    print(version)
elif command in ('autobrr', 'autobrrctl'):
    if 'create-user' in arguments and failure in ('account-create', 'account-rotate', 'account-exists'): sys.exit(76)
    if 'change-password' in arguments and failure == 'account-rotate': sys.exit(77)
    if any(entry in arguments for entry in ('create-user', 'change-password')):
        write_file(root / 'var/lib/autobrr/autobrr.db', 'fixture-user-database')
        write_file(root / 'var/lib/autobrr/operator-password.txt', sys.stdin.read())
    print(version)
else:
    print(version)
'''


class InstallerFixture:
    """Rebase scripts and their real helpers; only fake host commands reach PATH."""

    def __init__(self, app):
        self.temporary = tempfile.TemporaryDirectory(prefix=f"af-catalog-{app}-")
        self.root = Path(self.temporary.name)
        self.app = app
        self.metadata = CATALOG[app]
        self.commands = self.root / "mock-bin"
        self.commands.mkdir()
        directories = (
            "opt/AetherFlow/packages", "opt/AetherFlow/logs", "opt/AetherFlow/backend/data",
            "etc/systemd/system", "usr/lib/systemd/system", "etc/apache2/sites-available",
            "etc/apache2/conf-available", "etc/apache2/conf-enabled", "etc/apache2/sites-enabled", "etc/default",
            "etc/apt/keyrings", "etc/apt/sources.list.d", "etc/lighttpd/conf-enabled",
            "etc/aetherflow", "var/log/aetherflow", "var/lib", "var/www", "var/backups",
            "usr/local/bin", "usr/bin", "usr/sbin", "usr/share", "run/lock", "tmp",
            "home", "root", "srv", "mnt", "install", "etc/grafana", "etc/netdata", "etc/xrdp",
        )
        for directory in directories:
            (self.root / directory).mkdir(parents=True, exist_ok=True)
        self.file("host-command", HOST_COMMAND).chmod(0o755)
        self.file("pihole-bootstrap.sh", PIHOLE_BOOTSTRAP_SCRIPT)
        self.file("nodesource-bootstrap.sh", NODESOURCE_BOOTSTRAP_SCRIPT)
        self.file("netdata-bootstrap.sh", NETDATA_BOOTSTRAP_SCRIPT)
        self.file("etc/os-release", 'ID=debian\nVERSION_CODENAME=bookworm\nVERSION_ID="12"\n')
        self.file("etc/grafana/grafana.ini", "[server]\n;http_port = 3000\n[security]\n;admin_user = admin\n;admin_password = admin\n")
        self.file("etc/netdata/netdata.conf", "[global]\n history = 900\n[web]\ndefault port = 19999\nbind socket to IP = 127.0.0.1\n")
        self.file("etc/fuse.conf", "#user_allow_other\n")
        self.file("etc/passwd", "")
        self.file("etc/group", "")
        self.file("etc/shadow", "")
        self.file("etc/resolv.conf", "nameserver 192.0.2.1\n")
        names = (
            "apt-get dpkg dpkg-deb dpkg-query systemctl id getent chown useradd usermod userdel groupdel "
            "curl wget jq git npm yarn pnpm node python3 python3.13 python3.12 python3.11 python3.10 python pip pip3 sudo runuser su openssl "
            "gpg wg ip sysctl flock uname hostname netdata pihole pihole-FTL znc rclone qui "
            "htpasswd vncpasswd a2enmod a2dismod a2ensite a2dissite apache2ctl update-alternatives "
            "setcap mount umount fusermount hostnamectl sleep cargo loginctl ufw crontab install "
            "grafana-cli mergerfs syncthing qbittorrent-nox deluged deluge-web php "
            "kasmvncpasswd startkasmvnc palated x2godbadmin mysql mysqldump tailscale psql pg_dump pgrep pkill"
        ).split()
        for name in names:
            for directory in (self.commands, self.root / "usr/bin", self.root / "usr/sbin"):
                shutil.copyfile(self.root / "host-command", directory / name)
                (directory / name).chmod(0o755)
        self.file("usr/lib/systemd/system/" + self.metadata["service_name"] + ".service", "[Service]\nExecStart=/fixture/vendor-service\n")
        source = (ROOT / "packages/common.sh").read_text()
        names = re.findall(r"(?m)^([a-zA-Z_][a-zA-Z0-9_-]*)\(\) [({]$", source)
        helpers = self.rewrite(common_functions(*(name for name in names if name != "seed_jellyfin_master_user")))
        overrides = r'''
set -euo pipefail
umask 077
MASTER_USER=admin
MASTER_PASS=bootstrap-password
MASTER_HA1=fixture-ha1
LOCK_DIR="$AF_FIXTURE_ROOT/install"
require_root() { :; }
load_master_credentials() { :; }
ensure_node() { :; }
sync_node_global_bins() { :; }
github_latest_tag() { [[ "${3:-}" != false ]] || printf v; printf '%s\n' "$AF_FIXTURE_VERSION"; }
get_base_domain() { printf 'fixture.example\n'; }
seed_jellyfin_master_user() { :; }
'''
        self.file("opt/AetherFlow/packages/common.sh", helpers + overrides)
        self.file("packages/common.sh", helpers + overrides)
        self.file("packages/system/af-systemd-sandbox", self.rewrite((ROOT / "packages/system/af-systemd-sandbox").read_text()))
        youtube = ROOT / "packages/youtube-common.sh"
        if youtube.exists():
            text = self.rewrite(youtube.read_text())
            text += '''
youtube_private_port() {
    local port_file="$CONFIG_DIR/$1-port" port
    case "$1" in api) port=22001 ;; proxy) port=22002 ;; companion) port=22003 ;; esac
    [[ -s "$port_file" ]] || printf '%s\\n' "$port" > "$port_file"
    cat "$port_file"
}
'''
            self.file("packages/youtube-common.sh", text)
            self.file("opt/AetherFlow/packages/youtube-common.sh", text)
        self.prepare_release()

    def __enter__(self):
        return self

    def __exit__(self, *exception):
        self.close()

    def close(self):
        self.temporary.cleanup()

    def file(self, relative, content):
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        return target

    def rewrite(self, text):
        prefixes = ("/usr/local", "/usr/bin", "/usr/sbin", "/usr/share", "/usr/lib", "/opt", "/var", "/etc", "/srv", "/mnt", "/install", "/tmp", "/run", "/home", "/root", "/data")
        pattern = re.compile(r"(?<![\w/.-])(" + "|".join(re.escape(prefix) for prefix in prefixes) + r")(?=/|[^\w.-]|$)")
        return pattern.sub(lambda match: str(self.root) + match.group(0), text)

    def prepare_release(self):
        executable = HOST_COMMAND
        files = {
            "new-code": "fixture runtime\n", "package.json": '{"name":"fixture","version":"2.1.0"}\n',
            "index.php": "<?php echo 'fixture';\n", "occ": executable,
            "version.php": "<?php $OC_VersionString = '32.0.1';\n",
            "config/sample.php": "<?php\n", "api/config/default.php": "<?php\n",
            "conf/config.php": '<?php $scgi_port = 15000; $scgi_host = "127.0.0.1";\n',
            "server/server.js": executable, "server/app.js": executable, "server.js": executable,
            "server/package.json": '{"name":"fixture-server","version":"2.1.0"}\n',
            "Tautulli.py": executable, "SABnzbd.py": executable, "bazarr.py": executable,
            "cps.py": executable, "cloudplow.py": executable,
            "manage.py": executable, "requirements.txt": "", "start.sh": executable,
            "csui/settings.py": "SECRET_KEY = 'fresh-secret'\nDEBUG = True\nALLOWED_HOSTS = ['localhost']\n",
            "src/manage.py": executable, "src/paperless/__init__.py": '__version__ = "2.1.0"\n',
            "pyproject.toml": '[project]\nname = "fixture"\nversion = "2.1.0"\n',
            "client/package.json": '{"version":"2.1.0"}\n', "build/index.js": executable,
            "dist/index.js": executable, "dist/index.html": "fixture frontend\n",
            "frontend/package.json": '{"version":"2.1.0"}\n', "filebot.sh": executable,
            "src/main/java/me/kavin/piped/server/ServerLauncher.java": 'new InetSocketAddress(Constants.PORT)\n',
            "vault/.keep": "fixture vault\n", "target/release/mcvnc": executable,
            "bin/node": executable, "bin/npm": executable,
            "api/config/default.php": "<?php $version = '2.1.0';\n",
        }
        if self.app in ("maintainerr", "jellyseerr"):
            files["package.json"] = json.dumps({"version": "2.1.0", "packageManager": "yarn@4.9.0" if self.app == "maintainerr" else "pnpm@10.5.0"})
            for name in (".yarn/releases/yarn-4.9.0.cjs", "apps/server/dist/main.js", "apps/ui/dist/index.html",
                         "apps/server/dist/ui/index.html", "apps/server/dist/assets/font.ttf", "packages/contracts/dist/index.js",
                         "apps/server/assets/font.ttf", "apps/ui/.env", ".next/BUILD_ID", "dist/server/index.js"):
                files[name] = "fixture build output\n"
        flat = ("autobrr", "autobrrctl", "qui", "filebrowser", "navidrome", "notifiarr", "Requestrr.WebApi", "unpackerr", "recyclarr", "autoscan", "librespeed", "speedtest-backend", "vaultwarden", "rclone", "invidious_companion")
        for name in flat:
            files[name] = executable
        for name in ("Sonarr", "Radarr", "Lidarr", "Readarr", "Prowlarr", "Jackett", "Kavita", "AdGuardHome"):
            files[f"{name}/{name.lower() if name == 'Jackett' else name}"] = executable
        files["Ombi"] = executable
        files["flaresolverr/flaresolverr"] = executable
        files["Listenarr.Api"] = executable
        files["web-vault/index.html"] = "fixture vault\n"
        files["frontend/server/app.js"] = executable
        repository = self.root / "repository"
        for name, content in files.items():
            target = self.file("repository/" + name, content)
            if content == executable or name.endswith((".js", ".php")):
                target.chmod(0o755)
        (repository / ".git").mkdir()
        archive_files = dict(files)
        if self.app in ("tautulli", "sabnzbd", "bazarr", "paperless-ngx"):
            archive_files = {"release/" + name: content for name, content in files.items()}
        for filename, mode in (("release.tar.gz", "w:gz"), ("release.tar.xz", "w:xz")):
            with tarfile.open(self.root / filename, mode) as output:
                for name, content in archive_files.items():
                    payload = content.encode()
                    entry = tarfile.TarInfo(name)
                    entry.size, entry.mode = len(payload), 0o755
                    output.addfile(entry, io.BytesIO(payload))
        with tarfile.open(self.root / "node.tar.xz", "w:xz") as output:
            for name in ("node", "npm"):
                payload = executable.encode()
                node_version = "26.12.1" if self.app == "maintainerr" else "22.14.0"
                entry = tarfile.TarInfo("node-v" + node_version + "-linux-x64/bin/" + name)
                entry.size, entry.mode = len(payload), 0o755
                output.addfile(entry, io.BytesIO(payload))
        with zipfile.ZipFile(self.root / "release.zip", "w") as output:
            for name, content in files.items():
                output.writestr(("nextcloud/" if self.app == "nextcloud" else "") + name, content)
        with tarfile.open(self.root / "librespeed-src.tar.gz", "w:gz") as output:
            asset = b"fixture librespeed asset\n"
            entry = tarfile.TarInfo("speedtest-go-2.1.0/web/assets/index.html")
            entry.size = len(asset)
            output.addfile(entry, io.BytesIO(asset))
            binary = executable.encode()
            entry = tarfile.TarInfo("speedtest-go-2.1.0/speedtest-backend")
            entry.size, entry.mode = len(binary), 0o755
            output.addfile(entry, io.BytesIO(binary))
        for filename, directory, names in (
            ("prometheus.tar.gz", "prometheus-2.1.0.linux-amd64", ("prometheus", "promtool")),
            ("node-exporter.tar.gz", "node_exporter-2.1.0.linux-amd64", ("node_exporter",)),
        ):
            with tarfile.open(self.root / filename, "w:gz") as output:
                for name in names:
                    payload = executable.encode()
                    entry = tarfile.TarInfo(directory + "/" + name)
                    entry.size, entry.mode = len(payload), 0o755
                    output.addfile(entry, io.BytesIO(payload))

    @property
    def lock(self):
        return self.root / "install" / ("." + self.app + ".lock")

    def run(self, action="install", port=None, **environment):
        action = "remove" if action == "uninstall" else action
        removing = action == "remove"
        directory, prefix = ("remove", "remove") if removing else ("install", "install")
        source = (ROOT / f"packages/package/{directory}/{prefix}package-{self.app}").read_text()
        script = self.file(f"packages/package/{directory}/{prefix}package-{self.app}", self.rewrite(source))
        variables = {
            **os.environ, "PATH": str(self.commands) + ":/usr/bin:/bin",
            "AF_FIXTURE_ROOT": str(self.root), "AF_FIXTURE_APP": self.app,
            "AF_FIXTURE_VERSION": "2.1.0", "AF_LIFECYCLE_ACTION": action,
            "AF_PACKAGE_ACTION": action,
            "AF_KEEP_EXISTING_SECRETS": "1" if action in ("update", "reinstall") else "0",
            "AF_CONFIG_PASS": "", "AF_CONFIG_USER": "", "AF_DELETE_DATA": "false",
            "AETHERFLOW_INSTALL_ROOT": str(self.root), "AF_BUILDER_QUIESCE_SLEEP": "0.01",
            "AETHERFLOW_APACHE_ROOT": str(self.root / "etc/apache2"),
            "AF_PIHOLE_BOOTSTRAP_SHA256": hashlib.sha256(PIHOLE_BOOTSTRAP_SCRIPT.encode()).hexdigest(),
            "AF_NODESOURCE_BOOTSTRAP_SHA256": hashlib.sha256(NODESOURCE_BOOTSTRAP_SCRIPT.encode()).hexdigest(),
            "AF_TRUSTED_KEY_SHA256": hashlib.sha256((self.root / "release.tar.gz").read_bytes()).hexdigest(),
            "TMPDIR": str(self.root / "tmp"), "HOME": str(self.root / "home"),
            "DELETE_DATA": "false", **environment,
        }
        variables = {key: value for key, value in variables.items() if value is not None}
        selected_port = port if port is not None else self.metadata.get("default_port", 0)
        if selected_port:
            variables["AF_APP_PORT"] = str(selected_port)
        else:
            variables.pop("AF_APP_PORT", None)
            variables.pop("AETHERFLOW_APP_PORT", None)
        result = subprocess.run(["/bin/bash", str(script)], env=variables, stdin=subprocess.DEVNULL, text=True, capture_output=True, timeout=int(os.environ.get("AF_TEST_SUBPROCESS_TIMEOUT", "90")))
        if result.returncode:
            logfiles = sorted((self.root / "var/log/aetherflow").glob("*.log"))
            logs = "\n".join(path.read_text(errors="replace")[-3000:] for path in logfiles)
            result.stderr += "\n" + logs
        return result


class CatalogLifecycleMatrix(unittest.TestCase):
    def patch_host_command(self, fixture, command, old, new):
        for directory in (fixture.commands, fixture.root / "usr/bin", fixture.root / "usr/sbin"):
            path = directory / command
            source = path.read_text()
            self.assertIn(old, source)
            path.write_text(source.replace(old, new, 1))

    def test_postgresql_rollback_preserves_unrelated_cluster_databases(self):
        with InstallerFixture("piped") as fixture:
            unrelated = fixture.file("var/lib/postgresql/16/main/unrelated-database-marker", "before-unrelated-transaction")
            database = fixture.file("var/lib/postgresql/16/main/piped-database-marker", "before-app-migration")
            self.patch_host_command(fixture, "runuser", "if command == 'systemctl':\n", """if command == 'runuser' and 'pg_dump' in arguments:
    print((root / 'var/lib/postgresql/16/main/piped-database-marker').read_text(), end='')
    sys.exit(0)
if command == 'runuser' and 'psql' in arguments:
    if '-f' in arguments:
        source = arguments[arguments.index('-f') + 1]
        contents = sys.stdin.read() if source == '-' else pathlib.Path(source).read_text()
        (root / 'var/lib/postgresql/16/main/piped-database-marker').write_text(contents)
    else:
        print('1')
    sys.exit(0)
if command == 'systemctl':
""")
            program = r"""
source "$1"
LOGFILE="$AF_FIXTURE_ROOT/database-rollback.log"
backup_postgresql_database "$AF_FIXTURE_ROOT/database-backup" piped
printf acknowledged-unrelated-transaction > "$AF_FIXTURE_ROOT/var/lib/postgresql/16/main/unrelated-database-marker"
printf migrated-app-schema > "$AF_FIXTURE_ROOT/var/lib/postgresql/16/main/piped-database-marker"
restore_postgresql_database "$AF_FIXTURE_ROOT/database-backup" piped
"""
            result = subprocess.run(
                ["bash", "-euc", program, "rollback-probe", str(fixture.root / "packages/common.sh")],
                env={**os.environ, "PATH": str(fixture.commands) + ":/usr/bin:/bin", "AF_FIXTURE_ROOT": str(fixture.root), "AF_FIXTURE_APP": "piped"},
                capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(database.read_text(), "before-app-migration")
            self.assertEqual(unrelated.read_text(), "acknowledged-unrelated-transaction")
            commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()]
            self.assertTrue(any("pg_dump" in command for command in commands))
            self.assertTrue(any("psql" in command and "-f" in command for command in commands))

    def test_transmission_authenticated_readiness_succeeds_when_web_ui_returns_401(self):
        with InstallerFixture("transmission") as fixture:
            self.patch_host_command(fixture, "curl", "elif command in ('curl', 'wget'):\n", """elif command in ('curl', 'wget'):
    if any(argument.split('?', 1)[0].endswith('/transmission/web/') for argument in arguments):
        sys.exit(22)
""")
            installed = fixture.run("install")
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            self.assertTrue(fixture.lock.is_file())
            commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()]
            endpoints = [argument for command in commands if command[0] == "curl" for argument in command[1:] if argument.startswith("http://127.0.0.1:")]
            self.assertTrue(any(endpoint.endswith("/transmission/rpc") for endpoint in endpoints), endpoints)
            self.assertFalse(any(endpoint.endswith("/transmission/web/") for endpoint in endpoints), endpoints)

    def test_gitea_and_nzbget_readiness_do_not_depend_on_invalid_ping_route(self):
        for app, endpoint, receipt in (
            ("gitea", "/api/healthz", "var/lib/gitea/.af-version"),
            ("nzbget", "/jsonrpc/version", "opt/nzbget/.af-version"),
        ):
            with self.subTest(app=app), InstallerFixture(app) as fixture:
                installed = fixture.run("install")
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                version = fixture.root / receipt
                previous_version = version.read_text().strip()
                self.patch_host_command(fixture, "curl", "elif command in ('curl', 'wget'):\n", """elif command in ('curl', 'wget'):
    if any(argument.split('?', 1)[0].endswith('/ping') for argument in arguments):
        sys.exit(22)
""")
                (fixture.root / "commands.jsonl").write_text("")
                updated = fixture.run("update", AF_FIXTURE_VERSION="2.2.0")
                self.assertEqual(updated.returncode, 0, updated.stdout + updated.stderr)
                self.assertTrue(fixture.lock.is_file())
                self.assertEqual(version.read_text().strip(), "2.2.0")
                self.assertNotEqual(version.read_text().strip(), previous_version)
                commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()]
                endpoints = [argument for command in commands if command[0] == "curl" for argument in command[1:] if argument.startswith("http://127.0.0.1:")]
                self.assertTrue(any(url.endswith(endpoint) for url in endpoints), endpoints)
                self.assertFalse(any(url.endswith("/ping") for url in endpoints), endpoints)

    def test_verify_download_sha256_rejects_unverified_format_only_script_without_digest(self):
        with InstallerFixture("radarr") as fixture:
            artifact = fixture.file("tmp/unverified.sh", "#!/bin/sh\nexit 0\n")
            helper = common_functions("verify_sha256", "verify_download_sha256")
            helper += '\nprint_error() { printf "%s\\n" "$*" >&2; }; log_info() { :; }; curl() { return 22; }\nverify_download_sha256 "$1" testapp\n'
            environment = {key: value for key, value in os.environ.items() if not key.startswith(("AF_", "AETHERFLOW_"))}
            result = subprocess.run(
                ["bash", "-euc", helper, "digest-probe", str(artifact)],
                env={**environment, "LOGFILE": str(fixture.root / "checksum.log")}, capture_output=True, text=True, timeout=20,
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("command not found", result.stderr)
            self.assertNotIn("unbound variable", result.stderr)
            self.assertFalse(artifact.with_suffix(".sh.sha256").exists())

    def test_servarr_reinstall_preserves_existing_custom_password_even_when_keep_secrets_zero(self):
        with InstallerFixture("sonarr") as fixture:
            fixture.file("var/lib/sonarr/config.xml", "<Config><ApiKey>private-api-key</ApiKey></Config>")
            requests = []
            existing_password = "operator-chosen-password"
            host_configuration = {"id": 1, "authenticationMethod": "forms", "username": "admin", "password": existing_password}

            class Handler(BaseHTTPRequestHandler):
                def log_message(self, *arguments):
                    pass

                def handle_request(self):
                    body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                    requests.append((self.command, self.path))
                    if self.command == "PUT":
                        host_configuration.update(json.loads(body))
                    payload = json.dumps(host_configuration).encode()
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)

                do_GET = do_POST = do_PUT = handle_request

            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            helper = fixture.rewrite(common_functions("seed_servarr_master_user"))
            helper += '\nlog_warn() { :; }; print_error() { printf "%s\\n" "$*" >&2; }\nseed_servarr_master_user sonarr "$1"\n'
            try:
                result = subprocess.run(
                    ["bash", "-euc", helper, "servarr-probe", str(server.server_port)],
                    env={**os.environ, "PATH": "/usr/bin:/bin", "MASTER_USER": "admin", "MASTER_PASS": "replacement-master-password", "AF_CONFIG_USER": "", "AF_CONFIG_PASS": "", "AF_KEEP_EXISTING_SECRETS": "0", "AF_FORCE_PASSWORD_ROTATION": "0", "LOGFILE": str(fixture.root / "bootstrap.log")},
                    capture_output=True, text=True, timeout=20,
                )
            finally:
                server.shutdown()
                server.server_close()
                worker.join(timeout=2)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(("GET", "/api/v3/config/host"), requests)
            self.assertFalse(any(method in ("PUT", "POST") for method, path in requests), requests)
            self.assertEqual(host_configuration["password"], existing_password)

    def test_real_bootstrap_provisions_fresh_instances_without_argv_secrets(self):
        for app in ("sonarr", "jellyfin"):
            for configured in (False, True):
                with self.subTest(app=app, configured=configured), InstallerFixture(app) as fixture:
                    requests = []
                    command_lines = []
                    completed = configured
                    process = None
                    secret = "master-argv-probe-'\\\"-secret"
                    fixture.file("var/lib/sonarr/config.xml", "<Config><ApiKey>private-api-key</ApiKey></Config>")

                    class Handler(BaseHTTPRequestHandler):
                        def log_message(self, *arguments):
                            pass

                        def handle_request(self):
                            nonlocal completed
                            pending = [process.pid]
                            while pending:
                                process_id = pending.pop()
                                try:
                                    command_lines.append(Path(f"/proc/{process_id}/cmdline").read_bytes())
                                    pending.extend(int(child) for child in Path(f"/proc/{process_id}/task/{process_id}/children").read_text().split())
                                except (FileNotFoundError, ProcessLookupError):
                                    pass
                            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                            requests.append((self.command, self.path, json.loads(body) if body else None))
                            if app == "sonarr":
                                response = {"id": 1, "authenticationMethod": "forms" if configured else "none", "username": "operator" if configured else ""}
                            else:
                                if self.path == "/Startup/Complete":
                                    completed = True
                                response = {"StartupWizardCompleted": completed} if self.path == "/System/Info/Public" else {}
                            payload = json.dumps(response).encode()
                            self.send_response(200)
                            self.send_header("Content-Length", str(len(payload)))
                            self.end_headers()
                            self.wfile.write(payload)

                        do_GET = do_POST = do_PUT = handle_request

                    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
                    worker = threading.Thread(target=server.serve_forever, daemon=True)
                    worker.start()
                    helper_name = "seed_servarr_master_user" if app == "sonarr" else "seed_jellyfin_master_user"
                    body = fixture.rewrite(common_functions(helper_name))
                    body += '\nlog_warn() { printf "%s\\n" "$*" >&2; }; print_error() { printf "%s\\n" "$*" >&2; }\n'
                    body += f'{helper_name} ' + ("sonarr " if app == "sonarr" else "") + str(server.server_port)
                    try:
                        process = subprocess.Popen(["bash", "-euc", body], env={**os.environ, "PATH": "/usr/bin:/bin", "MASTER_USER": "admin", "MASTER_PASS": secret, "AF_KEEP_EXISTING_SECRETS": "1", "LOGFILE": str(fixture.root / "bootstrap.log")}, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        stdout, stderr = process.communicate(timeout=20)
                        self.assertEqual(process.returncode, 0, stdout + stderr + (fixture.root / "bootstrap.log").read_text())
                    finally:
                        if process and process.poll() is None:
                            process.kill()
                            process.communicate()
                        server.shutdown()
                        server.server_close()
                        worker.join(timeout=2)
                    self.assertTrue(command_lines)
                    self.assertTrue(any(b"python3" in command for command in command_lines))
                    self.assertFalse(any(secret.encode() in command or b"private-api-key" in command for command in command_lines))
                    changes = [request for request in requests if request[0] in ("POST", "PUT")]
                    if configured:
                        self.assertEqual(changes, [])
                    elif app == "sonarr":
                        self.assertEqual(len(changes), 1)
                        self.assertEqual(changes[0][0], "PUT")
                        self.assertEqual(changes[0][2]["password"], secret)
                        self.assertEqual(changes[0][2]["passwordConfirmation"], secret)
                        self.assertEqual(changes[0][2]["authenticationMethod"], "forms")
                        self.assertEqual(changes[0][2]["authenticationRequired"], "enabled")
                    else:
                        user = next(request[2] for request in changes if request[1] == "/Startup/User")
                        self.assertEqual(user, {"Name": "admin", "Password": secret})

    def test_nextcloud_preserves_operator_apps_across_update_and_retained_uninstall(self):
        with InstallerFixture("nextcloud") as fixture:
            self.assertEqual(fixture.run().returncode, 0)
            plugin = fixture.file("var/www/nextcloud/apps/operator-plugin/lib/operator.php", "operator-plugin-code\n")
            for action in ("update", "reinstall", "uninstall", "reinstall"):
                result = fixture.run(action)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(plugin.read_text(), "operator-plugin-code\n")
            result = fixture.run("uninstall", DELETE_DATA="true")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(plugin.exists())

    def test_moving_release_receipts_use_installed_binary_version(self):
        for app in ("sonarr", "radarr", "lidarr", "readarr", "prowlarr", "jackett"):
            with self.subTest(app=app), InstallerFixture(app) as fixture:
                for filename in ("release.tar.gz", "release.tar.xz"):
                    with tarfile.open(fixture.root / filename, "r:*") as archive:
                        contents = [(entry, archive.extractfile(entry).read()) for entry in archive if entry.isfile()]
                    with tarfile.open(fixture.root / filename, "w:gz" if filename.endswith(".gz") else "w:xz") as archive:
                        for entry, content in contents:
                            if entry.name.rsplit("/", 1)[-1].lower() == app:
                                content = b'#!/bin/sh\nprintf "2.1.0\\n"\n'
                                entry.size = len(content)
                            archive.addfile(entry, io.BytesIO(content))
                result = fixture.run(AF_FIXTURE_VERSION="9.9.9")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                version_file = fixture.root / f"opt/{app.capitalize()}/.af-version"
                self.assertEqual(version_file.read_text(), "2.1.0\n")

    def test_unverified_garbage_and_html_fail_closed_and_digest_policy_is_required(self):
        with InstallerFixture("radarr") as fixture:
            artifact = fixture.root / "tmp/artifact.bin"
            helper = common_functions("verify_sha256", "verify_download_sha256")
            helper += '\nprint_error() { printf "%s\\n" "$*" >&2; }; log_info() { :; }; curl() { return 22; }\nverify_download_sha256 "$1" radarr https://example.invalid/radarr.tar.gz\n'
            script_payload = b"#!/bin/sh\nexit 0\n"
            script_digest = hashlib.sha256(script_payload).hexdigest()
            clean_environment = {key: value for key, value in os.environ.items() if not key.startswith(("AF_", "AETHERFLOW_"))}
            for payload, environment, expected in (
                (b"", {}, False),
                (b"unverified-synthetic-payload", {}, False),
                (b"<!DOCTYPE html><html>error</html>", {}, False),
                (script_payload, {}, False),
                (script_payload, {"AF_REQUIRE_DOWNLOAD_SHA256": "1"}, False),
                (script_payload, {"AF_DOWNLOAD_SHA256": script_digest}, True),
                (script_payload, {"AF_REQUIRE_DOWNLOAD_SHA256": "1", "AF_DOWNLOAD_SHA256": script_digest}, True),
            ):
                artifact.write_bytes(payload)
                result = subprocess.run(["bash", "-euc", helper, "probe", str(artifact)], env={**clean_environment, "LOGFILE": str(fixture.root / "checksum.log"), **environment}, text=True, capture_output=True)
                self.assertEqual(result.returncode == 0, expected, result.stdout + result.stderr)

    def test_credential_installers_keep_master_password_out_of_external_arguments(self):
        for app in ("adguardhome", "dispatcharr", "nextcloud", "gitea", "duplicati", "syncthing", "rclone", "znc", "librespeed", "filebrowser", "grafana", "kavita", "audiobookshelf", "ombi", "qui", "pihole", "nzbget"):
            with self.subTest(app=app), InstallerFixture(app) as fixture:
                result = fixture.run()
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()]
                self.assertFalse(any("bootstrap-password" in argument for command in commands for argument in command), commands)
                if app == "nzbget":
                    python_commands = [command for command in commands if command[0] in ("python", "python3")]
                    self.assertTrue(python_commands, commands)
                    self.assertFalse(any("bootstrap-password" in argument for command in python_commands for argument in command), python_commands)
                if app == "gitea":
                    with sqlite3.connect(fixture.root / "var/lib/gitea/data/gitea.db") as database:
                        password, salt, algorithm = database.execute("SELECT passwd, salt, passwd_hash_algo FROM user WHERE lower_name='admin'").fetchone()
                    self.assertEqual(algorithm, "pbkdf2$50000$50")
                    expected = hashlib.pbkdf2_hmac("sha256", b"bootstrap-password", bytes.fromhex(salt), 50000, 50).hex()
                    self.assertEqual(password, expected)
                elif app == "duplicati":
                    service = (fixture.root / "etc/systemd/system/duplicati.service").read_text()
                    self.assertNotIn("webservice-password", service)
                    environment = fixture.root / "etc/duplicati/duplicati.env"
                    self.assertIn('DUPLICATI__WEBSERVICE_PASSWORD="bootstrap-password"', environment.read_text())
                    self.assertEqual(environment.stat().st_mode & 0o777, 0o600)

    def test_pihole_password_rotation_uses_hashes_without_plaintext_arguments(self):
        for modern in (False, True):
            with self.subTest(modern=modern), InstallerFixture("pihole") as fixture:
                if modern:
                    configuration = fixture.file("etc/pihole/pihole.toml", '[webserver]\nport = "8089o"\n[webserver.api]\npwhash = "operator-hash"\n')
                else:
                    configuration = fixture.file("etc/pihole/setupVars.conf", "WEBPASSWORD=operator-hash\n")
                result = fixture.run(AF_CONFIG_PASS="rotated-password", AF_KEEP_EXISTING_SECRETS="0")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                expected = hashlib.sha256(hashlib.sha256(b"rotated-password").hexdigest().encode()).hexdigest()
                self.assertIn(expected, configuration.read_text())
                commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()]
                self.assertFalse(any("rotated-password" in argument for command in commands for argument in command), commands)
                self.assertFalse(any(command[0] == "pihole" and "setpassword" in command for command in commands), commands)

    def test_jellyfin_and_kasmvnc_receipts_enforce_downgrade_and_uninstall_cleanup(self):
        for app in ("jellyfin", "kasmvnc"):
            with self.subTest(app=app), InstallerFixture(app) as fixture:
                result = fixture.run(AF_FIXTURE_VERSION="2.1.0")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                receipt = fixture.root / f"var/lib/{app}/.af-version"
                self.assertEqual(receipt.read_text(), "2.1.0\n")
                failed = fixture.run("update", AF_FIXTURE_VERSION="1.0.0")
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                self.assertEqual(receipt.read_text(), "2.1.0\n")
                removed = fixture.run("uninstall")
                self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
                self.assertFalse(receipt.exists())

    def test_n8n_failed_update_when_restore_copy_fails_preserves_live_db_and_backup(self):
        with InstallerFixture("n8n") as fixture:
            installed = fixture.run()
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            database = fixture.file("var/lib/n8n/database.sqlite", "sqlite-v1-live")
            fixture.file("mock-bin/cp", """#!/usr/bin/python3
import os, sys
source = next(argument for argument in sys.argv[1:] if not argument.startswith('-'))
if os.environ.get('AF_FAIL_RESTORE_SUBSTR', '') in source and os.environ.get('AF_FAIL_RESTORE_SUBSTR'):
    sys.exit(75)
os.execv('/bin/cp', ['/bin/cp', *sys.argv[1:]])
""").chmod(0o755)
            failed = fixture.run("update", AF_FIXTURE_FAILURE="service",
                                 AF_FAIL_RESTORE_SUBSTR=str(fixture.root / "tmp/af-runtime-"))
            self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
            self.assertEqual(database.read_text(), "sqlite-v1-live")
            backups = list((fixture.root / "tmp").glob("af-runtime-*/1/database.sqlite"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_text(), "sqlite-v1-live")
            self.assertIn("recovery backup preserved at", failed.stderr)
            self.assertFalse(list((fixture.root / "var/lib").glob(".n8n.af-restore.*")))

    def test_grafana_failed_update_rolls_back_migrated_db_and_version(self):
        with InstallerFixture("grafana") as fixture:
            installed = fixture.run(AF_FIXTURE_VERSION="1.0.0")
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            runtime = fixture.file("usr/share/grafana/bin/grafana-server", "package-runtime-v1")
            self.patch_host_command(fixture, "apt-get", "elif command == 'apt-get':\n", """elif command == 'apt-get':
    if 'install' in arguments and 'grafana' in arguments:
        (root / 'usr/share/grafana/bin/grafana-server').write_text('package-runtime-v2')
""")
            database = fixture.file("var/lib/grafana/grafana.db", "schema-v1")
            config = fixture.root / "etc/grafana/grafana.ini"
            previous_config = config.read_bytes()
            self.patch_host_command(fixture, "systemctl", "if command == 'systemctl':\n", """if command == 'systemctl':
    if os.environ.get('AF_GRAFANA_MIGRATION') == '1' and arguments[0] == 'restart' and 'grafana-server' in arguments:
        (root / 'var/lib/grafana/grafana.db').write_text('schema-v2-migrated')
        sys.exit(73)
""")
            failed = fixture.run("update", AF_GRAFANA_MIGRATION="1")
            self.assertEqual(failed.returncode, 73, failed.stdout + failed.stderr)
            self.assertEqual(database.read_text(), "schema-v1")
            self.assertEqual(runtime.read_text(), "package-runtime-v1")
            self.assertEqual((fixture.root / "var/lib/grafana/.af-version").read_text(), "1.0.0\n")
            self.assertEqual(config.read_bytes(), previous_config)
            self.assertFalse(list((fixture.root / "tmp").glob("af-state-*")))

    def test_nextcloud_download_failure_allows_clean_retry(self):
        with InstallerFixture("nextcloud") as fixture:
            failed = fixture.run(AF_FIXTURE_FAILURE="download")
            self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
            self.assertFalse((fixture.root / "mysql-nextcloud-present").exists())
            self.assertFalse((fixture.root / "var/www/nextcloud/config/config.php").exists())
            self.assertFalse(fixture.lock.exists())
            retried = fixture.run()
            self.assertEqual(retried.returncode, 0, retried.stdout + retried.stderr)
            self.assertTrue((fixture.root / "var/www/nextcloud/config/config.php").is_file())
            self.assertTrue(fixture.lock.is_file())

    def test_nextcloud_failure_after_database_creation_removes_new_database_for_retry(self):
        with InstallerFixture("nextcloud") as fixture:
            self.patch_host_command(fixture, "sudo", "failure = os.environ.get('AF_FIXTURE_FAILURE', '')", """failure = os.environ.get('AF_FIXTURE_FAILURE', '')
if command == 'sudo' and 'maintenance:install' in arguments and os.environ.get('AF_NEXTCLOUD_FAIL_INITIALIZATION') == '1':
    sys.exit(76)
""")
            failed = fixture.run(AF_NEXTCLOUD_FAIL_INITIALIZATION="1")
            self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
            self.assertFalse((fixture.root / "mysql-nextcloud-present").exists())
            self.assertFalse(fixture.lock.exists())
            retried = fixture.run()
            self.assertEqual(retried.returncode, 0, retried.stdout + retried.stderr)
            self.assertTrue(fixture.lock.is_file())

    def test_download_checksum_mismatch_fails_before_installation(self):
        for variable in ("AF_DOWNLOAD_SHA256", "AF_THREADFIN_SHA256", "AETHERFLOW_THREADFIN_SHA256"):
            with self.subTest(variable=variable), InstallerFixture("threadfin") as fixture:
                failed = fixture.run(**{variable: "0" * 64})
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                self.assertIn("digest mismatch", failed.stderr)
                self.assertFalse(fixture.lock.exists())
                self.assertFalse((fixture.root / "opt/threadfin/threadfin").exists())

    def test_download_checksum_accepts_matching_digest_and_companion_manifests(self):
        for manifest in (None, "sha256", "sha256sum", "manifest", "manifest-no-newline"):
            with self.subTest(manifest=manifest), InstallerFixture("threadfin") as fixture:
                payload = fixture.file("tmp/payload.bin", "fixture download\n")
                digest = hashlib.sha256(payload.read_bytes()).hexdigest()
                environment = {}
                if manifest is None:
                    environment["AF_DOWNLOAD_SHA256"] = digest.upper()
                elif manifest.startswith("manifest"):
                    suffix = "  release.bin" + ("" if manifest.endswith("no-newline") else "\n")
                    checksum = fixture.file("tmp/SHA256SUMS", digest + suffix)
                    environment["AF_DOWNLOAD_CHECKSUM_FILE"] = str(checksum)
                else:
                    fixture.file("tmp/payload.bin." + manifest, digest + "\n")
                program = 'source "$1"; LOGFILE="$AF_FIXTURE_ROOT/checksum.log"; verify_download_sha256 "$2" threadfin https://fixture.invalid/release.bin'
                result = subprocess.run(["bash", "-euc", program, "fixture", str(fixture.root / "packages/common.sh"), str(payload)],
                                        env={**os.environ, "AF_FIXTURE_ROOT": str(fixture.root), **environment}, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                if manifest is not None:
                    checksum = Path(environment["AF_DOWNLOAD_CHECKSUM_FILE"]) if environment else Path(str(payload) + "." + manifest)
                    checksum.write_text("0" * 64 + (suffix if manifest.startswith("manifest") else "\n"))
                    result = subprocess.run(["bash", "-euc", program, "fixture", str(fixture.root / "packages/common.sh"), str(payload)],
                                            env={**os.environ, "AF_FIXTURE_ROOT": str(fixture.root), **environment}, text=True, capture_output=True)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_failed_update_restores_sqlite_database_after_startup_migration(self):
        for app, runtime, database in (
            ("overseerr", "opt/overseerr", "var/lib/overseerr/db/db.sqlite3"),
            ("tautulli", "opt/Tautulli", "var/lib/tautulli/tautulli.db"),
            ("calibreweb", "opt/calibre-web", "var/lib/calibre-web/app.db"),
            ("homeassistant", "srv/homeassistant", "home/homeassistant/.homeassistant/home-assistant_v2.db"),
            ("bazarr", "opt/bazarr", "var/lib/bazarr/db/bazarr.db"),
        ):
            with self.subTest(app=app), InstallerFixture(app) as fixture:
                installed = fixture.run("install", AF_FIXTURE_VERSION="2.1.0")
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                previous = fixture.file(runtime + "/audit-old-runtime", "previous executable\n")
                state = fixture.file(database, "")
                with sqlite3.connect(state) as connection:
                    connection.execute("CREATE TABLE audit_schema (version INTEGER NOT NULL)")
                    connection.execute("INSERT INTO audit_schema VALUES (1)")
                self.patch_host_command(fixture, "systemctl", "if command == 'systemctl':\n", """if command == 'systemctl':
    if arguments and arguments[0] == 'enable' and '--now' in arguments:
        import sqlite3
        with sqlite3.connect(root / os.environ['AF_AUDIT_DATABASE']) as connection:
            connection.execute('UPDATE audit_schema SET version=2')
        (root / 'startup-migration-ran').touch()
""")
                failed = fixture.run("update", AF_FIXTURE_VERSION="2.2.0", AF_FIXTURE_FAILURE="readiness", AF_AUDIT_DATABASE=database)
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                self.assertTrue((fixture.root / "startup-migration-ran").exists())
                with sqlite3.connect(state) as connection:
                    self.assertEqual(connection.execute("SELECT version FROM audit_schema").fetchone()[0], 1)
                self.assertEqual(previous.read_text(), "previous executable\n")
                self.assertEqual((fixture.root / runtime / ".af-version").read_text().strip(), "2.1.0")
                self.assertTrue(fixture.lock.exists())

    def test_state_snapshots_include_final_writes_from_stopping_the_old_service(self):
        for app in ("bazarr", "invidious", "piped", "nextcloud"):
            with self.subTest(app=app), InstallerFixture(app) as fixture:
                installed = fixture.run("install")
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                database_path = f"var/lib/{app}/audit-stopped-state.db"
                database = fixture.file(database_path, "")
                with sqlite3.connect(database) as connection:
                    connection.execute("CREATE TABLE audit_schema (version INTEGER NOT NULL)")
                    connection.execute("INSERT INTO audit_schema VALUES (0)")
                self.patch_host_command(fixture, "systemctl", "if command == 'systemctl':\n", """if command == 'systemctl':
    target_service = os.environ['AF_AUDIT_SERVICE']
    targets_app = any(argument.removesuffix('.service') == target_service for argument in arguments)
    stopped = root / 'old-service-flushed'
    migrated = root / 'startup-migration-ran'
    if targets_app and arguments[0] == 'stop' and not stopped.exists():
        import sqlite3
        with sqlite3.connect(root / os.environ['AF_AUDIT_DATABASE']) as connection:
            connection.execute('UPDATE audit_schema SET version=1')
        if app == 'bazarr':
            with (root / 'var/lib/bazarr/config/config.yaml').open('a') as config:
                config.write('audit_stopped: true\\n')
        stopped.touch()
    if targets_app and stopped.exists() and not migrated.exists() and (arguments[0] in ('start', 'restart') or arguments[0] == 'enable' and '--now' in arguments):
        import sqlite3
        with sqlite3.connect(root / os.environ['AF_AUDIT_DATABASE']) as connection:
            connection.execute('UPDATE audit_schema SET version=2')
        migrated.touch()
""")
                failed = fixture.run("update", AF_FIXTURE_FAILURE="readiness", AF_AUDIT_DATABASE=database_path,
                                     AF_AUDIT_SERVICE=fixture.metadata["service_name"].removesuffix(".service"))
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                self.assertTrue((fixture.root / "old-service-flushed").exists())
                self.assertTrue((fixture.root / "startup-migration-ran").exists())
                with sqlite3.connect(database) as connection:
                    self.assertEqual(connection.execute("SELECT version FROM audit_schema").fetchone()[0], 1)
                if app == "bazarr":
                    self.assertIn("audit_stopped: true", (fixture.root / "var/lib/bazarr/config/config.yaml").read_text())

    def test_rejected_deb_install_fails_closed_even_when_apt_fix_succeeds(self):
        for app, version_path in (
            ("emby", "opt/emby-server/.af-version"),
            ("duplicati", "var/lib/duplicati/.af-version"),
            ("audiobookshelf", "opt/audiobookshelf/.af-version"),
        ):
            with self.subTest(app=app), InstallerFixture(app) as fixture:
                installed = fixture.run("install", AF_FIXTURE_VERSION="2.1.0")
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                self.patch_host_command(fixture, "dpkg", "elif command == 'dpkg':\n", "elif command == 'dpkg':\n    if '-i' in arguments: sys.exit(1)\n")
                log = fixture.root / "commands.jsonl"
                count = len(log.read_text().splitlines())
                failed = fixture.run("update", AF_FIXTURE_VERSION="2.2.0")
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                self.assertEqual((fixture.root / version_path).read_text().strip(), "2.1.0")
                self.assertTrue(fixture.lock.exists())
                commands = [json.loads(line) for line in log.read_text().splitlines()[count:]]
                self.assertEqual(sum(command[:2] == ["dpkg", "-i"] for command in commands), 2)
                self.assertTrue(any(command[:2] == ["apt-get", "install"] and "-f" in command for command in commands))

    def test_deb_install_verifies_installed_status_and_exact_version(self):
        for observed in ("not-installed 2.2.0", "unpacked 2.2.0", "installed 2.1.0", "installed"):
            with self.subTest(observed=observed), InstallerFixture("emby") as fixture:
                installed = fixture.run("install", AF_FIXTURE_VERSION="2.1.0")
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                self.patch_host_command(fixture, "dpkg-query", "elif command == 'dpkg-query':\n",
                                        f"elif command == 'dpkg-query':\n    print({observed!r}); sys.exit(0)\n")
                failed = fixture.run("update", AF_FIXTURE_VERSION="2.2.0")
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                self.assertEqual((fixture.root / "opt/emby-server/.af-version").read_text().strip(), "2.1.0")

    def test_deb_dependency_repair_retries_install_before_committing(self):
        with InstallerFixture("emby") as fixture:
            self.patch_host_command(fixture, "dpkg", "elif command == 'dpkg':\n", """elif command == 'dpkg':
    if '-i' in arguments and not (root / 'first-dpkg-attempt').exists():
        (root / 'first-dpkg-attempt').touch()
        sys.exit(1)
""")
            installed = fixture.run("install", AF_FIXTURE_VERSION="2.1.0")
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()]
            installs = [index for index, command in enumerate(commands) if command[:2] == ["dpkg", "-i"]]
            self.assertEqual(len(installs), 2)
            self.assertTrue(any(command[:2] == ["apt-get", "install"] and "-f" in command for command in commands[installs[0]:installs[1]]))
            self.assertEqual((fixture.root / "opt/emby-server/.af-version").read_text().strip(), "2.1.0")

    def test_other_custom_rollbacks_restore_migrated_application_state(self):
        for app, directory in (
            ("cloudplow", "var/lib/cloudplow"), ("flaresolverr", "var/lib/flaresolverr"),
            ("sabnzbd", "var/lib/sabnzbd"), ("flood", "var/lib/flood"),
            ("duplicati", "var/lib/duplicati"), ("audiobookshelf", "var/lib/audiobookshelf"),
            ("prometheus", "var/lib/prometheus"), ("mcvnc", "var/lib/mcvnc"),
            ("fail2ban", "var/lib/fail2ban"), ("paperless-ngx", "var/lib/paperless/data"),
            ("homeassistant", "var/lib/homeassistant"), ("calibreweb", "var/lib/calibre-library"),
        ):
            with self.subTest(app=app), InstallerFixture(app) as fixture:
                installed = fixture.run("install")
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                database = fixture.file(directory + "/audit-migration.db", "")
                with sqlite3.connect(database) as connection:
                    connection.execute("CREATE TABLE audit_schema (version INTEGER NOT NULL)")
                    connection.execute("INSERT INTO audit_schema VALUES (1)")
                self.patch_host_command(fixture, "systemctl", "if command == 'systemctl':\n", """if command == 'systemctl':
    target_service = os.environ['AF_AUDIT_SERVICE']
    starts_target = any(argument.removesuffix('.service') == target_service for argument in arguments)
    if arguments and starts_target and not (root / 'startup-migration-ran').exists() and (arguments[0] == 'restart' or arguments[0] == 'enable' and '--now' in arguments):
        import sqlite3
        database = root / os.environ['AF_AUDIT_DATABASE']
        with sqlite3.connect(database) as connection:
            connection.execute('UPDATE audit_schema SET version=2')
        database.with_suffix('.new-state').touch()
        (root / 'startup-migration-ran').touch()
""")
                failed = fixture.run("update", AF_FIXTURE_VERSION="2.1.0" if app == "prometheus" else "2.2.0",
                                     AF_FIXTURE_FAILURE="readiness", AF_AUDIT_DATABASE=directory + "/audit-migration.db",
                                     AF_AUDIT_SERVICE=fixture.metadata["service_name"])
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                self.assertTrue((fixture.root / "startup-migration-ran").exists())
                with sqlite3.connect(database) as connection:
                    self.assertEqual(connection.execute("SELECT version FROM audit_schema").fetchone()[0], 1)
                self.assertFalse(database.with_suffix(".new-state").exists())

    def test_explicit_purge_removes_installer_backups_under_var_backups(self):
        for app in ("cloudplow", "overseerr", "maintainerr", "tautulli", "flaresolverr", "homeassistant", "calibreweb", "jellyseerr"):
            with self.subTest(app=app), InstallerFixture(app) as fixture:
                installed = fixture.run("install")
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                fixture.file(f"var/backups/aetherflow-{app}/data.tar.gz", "synthetic retained backup\n")
                fixture.file(f"var/backups/aetherflow-{app}.legacy/app/operator-retained-secret.json", "synthetic secret\n")
                unrelated = fixture.file(f"var/backups/aetherflow-{app}-unrelated/data", "unrelated backup\n")
                removed = fixture.run("uninstall", DELETE_DATA="false")
                self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
                self.assertTrue((fixture.root / f"var/backups/aetherflow-{app}.legacy").exists())
                purged = fixture.run("uninstall", DELETE_DATA="true")
                self.assertEqual(purged.returncode, 0, purged.stdout + purged.stderr)
                self.assertFalse((fixture.root / f"var/backups/aetherflow-{app}").exists())
                self.assertEqual(list((fixture.root / "var/backups").glob(f"aetherflow-{app}.*")), [])
                self.assertEqual(unrelated.read_text(), "unrelated backup\n")

    def test_untagged_git_checkout_still_writes_observable_af_version_receipt(self):
        automation = json.loads((ROOT / "config/package_automation.json").read_text())
        for app, runtime in (("tautulli", "opt/Tautulli"), ("calibreweb", "opt/calibre-web")):
            with self.subTest(app=app), InstallerFixture(app) as fixture:
                self.patch_host_command(fixture, "git", "elif command == 'git':\n", "elif command == 'git':\n    if 'describe' in arguments: sys.exit(128)\n")
                installed = fixture.run("install")
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                self.assertTrue(fixture.lock.exists())
                receipt = fixture.root / runtime / ".af-version"
                self.assertTrue(receipt.read_text().strip())
                observed = subprocess.run(
                    ["/bin/bash", "--noprofile", "--norc", "-c", fixture.rewrite(automation[app]["version_command"][-1])],
                    cwd=fixture.root / "opt/AetherFlow", capture_output=True, text=True, timeout=30,
                    env={**os.environ, "PATH": str(fixture.commands) + ":/usr/bin:/bin", "AF_FIXTURE_ROOT": str(fixture.root),
                         "AF_FIXTURE_APP": app, "AF_FIXTURE_VERSION": "2.1.0", "HOME": str(fixture.root / "home")},
                )
                self.assertEqual(observed.returncode, 0, observed.stderr)
                self.assertTrue(observed.stdout.strip())

    def test_catalog_has_exactly_the_explicit_77_apps(self):
        self.assertEqual(len(CATALOG_APPS), 77)
        self.assertEqual(set(CATALOG_APPS), set(CATALOG))
        self.assertEqual(set(CANONICAL_APP_STATE_SENTINELS), set(CATALOG_APPS))
        self.assertEqual(set(PORT_CONFIG_EXPECTATIONS), set(CATALOG_APPS))
        self.assertEqual(set(VERSION_RECEIPT_EXPECTATIONS), set(CATALOG_APPS))
        for app in CATALOG_APPS:
            with self.subTest(app=app):
                expectations = PORT_CONFIG_EXPECTATIONS[app]
                self.assertTrue(expectations)
                self.assertEqual(any("{port}" in pattern for path, pattern in expectations), CATALOG[app]["default_port"] != 0)
                for relative, pattern in expectations:
                    self.assertFalse(Path(relative).is_absolute())
                    re.compile(pattern.replace("{port}", str(CATALOG[app]["default_port"])))
                self.assertTrue(VERSION_RECEIPT_EXPECTATIONS[app])
                for relative in VERSION_RECEIPT_EXPECTATIONS[app]:
                    self.assertEqual(Path(relative).name, ".af-version")
                    self.assertFalse(Path(relative).is_absolute())

    def test_guest_family_drills_use_canonical_catalog_services_and_receipts(self):
        with mock.patch.object(sys, "path", [str(ROOT / "scripts"), *sys.path]):
            from v4_native_package_guest_drills import NATIVE_FAMILY_DRILLS
        self.assertEqual({entry["category"] for entry in CATALOG.values()}, {CATALOG[definition.package_id]["category"] for definition in NATIVE_FAMILY_DRILLS})
        for definition in NATIVE_FAMILY_DRILLS:
            with self.subTest(family=definition.family, app=definition.package_id):
                spec = CATALOG[definition.package_id]
                self.assertEqual(definition.service_unit.removesuffix(".service").removesuffix(".timer"), spec["service_name"])
                self.assertIn(definition.version_path, VERSION_RECEIPT_EXPECTATIONS[definition.package_id])
                if spec["default_port"]:
                    self.assertEqual(definition.listener_port, spec["default_port"])
                elif definition.package_id == "quassel":
                    self.assertEqual(definition.listener_port, 4242)
                else:
                    self.assertEqual(definition.listener_port, 0)

    def assert_catalog_package_lifecycle(self, app):
        fixture = InstallerFixture(app)
        self.addCleanup(fixture.close)
        retained = canonical_state_sentinels_for_app(fixture.root, app)
        unrelated_sentinel = fixture.root / "var/lib/unrelated-operator-preserve.sentinel"
        for sentinel in (*retained, unrelated_sentinel):
            fixture.file(str(sentinel.relative_to(fixture.root)), "operator-owned history\n")
        if app == "dispatcharr":
            (fixture.root / "var/lib/dispatcharr").chmod(0o755)
            fixture.file("var/lib/dispatcharr/.aetherflow-data-owner", f"aetherflow-dispatcharr-data-v1:{fixture.root}/var/lib/dispatcharr\n").chmod(0o600)
        for action in ("install", "update", "reinstall", "uninstall"):
            with self.subTest(app=app, action=action):
                command_log = fixture.root / "commands.jsonl"
                command_offset = len(command_log.read_text()) if command_log.exists() else 0
                result = fixture.run(action, DELETE_DATA="false")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(fixture.lock.exists(), action != "uninstall")
                for sentinel in (*retained, unrelated_sentinel):
                    self.assertTrue(sentinel.is_file(), f"{action} removed canonical state: {sentinel}")
                    self.assertEqual(sentinel.read_text(), "operator-owned history\n")
                if action != "uninstall":
                    self.verify_active_state(fixture, fixture.metadata, action, command_offset=command_offset)
                else:
                    self.verify_version_receipts_removed(fixture)
        with self.subTest(app=app, action="install-after-retained-uninstall"):
            command_offset = len((fixture.root / "commands.jsonl").read_text())
            reinstall_after_uninstall = fixture.run("install", AF_FIXTURE_VERSION="2.1.0")
            self.assertEqual(reinstall_after_uninstall.returncode, 0, reinstall_after_uninstall.stdout + reinstall_after_uninstall.stderr)
            self.verify_active_state(fixture, fixture.metadata, "reinstall", command_offset=command_offset)
            for sentinel in (*retained, unrelated_sentinel):
                self.assertTrue(sentinel.is_file(), f"Install after retained uninstall removed: {sentinel}")
                self.assertEqual(sentinel.read_text(), "operator-owned history\n")
        with self.subTest(app=app, action="purge"):
            result = fixture.run("uninstall", DELETE_DATA="true")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertFalse(fixture.lock.exists())
            self.verify_version_receipts_removed(fixture)
            for sentinel in retained:
                self.assertFalse(sentinel.exists(), f"Purge retained canonical state: {sentinel}")
            self.assertTrue(unrelated_sentinel.is_file(), "Purge removed unrelated operator data")
            self.assertEqual(unrelated_sentinel.read_text(), "operator-owned history\n")

    def test_fetch_and_run_rejects_skip_and_mismatch_checksums(self):
        fixture = InstallerFixture("pihole")
        self.addCleanup(fixture.close)
        payload = '#!/bin/bash\nprintf "%s\\n" "$*" > "$AF_BOOTSTRAP_EXECUTED"\n'
        fixture.file("bootstrap-payload.sh", payload)
        digest = hashlib.sha256(payload.encode()).hexdigest()
        execution_marker = fixture.root / "bootstrap-executed"
        provenance_log = fixture.file("bootstrap-verification.log", "")
        helper = fixture.rewrite(common_functions("fetch_and_run"))
        program = r'''
log_info() { :; }
print_error() { printf '%s\n' "$*" >&2; }
curl() {
    local destination="" argument
    while [[ "$#" -gt 0 ]]; do
        argument="$1"; shift
        if [[ "$argument" == -o ]]; then destination="$1"; shift; fi
    done
    cp -- "$AF_FIXTURE_ROOT/bootstrap-payload.sh" "$destination"
}
''' + helper + '\nfetch_and_run https://fixture.invalid/bootstrap "$1" --fixture-argument\n'
        for checksum in ("SKIP", "", "0" * 64, "g" * 64, "0" * 63, "0" * 65, digest, digest.upper()):
            with self.subTest(checksum=checksum):
                execution_marker.unlink(missing_ok=True)
                provenance_log.write_text("")
                result = subprocess.run(["/bin/bash", "-euc", program, "fixture", checksum], env={
                    **os.environ, "AF_FIXTURE_ROOT": str(fixture.root),
                    "AF_BOOTSTRAP_EXECUTED": str(execution_marker), "LOGFILE": str(provenance_log),
                }, text=True, capture_output=True, timeout=15)
                if checksum.lower() == digest:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(execution_marker.read_text(), "--fixture-argument\n")
                    self.assertIn(f"[BOOTSTRAP-PROVENANCE] url=https://fixture.invalid/bootstrap sha256={digest}", provenance_log.read_text())
                else:
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertFalse(execution_marker.exists())
                    self.assertEqual(provenance_log.read_text(), "")
                self.assertFalse(list((fixture.root / "tmp").glob("aetherflow-install-*.sh")))

    def test_bootstrap_pins_match_vendor_digests_and_nodesource_verifies_them(self):
        for path, variable, expected_vendor_digest, payload in (
            (
                "packages/package/install/installpackage-pihole",
                "AF_PIHOLE_BOOTSTRAP_SHA256",
                "0c67c8f8358fede4b4dd8d51b429114461c9bb90ad56ff00ef05637f664bf3ac",
                PIHOLE_BOOTSTRAP_SCRIPT,
            ),
            (
                "packages/common.sh",
                "AF_NODESOURCE_BOOTSTRAP_SHA256",
                "2c4c6683a17b6f4128898a7b521e3c8bb725a99ffaf1b5e32ac97c6fa7d381be",
                NODESOURCE_BOOTSTRAP_SCRIPT,
            ),
        ):
            with self.subTest(variable=variable):
                source = (ROOT / path).read_text()
                pinned = re.search(re.escape(variable) + r":-([0-9a-fA-F]{64})", source)
                self.assertIsNotNone(pinned)
                self.assertEqual(pinned.group(1), expected_vendor_digest)
                self.assertNotEqual(pinned.group(1), hashlib.sha256(payload.encode()).hexdigest())
        pihole_fixture = InstallerFixture("pihole")
        self.addCleanup(pihole_fixture.close)
        unpinned_res = pihole_fixture.run("install", AF_PIHOLE_BOOTSTRAP_SHA256=None)
        self.assertNotEqual(unpinned_res.returncode, 0)
        self.assertFalse(pihole_fixture.lock.exists())
        fixture = InstallerFixture("pihole")
        self.addCleanup(fixture.close)
        helper = fixture.rewrite(common_functions("ensure_node"))
        program = 'source "$AF_FIXTURE_ROOT/packages/common.sh"\n' + helper + '''
command_exists() { [[ "$1" != node ]]; }
ensure_node 20
'''
        for checksum in ("0" * 64, hashlib.sha256(NODESOURCE_BOOTSTRAP_SCRIPT.encode()).hexdigest().upper()):
            with self.subTest(checksum=checksum):
                result = subprocess.run(["/bin/bash", "-euc", program], env={
                    **os.environ, "PATH": str(fixture.commands) + ":/usr/bin:/bin",
                    "AF_FIXTURE_ROOT": str(fixture.root), "AF_FIXTURE_APP": "pihole",
                    "AF_NODESOURCE_BOOTSTRAP_SHA256": checksum, "LOGFILE": str(fixture.root / "bootstrap.log"),
                }, text=True, capture_output=True, timeout=15)
                self.assertEqual(result.returncode == 0, checksum != "0" * 64, result.stdout + result.stderr)
                commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()]
                if checksum == "0" * 64:
                    self.assertFalse(any("nodejs" in command for command in commands))
                    self.assertNotIn("nodesource bootstrap", (fixture.root / "bootstrap.log").read_text())
                else:
                    self.assertTrue(any("nodejs" in command for command in commands))
                    self.assertIn("[BOOTSTRAP-PROVENANCE] url=https://deb.nodesource.com/setup_20.x", (fixture.root / "bootstrap.log").read_text())

    def test_all_77_remove_scripts_purge_canonical_state_sentinels(self):
        self.assertEqual(len(CATALOG_APPS), 77)
        sentinel_coverage_gaps = []
        for app in CATALOG_APPS:
            source = (ROOT / f"packages/package/remove/removepackage-{app}").read_text()
            var_lib_targets = set()
            for line in source.splitlines():
                if not line.lstrip().startswith("safe_rm_rf "):
                    continue
                tokens = shlex.split(line, comments=True)
                if tokens and tokens[0] == "safe_rm_rf":
                    var_lib_targets.update(token for token in tokens[1:] if token.startswith("/var/lib/"))
            if f"/var/lib/{app}" not in var_lib_targets:
                sentinel_coverage_gaps.append(app)
        self.assertEqual(sentinel_coverage_gaps, [])
        for app in CATALOG_APPS:
            with self.subTest(app=app):
                fixture = InstallerFixture(app)
                try:
                    retained = canonical_state_sentinels_for_app(fixture.root, app)
                    unrelated = fixture.root / "var/lib/unrelated-operator-preserve.sentinel"
                    for sentinel in (*retained, unrelated):
                        fixture.file(str(sentinel.relative_to(fixture.root)), "operator-owned history\n")
                    fixture.file("install/." + app + ".lock", "installed\n")
                    if app == "dispatcharr":
                        (fixture.root / "var/lib/dispatcharr").chmod(0o755)
                        fixture.file("var/lib/dispatcharr/.aetherflow-data-owner", f"aetherflow-dispatcharr-data-v1:{fixture.root}/var/lib/dispatcharr\n").chmod(0o600)
                    retained_result = fixture.run("uninstall", DELETE_DATA="false")
                    self.assertEqual(retained_result.returncode, 0, retained_result.stdout + retained_result.stderr)
                    self.assertFalse(fixture.lock.exists())
                    for sentinel in (*retained, unrelated):
                        self.assertTrue(sentinel.is_file(), f"Uninstall removed {sentinel}")
                        self.assertEqual(sentinel.read_text(), "operator-owned history\n")
                    fixture.file("install/." + app + ".lock", "installed\n")
                    purge_result = fixture.run("uninstall", DELETE_DATA="true")
                    self.assertEqual(purge_result.returncode, 0, purge_result.stdout + purge_result.stderr)
                    self.assertFalse(fixture.lock.exists())
                    for sentinel in retained:
                        self.assertFalse(sentinel.exists(), f"Purge retained {sentinel}")
                    self.assertTrue(unrelated.is_file())
                    self.assertEqual(unrelated.read_text(), "operator-owned history\n")
                finally:
                    fixture.close()

    def verify_active_state(self, fixture, spec, action, command_offset=0):
        app = fixture.app
        self.assertTrue(fixture.lock.exists(), f"Missing {action} install receipt")
        units = list((fixture.root / "etc/systemd/system").glob("*.service"))
        units += list((fixture.root / "usr/lib/systemd/system").glob("*.service"))
        self.assertTrue(units, "No managed or vendor unit")
        unit = spec["service_name"] + (".timer" if app == "recyclarr" else ".service")
        self.assertTrue((fixture.root / ("active-" + unit)).exists(), "Catalog service was not started")
        for relative in VERSION_RECEIPT_EXPECTATIONS[app]:
            version_file = fixture.root / relative
            self.assertTrue(version_file.is_file(), f"Missing {action} version receipt: {relative}")
            self.assertTrue(version_file.read_text().strip(), f"Empty version receipt: {version_file}")
            self.assertFalse(version_file.is_symlink())
        for relative, pattern in PORT_CONFIG_EXPECTATIONS[app]:
            config = fixture.root / relative
            self.assertTrue(config.is_file(), f"Missing {action} application configuration: {relative}")
            content = config.read_text()
            if relative == "commands.jsonl":
                content = content[command_offset:]
            self.assertRegex(content, pattern.replace("{port}", re.escape(str(spec["default_port"]))), f"{app}: {action} configuration/listener/unit mismatch in {relative}")
        if app == "filebrowser":
            self.assertTrue((fixture.root / "opt/filebrowser/filebrowser.db").is_file())
        elif app == "unpackerr":
            self.assertTrue((fixture.root / "etc/unpackerr/unpackerr.conf").is_file())
        elif app == "mergerfs":
            self.assertTrue((fixture.root / "etc/fuse.conf").is_file())
        if app == "prometheus":
            for alias, binary in (("prometheus", "prometheus"), ("prometheus-node-exporter", "node_exporter")):
                alias_path = fixture.root / "usr/bin" / alias
                self.assertTrue(alias_path.is_symlink())
                self.assertEqual(alias_path.resolve(), fixture.root / "usr/local/bin" / binary)

    def verify_version_receipts_removed(self, fixture):
        for relative in VERSION_RECEIPT_EXPECTATIONS[fixture.app]:
            version_file = fixture.root / relative
            self.assertFalse(version_file.exists(), f"Uninstall retained active version receipt: {relative}")
            self.assertFalse(version_file.is_symlink(), f"Uninstall retained a linked version receipt: {relative}")


def catalog_test(app):
    def test(self):
        self.assert_catalog_package_lifecycle(app)
    return test


for catalog_app in CATALOG_APPS:
    setattr(CatalogLifecycleMatrix, f"test_{catalog_app.replace('-', '_')}_install_update_reinstall_uninstall", catalog_test(catalog_app))


class CatalogCredentialAndFailureTests(unittest.TestCase):
    def fixture(self, app):
        fixture = InstallerFixture(app)
        self.addCleanup(fixture.close)
        return fixture

    def assert_success(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_invidious_failed_update_rolls_back_migrated_postgresql_state(self):
        fixture = self.fixture("invidious")
        self.assert_success(fixture.run("install"))
        database = fixture.file("var/lib/postgresql/fixture-invidious-schema", "schema-v1\n")
        version = fixture.root / "opt/invidious/.af-version"
        previous_version = version.read_bytes()
        command = fixture.commands / "runuser"
        anchor = "failure = os.environ.get('AF_FIXTURE_FAILURE', '')"
        command.write_text(command.read_text().replace(
            anchor,
            anchor + "\nif command == 'runuser' and any('--migrate' in argument for argument in arguments):\n"
            "    (root / 'var/lib/postgresql/fixture-invidious-schema').write_text('schema-v2-migrated\\n')",
            1,
        ))
        result = fixture.run("update", AF_FIXTURE_FAILURE="service",
                             AF_FIXTURE_FAILURE_UNIT="af-invidious.service", AF_FIXTURE_VERSION="3.0.0")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(database.read_text(), "schema-v1\n")
        self.assertEqual(version.read_bytes(), previous_version)
        commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()]
        self.assertTrue(any("pg_dump" in entry for entry in commands))
        self.assertTrue(any("psql" in entry and "-f" in entry for entry in commands))

    def test_rclone_update_rejects_config_symlink_without_chmodding_target(self):
        fixture = self.fixture("rclone")
        victim = fixture.file("etc/operator-protected.conf", "unchanged operator configuration\n")
        victim.chmod(0o444)
        config = fixture.root / "etc/rclone/rclone.conf"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.symlink_to(victim)
        result = fixture.run("update")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(config.is_symlink())
        self.assertEqual(victim.stat().st_mode & 0o777, 0o444)
        self.assertEqual(victim.read_text(), "unchanged operator configuration\n")

    def test_xrdp_update_preserves_operator_custom_startwm_session(self):
        fixture = self.fixture("xrdp")
        session = "#!/bin/sh\nexec operator-custom-desktop\n"
        config = fixture.file("etc/xrdp/startwm.sh", session)
        for action in ("update", "reinstall"):
            with self.subTest(action=action):
                self.assert_success(fixture.run(action))
                self.assertEqual(config.read_text(), session)

    def test_retained_uninstall_preserves_system_user_until_explicit_purge(self):
        fixture = self.fixture("rclone")
        self.assert_success(fixture.run("install"))
        fixture.file("mock-bin/getent", "#!/bin/sh\nexit 0\n").chmod(0o755)
        retained = fixture.file("var/lib/rclone/operator-data", "private operator state\n")
        command_log = fixture.root / "commands.jsonl"
        command_log.write_text("")
        self.assert_success(fixture.run("uninstall", DELETE_DATA="false"))
        commands = [json.loads(line) for line in command_log.read_text().splitlines()]
        self.assertFalse(any(entry[0] in ("userdel", "groupdel") for entry in commands))
        self.assertTrue(retained.is_file())
        command_log.write_text("")
        self.assert_success(fixture.run("uninstall", DELETE_DATA="true"))
        commands = [json.loads(line) for line in command_log.read_text().splitlines()]
        self.assertIn(["userdel", "rclone"], commands)
        self.assertIn(["groupdel", "rclone"], commands)
        self.assertFalse(retained.exists())

    def test_remote_desktop_updates_preserve_custom_vnc_startup_sessions(self):
        for app in ("novnc", "kasmvnc"):
            with self.subTest(app=app):
                fixture = self.fixture(app)
                session = "#!/bin/sh\nexec operator-custom-desktop\n"
                config = fixture.file(f"var/lib/{app}/.vnc/xstartup", session)
                for action in ("update", "reinstall"):
                    self.assert_success(fixture.run(action))
                    self.assertEqual(config.read_text(), session)

    def test_audiobookshelf_allocated_port_matches_vendor_defaults_and_unit(self):
        fixture = self.fixture("audiobookshelf")
        defaults = fixture.file("etc/default/audiobookshelf", "PORT=13378\nOPERATOR_SETTING=retained\n")
        self.assert_success(fixture.run("update", port=23456))
        self.assertIn("PORT=23456", defaults.read_text())
        self.assertIn("OPERATOR_SETTING=retained", defaults.read_text())
        self.assertIn("Environment=PORT=23456", (fixture.root / "etc/systemd/system/audiobookshelf.service").read_text())

    def test_database_migrating_catalog_siblings_restore_state_after_activation_failure(self):
        cases = (
            ("piped", "var/lib/postgresql/fixture-piped-schema", "af-piped.service"),
            ("palate", "var/lib/postgresql/fixture-palate-schema", "af-palate.service"),
            ("dispatcharr", "var/lib/postgresql/fixture-dispatcharr-schema", "dispatcharr.service"),
            ("paperless-ngx", "var/lib/paperless/data/db.sqlite3", "paperless-webserver.service"),
            ("gitea", "var/lib/gitea/data/gitea.db", "gitea.service"),
            ("seedcross", "var/lib/seedcross/db/db.sqlite3", "seedcross.service"),
            ("ombi", "var/lib/ombi/Ombi.db", "ombi.service"),
            ("requestrr", "var/lib/requestrr/config/settings.db", "requestrr.service"),
        )
        for app, relative, unit in cases:
            with self.subTest(app=app):
                fixture = self.fixture(app)
                self.assert_success(fixture.run("install"))
                database = fixture.file(relative, "schema-v1\n")
                result = fixture.run("update", AF_FIXTURE_FAILURE="service", AF_FIXTURE_FAILURE_UNIT=unit,
                                     AF_FIXTURE_MIGRATION_STATE=relative, AF_FIXTURE_VERSION="3.0.0")
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue((fixture.root / "service-failed").is_file(), "Service failure was not reached")
                self.assertEqual(database.read_text(), "schema-v1\n")

    def test_catalog_recursive_ownership_changes_never_dereference_symlinks(self):
        for script in sorted((ROOT / "packages/package/install").glob("installpackage-*")):
            with self.subTest(script=script.name):
                self.assertNotRegex(script.read_text(), r"\bchown\s+-R\s")

    def test_catalog_account_removal_is_explicitly_inside_data_purge_branch(self):
        for script in sorted((ROOT / "packages/package/remove").glob("removepackage-*")):
            with self.subTest(script=script.name):
                branches = []
                for line in script.read_text().splitlines():
                    statement = line.strip()
                    if statement.startswith("if ") and statement.endswith("then"):
                        branches.append("DELETE_DATA" in statement and "true" in statement)
                    elif statement == "else" and branches:
                        branches[-1] = False
                    elif statement == "fi" and branches:
                        branches.pop()
                    if statement.startswith("purge_system_user "):
                        self.assertTrue(any(branches), f"Ungated system account deletion: {line}")

    def test_catalog_config_permission_updates_reject_operator_file_symlinks(self):
        for app, relative in (
            ("qui", "var/lib/qui/config.toml"), ("autoscan", "etc/autoscan/config.yml"),
            ("novnc", "var/lib/novnc/.vnc/passwd"), ("kasmvnc", "var/lib/kasmvnc/.kasmpasswd"),
            ("quassel", "var/lib/quassel/quasselCert.pem"), ("znc", "var/lib/znc/znc.pem"),
            ("xrdp", "etc/xrdp/startwm.sh"), ("recyclarr", "var/lib/recyclarr/recyclarr.yml"),
        ):
            with self.subTest(app=app):
                fixture = self.fixture(app)
                victim = fixture.file("etc/operator-protected.conf", "operator configuration\n")
                victim.chmod(0o444)
                config = fixture.root / relative
                config.parent.mkdir(parents=True, exist_ok=True)
                config.symlink_to(victim)
                result = fixture.run("update")
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(victim.read_text(), "operator configuration\n")
                self.assertEqual(victim.stat().st_mode & 0o777, 0o444)

    def test_prometheus_retained_reinstall_download_failure_preserves_concurrent_state_writes(self):
        fixture = self.fixture("prometheus")
        self.assert_success(fixture.run("install"))
        history = fixture.file("var/lib/prometheus/history.sentinel", "retained history\n")
        receipt = fixture.lock.read_bytes(), fixture.lock.stat().st_mtime_ns
        command_count = len((fixture.root / "commands.jsonl").read_text().splitlines())
        fixture.file("mock-bin/curl", """#!/usr/bin/python3
import os, pathlib, sys
root = pathlib.Path(os.environ['AF_FIXTURE_ROOT'])
(root / 'var/lib/prometheus/recent-write.sentinel').write_text('concurrent state write\\n')
sys.exit(22)
""").chmod(0o755)
        result = fixture.run("reinstall")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(history.read_text(), "retained history\n")
        self.assertEqual((fixture.root / "var/lib/prometheus/recent-write.sentinel").read_text(), "concurrent state write\n")
        self.assertTrue(fixture.lock.exists())
        self.assertEqual((fixture.lock.read_bytes(), fixture.lock.stat().st_mtime_ns), receipt)
        commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()[command_count:]]
        self.assertFalse(any(entry[:2] in (["systemctl", "stop"], ["systemctl", "restart"]) for entry in commands))

    def test_paperless_retained_reinstall_aborts_before_mutation_when_service_stop_fails(self):
        fixture = self.fixture("paperless-ngx")
        self.assert_success(fixture.run("install"))
        runtime = fixture.file("opt/paperless/prior-runtime.sentinel", "retained runtime\n")
        environment = fixture.file("opt/paperless/.venv/prior-environment.sentinel", "retained environment\n")
        config = fixture.root / "etc/paperless.conf"
        original = config.read_bytes(), runtime.stat().st_ino, environment.stat().st_ino
        receipt = fixture.lock.read_bytes(), fixture.lock.stat().st_mtime_ns
        command_count = len((fixture.root / "commands.jsonl").read_text().splitlines())
        fixture.file("mock-bin/systemctl", """#!/usr/bin/python3
import os, pathlib, sys
root = pathlib.Path(os.environ['AF_FIXTURE_ROOT'])
arguments = sys.argv[1:]
if arguments and arguments[0] == 'stop':
    (root / 'stop-refused').touch()
    sys.exit(73)
os.execv(str(root / 'usr/bin/systemctl'), [str(root / 'usr/bin/systemctl'), *arguments])
""").chmod(0o755)
        result = fixture.run("reinstall")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((fixture.root / "stop-refused").exists())
        commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()[command_count:]]
        self.assertFalse(any("manage.py" in str(entry) for entry in commands), commands)
        self.assertFalse(any(entry[:3] == ["python3", "-m", "venv"] for entry in commands), commands)
        self.assertEqual((config.read_bytes(), runtime.stat().st_ino, environment.stat().st_ino), original)
        self.assertEqual(runtime.read_text(), "retained runtime\n")
        self.assertEqual(environment.read_text(), "retained environment\n")
        self.assertTrue(fixture.lock.exists())
        self.assertEqual((fixture.lock.read_bytes(), fixture.lock.stat().st_mtime_ns), receipt)

    def test_retained_installers_preserve_runtime_when_required_service_stop_fails(self):
        for app, runtime_directory in (
            ("sabnzbd", "opt/SABnzbd"), ("calibreweb", "opt/calibre-web"),
            ("cloudplow", "opt/cloudplow"), ("flaresolverr", "opt/flaresolverr"),
            ("homeassistant", "srv/homeassistant"), ("overseerr", "opt/overseerr"),
            ("tautulli", "opt/Tautulli"), ("thelounge", "opt/thelounge"),
            ("unmanic", "opt/unmanic"), ("pyload", "opt/pyload"),
            ("n8n", "opt/n8n"), ("prometheus", "etc/prometheus"),
            ("listenarr", "opt/listenarr"),
        ):
            with self.subTest(app=app):
                fixture = self.fixture(app)
                self.assert_success(fixture.run("install"))
                runtime = fixture.file(runtime_directory + "/retained-runtime.sentinel", "retained runtime\n")
                state = fixture.file("var/lib/" + app + "/retained-state.sentinel", "retained state\n")
                original = runtime.stat().st_ino, state.stat().st_ino, fixture.lock.read_bytes(), fixture.lock.stat().st_mtime_ns
                result = fixture.run("reinstall", AF_FIXTURE_FAILURE="stop")
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual((runtime.stat().st_ino, state.stat().st_ino, fixture.lock.read_bytes(), fixture.lock.stat().st_mtime_ns), original)
                self.assertEqual(runtime.read_text(), "retained runtime\n")
                self.assertEqual(state.read_text(), "retained state\n")

    def test_prometheus_node_exporter_download_failure_precedes_quiescence(self):
        fixture = self.fixture("prometheus")
        self.assert_success(fixture.run("install"))
        state = fixture.file("var/lib/prometheus/history.sentinel", "retained state\n")
        command_count = len((fixture.root / "commands.jsonl").read_text().splitlines())
        fixture.file("mock-bin/curl", """#!/usr/bin/python3
import os, pathlib, sys
root = pathlib.Path(os.environ['AF_FIXTURE_ROOT'])
arguments = sys.argv[1:]
if any('node_exporter' in argument for argument in arguments):
    (root / 'var/lib/prometheus/recent-write.sentinel').write_text('concurrent state write\\n')
    sys.exit(22)
os.execv(str(root / 'usr/bin/curl'), [str(root / 'usr/bin/curl'), *arguments])
""").chmod(0o755)
        result = fixture.run("reinstall")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(state.read_text(), "retained state\n")
        self.assertTrue((fixture.root / "var/lib/prometheus/recent-write.sentinel").exists())
        self.assertTrue(fixture.lock.exists())
        commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()[command_count:]]
        self.assertFalse(any(entry[:2] in (["systemctl", "stop"], ["systemctl", "restart"]) for entry in commands))

    def test_flood_retained_reinstall_restarts_service_and_rejects_empty_version(self):
        fixture = self.fixture("flood")
        fixture.file("mock-bin/systemctl", """#!/usr/bin/python3
import os, pathlib, sys
root = pathlib.Path(os.environ['AF_FIXTURE_ROOT'])
arguments = sys.argv[1:]
if arguments and arguments[0] in ('enable', 'start', 'restart') and 'flood' in arguments:
    if arguments[0] == 'restart' or not (root / 'active-flood.service').exists():
        (root / 'active-runtime-version').write_text(os.environ['AF_FIXTURE_VERSION'])
os.execv(str(root / 'usr/bin/systemctl'), [str(root / 'usr/bin/systemctl'), *arguments])
""").chmod(0o755)
        self.assert_success(fixture.run("install", AF_FIXTURE_VERSION="2.1.0"))
        command_count = len((fixture.root / "commands.jsonl").read_text().splitlines())
        self.assert_success(fixture.run("reinstall", AF_FIXTURE_VERSION="2.2.0"))
        commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()[command_count:]]
        self.assertIn(["systemctl", "restart", "flood"], commands)
        self.assertEqual((fixture.root / "active-runtime-version").read_text(), "2.2.0")
        self.assertEqual((fixture.root / "var/lib/flood/.af-version").read_text().strip(), "2.2.0")
        fresh = self.fixture("flood")
        result = fresh.run("install", AF_FIXTURE_VERSION="")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(fresh.lock.exists())
        self.assertFalse((fresh.root / "var/lib/flood/.af-version").exists())
        self.assertFalse((fresh.root / "etc/systemd/system/flood.service").exists())
        self.assertFalse((fresh.root / "active-flood.service").exists())

    def test_flood_duplicati_and_fail2ban_fail_closed_when_service_readiness_unavailable(self):
        for app in ("flood", "duplicati", "fail2ban", "emby", "jellyfin"):
            with self.subTest(app=app):
                fixture = self.fixture(app)
                result = fixture.run("install", AF_FIXTURE_FAILURE="readiness")
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(fixture.lock.exists())
                if app in ("flood", "duplicati", "fail2ban"):
                    self.assertFalse((fixture.root / ("active-" + fixture.metadata["service_name"] + ".service")).exists())
                    version = "etc/fail2ban/.af-version" if app == "fail2ban" else "var/lib/" + app + "/.af-version"
                    self.assertFalse((fixture.root / version).exists())

    def test_activation_failure_restores_flood_duplicati_and_fail2ban_metadata(self):
        for app, runtime_paths in (
            ("flood", ("opt/flood/node_modules/.bin/flood", "usr/local/bin/flood", "var/lib/flood/.af-version", "etc/systemd/system/flood.service")),
            ("duplicati", ("etc/duplicati/duplicati.env", "var/lib/duplicati/.af-version", "etc/systemd/system/duplicati.service")),
            ("fail2ban", ("etc/fail2ban/.af-version", "etc/fail2ban/jail.d/10-aetherflow.local")),
        ):
            for failure in ("service", "readiness"):
                with self.subTest(app=app, failure=failure):
                    fixture = self.fixture(app)
                    self.assert_success(fixture.run("install"))
                    state = fixture.file("var/lib/" + app + "/history.sentinel", "retained state\n")
                    previous = {relative: (fixture.root / relative).read_bytes() for relative in runtime_paths}
                    receipt = fixture.lock.read_bytes(), fixture.lock.stat().st_mtime_ns
                    result = fixture.run("reinstall", AF_FIXTURE_VERSION="2.2.0", AF_FIXTURE_FAILURE=failure)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual({relative: (fixture.root / relative).read_bytes() for relative in runtime_paths}, previous)
                    self.assertEqual(state.read_text(), "retained state\n")
                    self.assertEqual((fixture.lock.read_bytes(), fixture.lock.stat().st_mtime_ns), receipt)

    def test_deluge_rejects_symlink_hardlink_and_symlinked_parent_config_targets(self):
        for filename in ("web.conf", "auth"):
            for variant in ("symlink", "hardlink", "symlink-parent"):
                with self.subTest(filename=filename, variant=variant):
                    fixture = self.fixture("deluge")
                    original = json.dumps({"operator": "retained", "pwd_salt": "retained", "pwd_sha1": "retained-hash", "port": 1234})
                    target = fixture.file("root/config-target/" + filename, original)
                    config = fixture.root / "var/lib/deluge/.config/deluge" / filename
                    config.parent.mkdir(parents=True)
                    if variant == "symlink-parent":
                        config.parent.rmdir()
                        config.parent.symlink_to(target.parent, target_is_directory=True)
                    elif variant == "hardlink":
                        os.link(target, config)
                    else:
                        config.symlink_to(target)
                    before = (target.read_bytes(), target.stat().st_mode, target.stat().st_mtime_ns)
                    result = fixture.run("update", 16767)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual((target.read_bytes(), target.stat().st_mode, target.stat().st_mtime_ns), before)
                    self.assertFalse(fixture.lock.exists())

    def test_managed_config_adapter_preserves_metadata_and_uses_atomic_replacement(self):
        fixture = self.fixture("deluge")
        config = fixture.file("root/managed/config.json", '{"operator": "retained"}\n')
        config.chmod(0o600)
        before = config.stat()
        with config.open() as old_descriptor:
            program = common_functions("safe_config_python") + r'''
safe_config_python "$1" <<'PYEOF'
import sys
with ManagedConfig(sys.argv[1]) as config:
    text = config.read_text()
    config.write_text(text + 'updated\n')
    assert config.read_text() == text + 'updated\n'
PYEOF
'''
            result = subprocess.run(["bash", "-euc", program, "fixture", str(config)], text=True, capture_output=True, timeout=10)
            self.assert_success(result)
            self.assertEqual(old_descriptor.read(), '{"operator": "retained"}\n')
        after = config.stat()
        self.assertNotEqual(after.st_ino, before.st_ino)
        self.assertEqual((after.st_uid, after.st_gid, after.st_mode, after.st_nlink), (before.st_uid, before.st_gid, before.st_mode, 1))
        self.assertEqual(config.read_text(), '{"operator": "retained"}\nupdated\n')
        self.assertEqual(list(config.parent.glob(".af-config.*")), [])

    def test_inline_config_mutators_reject_linked_configuration_targets(self):
        targets = (
            ("dispatcharr", "etc/dispatcharr/dispatcharr.env"),
            ("grafana", "etc/grafana/grafana.ini"),
            ("invidious", "etc/invidious/config.yml"),
            ("kasmvnc", "var/lib/kasmvnc/.vnc/kasmvnc.yaml"),
            ("librespeed", "opt/librespeed/settings.toml"),
            ("mcvnc", "etc/mcvnc/mcvnc.env"),
            ("notifiarr", "etc/notifiarr/notifiarr.conf"),
            ("paperless-ngx", "etc/paperless.conf"),
            ("palate", "etc/palate/palate.env"),
            ("piped", "etc/piped/config.properties"),
            ("seedcross", "var/lib/seedcross/runtime.json"),
            ("transmission", "var/lib/transmission-daemon/.config/transmission-daemon/settings.json"),
            ("znc", "var/lib/znc/configs/znc.conf"),
            ("calibreweb", "var/lib/calibre-web/app.db"),
            ("scrutiny", "etc/scrutiny/scrutiny.yaml"),
        )
        for app, relative in targets:
            for variant in ("symlink", "hardlink", "symlink-parent"):
                with self.subTest(app=app, variant=variant):
                    fixture = self.fixture(app)
                    config = fixture.root / relative
                    config.parent.mkdir(parents=True, exist_ok=True)
                    if config.exists():
                        config.unlink()
                    target = fixture.file("root/config-target/" + config.name, "operator-configuration\n")
                    if variant == "symlink-parent":
                        shutil.copytree(config.parent, target.parent, dirs_exist_ok=True, symlinks=True)
                        shutil.rmtree(config.parent)
                        config.parent.symlink_to(target.parent, target_is_directory=True)
                    elif variant == "hardlink":
                        os.link(target, config)
                    else:
                        config.symlink_to(target)
                    before = (target.read_bytes(), target.stat().st_mode, target.stat().st_mtime_ns)
                    result = fixture.run("update")
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual((target.read_bytes(), target.stat().st_mode, target.stat().st_mtime_ns), before)
                    self.assertFalse(fixture.lock.exists())

    def test_managed_config_adapter_rejects_nonregular_targets(self):
        for variant in ("fifo", "directory", "dangling-symlink"):
            with self.subTest(variant=variant):
                fixture = self.fixture("deluge")
                config = fixture.root / "root/config.json"
                if variant == "fifo":
                    os.mkfifo(config)
                elif variant == "directory":
                    config.mkdir()
                else:
                    config.symlink_to(fixture.root / "root/missing-config.json")
                program = common_functions("safe_config_python", "validate_config_paths") + '\nvalidate_config_paths "$1"\n'
                result = subprocess.run(["bash", "-euc", program, "fixture", str(config)], text=True, capture_output=True, timeout=10)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse((fixture.root / "root/missing-config.json").exists())

    def test_notifiarr_rejects_linked_integration_configuration_targets(self):
        for variant in ("symlink", "hardlink", "symlink-parent"):
            with self.subTest(variant=variant):
                fixture = self.fixture("notifiarr")
                target = fixture.file("root/config-target/config.xml", "<Config><ApiKey>retained-key</ApiKey></Config>\n")
                config = fixture.root / "var/lib/sonarr/config.xml"
                config.parent.mkdir()
                if variant == "symlink-parent":
                    config.parent.rmdir()
                    config.parent.symlink_to(target.parent, target_is_directory=True)
                elif variant == "hardlink":
                    os.link(target, config)
                else:
                    config.symlink_to(target)
                before = target.read_bytes()
                result = fixture.run("update")
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(target.read_bytes(), before)
                self.assertFalse(fixture.lock.exists())

    def test_audiobookshelf_first_run_bootstrap_failure_fails_closed(self):
        fixture = self.fixture("audiobookshelf")
        result = fixture.run("install", AF_FIXTURE_FAILURE="bootstrap-python")
        self.assertEqual(result.returncode, 79, result.stdout + result.stderr)
        self.assertFalse(fixture.lock.exists())
        self.assertFalse((fixture.root / "active-audiobookshelf.service").exists())
        self.assertFalse((fixture.root / "etc/systemd/system/audiobookshelf.service").exists())
        self.assertFalse((fixture.root / "opt/audiobookshelf/.af-version").exists())

    def test_first_run_account_bootstrap_failures_rollback_archive_installers(self):
        for app in ("navidrome", "kavita", "ombi"):
            with self.subTest(app=app):
                fixture = self.fixture(app)
                result = fixture.run("install", AF_FIXTURE_FAILURE="bootstrap-python")
                self.assertEqual(result.returncode, 79, result.stdout + result.stderr)
                self.assertFalse(fixture.lock.exists())
                self.assertFalse((fixture.root / ("active-" + app + ".service")).exists())
                self.assertFalse((fixture.root / "etc/systemd/system" / (app + ".service")).exists())

    def test_audiobookshelf_failed_update_restores_prior_configuration_and_service(self):
        fixture = self.fixture("audiobookshelf")
        config = fixture.file("etc/default/audiobookshelf", "PORT=13378\nOPERATOR_SETTING=retained\n")
        unit = fixture.file("etc/systemd/system/audiobookshelf.service", "[Service]\nExecStart=/retained/audiobookshelf\n")
        version = fixture.file("opt/audiobookshelf/.af-version", "1.0.0\n")
        fixture.file("active-audiobookshelf.service", "active\n")
        receipt = fixture.file("install/.audiobookshelf.lock", "prior-receipt\n")
        paths = (config, unit, version, receipt)
        before = [path.read_bytes() for path in paths]
        result = fixture.run("update", AF_FIXTURE_FAILURE="bootstrap-python")
        self.assertEqual(result.returncode, 79, result.stdout + result.stderr)
        self.assertEqual([path.read_bytes() for path in paths], before)
        self.assertTrue((fixture.root / "active-audiobookshelf.service").exists())

    def test_pihole_retained_uninstall_preserves_lighttpd_configuration_and_purge_removes_it(self):
        fixture = self.fixture("pihole")
        original = 'server.name = "operator.example"\ninclude "operator-extra.conf"\nserver.port := 8089\n'
        paths = [fixture.file(relative, original) for relative in ("etc/lighttpd/external.conf", "etc/lighttpd/conf-enabled/99-pihole-port.conf")]
        self.assert_success(fixture.run("uninstall", DELETE_DATA="false"))
        for path in paths:
            self.assertTrue(path.exists())
            self.assertEqual(path.read_text(), original)
        self.assert_success(fixture.run("uninstall", DELETE_DATA="true"))
        for path in paths:
            self.assertFalse(path.exists())

    def test_pihole_failed_bootstrap_restores_systemd_resolved_stub_and_dropin(self):
        fixture = self.fixture("pihole")
        stub = fixture.file("run/systemd/resolve/stub-resolv.conf", "nameserver 127.0.0.53\n")
        fixture.file("run/systemd/resolve/resolv.conf", "nameserver 192.0.2.53\n")
        resolver = fixture.root / "etc/resolv.conf"
        resolver.unlink()
        resolver.symlink_to(stub)
        original_link = os.readlink(resolver)
        fixture.file("active-systemd-resolved.service", "active\n")
        result = fixture.run("install", AF_FIXTURE_FAILURE="bootstrap")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(os.readlink(resolver), original_link)
        self.assertFalse((fixture.root / "etc/systemd/resolved.conf.d/pihole.conf").exists())
        self.assertFalse((fixture.root / "etc/pihole/setupVars.conf").exists())
        self.assertFalse(fixture.lock.exists())
        commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()]
        self.assertGreaterEqual(commands.count(["systemctl", "restart", "systemd-resolved"]), 2)

    def test_pihole_failed_bootstrap_restores_existing_configuration(self):
        fixture = self.fixture("pihole")
        paths = [fixture.file(relative, text) for relative, text in (
            ("etc/systemd/resolved.conf.d/pihole.conf", "[Resolve]\nDNSStubListener=yes\n"),
            ("etc/pihole/setupVars.conf", "WEBPASSWORD=retained-hash\n"),
            ("etc/lighttpd/external.conf", 'server.name = "operator.example"\n'),
        )]
        paths.append(fixture.root / "etc/resolv.conf")
        before = [path.read_bytes() for path in paths]
        fixture.file("active-systemd-resolved.service", "active\n")
        result = fixture.run("update", AF_FIXTURE_FAILURE="bootstrap")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual([path.read_bytes() for path in paths], before)
        self.assertFalse(fixture.lock.exists())

    def test_pihole_rejects_linked_lighttpd_configuration_targets(self):
        for relative in ("etc/lighttpd/external.conf", "etc/lighttpd/conf-enabled/99-pihole-port.conf"):
            for variant in ("symlink", "hardlink", "symlink-parent"):
                with self.subTest(relative=relative, variant=variant):
                    fixture = self.fixture("pihole")
                    original = 'server.name = "operator.example"\nserver.port := 8089\n'
                    config = fixture.root / relative
                    target = fixture.file("root/lighttpd-target/" + config.name, original)
                    if variant == "symlink-parent":
                        shutil.rmtree(config.parent)
                        config.parent.symlink_to(target.parent, target_is_directory=True)
                    elif variant == "hardlink":
                        os.link(target, config)
                    else:
                        config.symlink_to(target)
                    result = fixture.run("update", 18089)
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(target.read_text(), original)
                    self.assertFalse(fixture.lock.exists())

    def test_fail2ban_update_preserves_operator_jail_local_policy(self):
        fixture = self.fixture("fail2ban")
        original = "[DEFAULT]\nmaxretry = 20\n[sshd]\nenabled = false\nport = 2222\n"
        config = fixture.file("etc/fail2ban/jail.local", original)
        fixture.file("etc/ssh/sshd_config", "Port 2200\n")
        self.assert_success(fixture.run("update"))
        self.assertEqual(config.read_bytes(), original.encode())

    def run_account_bootstrap(self, app, request, retained=False):
        source = (ROOT / "packages/package/install" / ("installpackage-" + app)).read_text()
        program = next(block for block in re.findall(r"<<'PYEOF'\n(.*?)\nPYEOF", source, re.DOTALL) if "urllib.request" in block)
        with mock.patch.dict(os.environ, {"AF_APP_PORT": "12345", "MASTER_USER": "admin", "MASTER_PASS": "fixture-password", "AF_SEED_USER": "admin", "AF_SEED_PASS": "fixture-password", "AF_BOOTSTRAP_RETAINED": "1" if retained else "0"}):
            with mock.patch.object(sys, "argv", ["-", "admin", "fixture-password"]), mock.patch("urllib.request.urlopen", side_effect=request), mock.patch("time.sleep"):
                exec(compile(program, str(ROOT / "packages/package/install" / ("installpackage-" + app)), "exec"), {})

    def test_account_bootstrap_status_failure_never_attempts_initialization(self):
        for app, attempts in (("audiobookshelf", 30), ("navidrome", 30), ("kavita", 120), ("ombi", 30)):
            with self.subTest(app=app):
                requests = mock.Mock(side_effect=urllib.error.URLError("fixture endpoint unavailable"))
                with self.assertRaises(SystemExit) as exited:
                    self.run_account_bootstrap(app, requests)
                self.assertNotEqual(exited.exception.code, 0)
                self.assertEqual(requests.call_count, attempts)
                self.assertTrue(all(isinstance(call.args[0], str) for call in requests.call_args_list))

    def test_audiobookshelf_initialized_status_skips_initialization(self):
        response = mock.MagicMock(status=200)
        response.__enter__.return_value = response
        response.read.return_value = b'{"isInit": true}'
        requests = mock.Mock(return_value=response)
        with self.assertRaises(SystemExit) as exited:
            self.run_account_bootstrap("audiobookshelf", requests)
        self.assertEqual(exited.exception.code, 0)
        self.assertEqual(requests.call_count, 1)

    def test_account_bootstrap_existing_account_responses_are_idempotent(self):
        for app in ("navidrome", "kavita", "ombi"):
            source = (ROOT / "packages/package/install" / ("installpackage-" + app)).read_text()
            self.assertLess(source.index('ADMIN_RETAINED=0'), source.index('stage_app_archive '))
            for status in (400, 403, 409):
                for retained in (False, True):
                    with self.subTest(app=app, status=status, retained=retained):
                        response = mock.MagicMock(status=200)
                        response.__enter__.return_value = response
                        detail = b'Administrator already exists' if not retained else b'Registration disabled'
                        error = urllib.error.HTTPError("http://fixture.invalid", status, "fixture response", {}, io.BytesIO(detail))
                        self.run_account_bootstrap(app, [response, error], retained=retained)

    def test_account_bootstrap_network_and_unrelated_http_failures_propagate(self):
        for app in ("audiobookshelf", "navidrome", "kavita", "ombi"):
            for failure in ("network", "http"):
                with self.subTest(app=app, failure=failure):
                    response = mock.MagicMock(status=200)
                    response.__enter__.return_value = response
                    response.read.return_value = b'{"isInit": false}'
                    error = urllib.error.URLError("fixture unavailable") if failure == "network" else urllib.error.HTTPError("http://fixture.invalid", 400, "fixture response", {}, io.BytesIO(b'Invalid account configuration'))
                    with self.assertRaises(urllib.error.URLError):
                        self.run_account_bootstrap(app, [response, error])

    def test_github_discovery_outage_fails_closed_without_downgrading_installed_app(self):
        fixture = self.fixture("gitea")
        initial = fixture.run("install")
        self.assert_success(initial)
        version_file = fixture.root / "var/lib/gitea/.af-version"
        initial_version = version_file.read_text().strip()
        self.assertEqual(initial_version, "2.1.0")
        installed_binary = fixture.root / "usr/local/bin/gitea"
        initial_binary = installed_binary.read_bytes()
        wrapper = r'''
curl() {
    case "$*" in
        *github.com/go-gitea/gitea/releases/latest*|*api.github.com/repos/go-gitea/gitea/releases/latest*)
            return 22 ;;
    esac
    command curl "$@"
}
'''
        for relative in ("packages/common.sh", "opt/AetherFlow/packages/common.sh"):
            with (fixture.root / relative).open("a") as output:
                output.write("\n" + common_functions("github_latest_tag") + "\n" + wrapper)
        updated = fixture.run("update", AF_ALLOW_RELEASE_FALLBACK=None, AF_ALLOW_DOWNGRADE=None)
        self.assertNotEqual(updated.returncode, 0, updated.stdout + updated.stderr)
        self.assertIn("Failed to discover latest GitHub release for go-gitea/gitea", updated.stderr)
        self.assertEqual(version_file.read_text().strip(), initial_version)
        self.assertEqual(installed_binary.read_bytes(), initial_binary)
        self.assertTrue(fixture.lock.exists())

    def test_missing_master_credentials_generates_random_secret_and_znc_loopback_listener(self):
        fixture = self.fixture("znc")
        helper = fixture.rewrite(common_functions("load_master_credentials"))
        body = helper + '\nunset MASTER_USER MASTER_PASS MASTER_HA1\nload_master_credentials\nprintf "%s\\n" "$MASTER_PASS"\n'
        environment = dict(os.environ, PATH=str(fixture.commands) + ":/usr/bin:/bin",
                           AF_FIXTURE_ROOT=str(fixture.root), AF_FIXTURE_APP=fixture.app)
        result = subprocess.run(["/bin/bash", "-euc", body], env=environment, text=True, capture_output=True)
        self.assert_success(result)
        password = result.stdout.strip()
        self.assertNotEqual(password, "adminadmin")
        self.assertRegex(password, r"^[0-9a-f]{32}$")
        credentials = fixture.root / "var/lib/aetherflow/.master.creds"
        self.assertEqual(credentials.stat().st_mode & 0o777, 0o600)
        self.assertEqual(credentials.parent.stat().st_mode & 0o777, 0o700)
        stored = json.loads(credentials.read_text())
        self.assertEqual(stored, {"username": "admin", "password": password,
                                  "ha1": hashlib.md5(password.encode()).hexdigest()})
        repeated = subprocess.run(["/bin/bash", "-euc", body], env=environment, text=True, capture_output=True)
        self.assert_success(repeated)
        self.assertEqual(repeated.stdout, result.stdout)
        for relative in ("packages/common.sh", "opt/AetherFlow/packages/common.sh"):
            common = fixture.root / relative
            common.write_text(common.read_text() + "\n" + body.rsplit('printf ', 1)[0])
        self.assert_success(fixture.run())
        config = (fixture.root / "var/lib/znc/configs/znc.conf").read_text()
        self.assertNotIn("aetherflowzncsalt123", config)
        self.assertIn("Host = 127.0.0.1", config)
        digest, salt = re.search(r"Pass\s*= sha256#([0-9a-f]{64})#([0-9a-f]{32})#", config).groups()
        self.assertNotEqual(digest, hashlib.sha256(("adminadmin" + salt).encode()).hexdigest())
        self.assertEqual(digest, hashlib.sha256((password + salt).encode()).hexdigest())

    def test_master_credentials_preserve_safe_environment_and_hash_when_missing(self):
        fixture = self.fixture("znc")
        helper = fixture.rewrite(common_functions("load_master_credentials"))
        for supplied_hash in ("", "operator-existing-hash"):
            with self.subTest(hash=supplied_hash):
                environment = dict(os.environ, MASTER_USER="operator", MASTER_PASS="environment-secret",
                                   MASTER_HA1=supplied_hash)
                result = subprocess.run(["/bin/bash", "-euc", helper + '\nload_master_credentials\nprintf "%s:%s:%s" "$MASTER_USER" "$MASTER_PASS" "$MASTER_HA1"'],
                                        env=environment, text=True, capture_output=True)
                self.assert_success(result)
                expected_hash = supplied_hash or hashlib.md5(b"environment-secret").hexdigest()
                self.assertEqual(result.stdout, "operator:environment-secret:" + expected_hash)
                self.assertFalse((fixture.root / "var/lib/aetherflow/.master.creds").exists())

    def test_qbittorrent_without_password_loads_persisted_random_master_secret(self):
        import base64
        fixture = self.fixture("qbittorrent")
        helper = fixture.rewrite(common_functions("load_master_credentials", "generate_qbittorrent_pbkdf2"))
        body = helper + '\nunset MASTER_USER MASTER_PASS MASTER_HA1\ngenerate_qbittorrent_pbkdf2\n'
        environment = dict(os.environ, PATH=str(fixture.commands) + ":/usr/bin:/bin",
                           AF_FIXTURE_ROOT=str(fixture.root), AF_FIXTURE_APP=fixture.app)
        result = subprocess.run(["/bin/bash", "-euc", body], env=environment, text=True, capture_output=True)
        self.assert_success(result)
        credentials = json.loads((fixture.root / "var/lib/aetherflow/.master.creds").read_text())
        salt, digest = re.fullmatch(r"@ByteArray\(([^:]+):([^\)]+)\)\n", result.stdout).groups()
        self.assertEqual(base64.b64decode(digest), hashlib.pbkdf2_hmac("sha512", credentials["password"].encode(),
                                                                  base64.b64decode(salt), 100000, 64))

    def test_bazarr_build_failure_preserves_working_runtime_and_version(self):
        for failure in ("build", "pip-build", "service"):
            with self.subTest(failure=failure):
                fixture = self.fixture("bazarr")
                runtime = fixture.file("opt/bazarr/bazarr.py", "previous working runtime\n")
                version = fixture.file("opt/bazarr/.af-version", "1.0.0\n")
                venv = fixture.file("opt/bazarr/.venv/operator-runtime", "previous virtual environment\n")
                config = fixture.file("var/lib/bazarr/config/config.yaml", "general:\n  port: 6767\n")
                unit = fixture.file("etc/systemd/system/bazarr.service", "previous-unit\n")
                (fixture.root / "active-bazarr.service").touch()
                fixture.lock.write_text("previous-receipt\n")
                receipt = fixture.lock.stat().st_mtime_ns
                result = fixture.run("update", 16767, AF_FIXTURE_FAILURE=failure)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(runtime.read_text(), "previous working runtime\n")
                self.assertEqual(version.read_text(), "1.0.0\n")
                self.assertEqual(venv.read_text(), "previous virtual environment\n")
                self.assertEqual(config.read_text(), "general:\n  port: 6767\n")
                self.assertEqual(unit.read_text(), "previous-unit\n")
                self.assertTrue((fixture.root / "active-bazarr.service").exists())
                self.assertEqual(fixture.lock.stat().st_mtime_ns, receipt)
                self.assertFalse(list((fixture.root / "opt").glob(".bazarr-build.*")))

    def test_listenarr_reinstall_replaces_executing_apphost_without_etxtbsy(self):
        fixture = self.fixture("listenarr")
        executable = fixture.root / "opt/Listenarr/Listenarr.Api"
        executable.parent.mkdir(parents=True)
        shutil.copyfile("/usr/bin/sleep", executable)
        executable.chmod(0o755)
        fixture.file("opt/Listenarr/.af-version", "1.0.0\n")
        fixture.file("etc/systemd/system/listenarr.service", "previous-unit\n")
        process = subprocess.Popen([str(executable), "60"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            result = fixture.run("reinstall")
        finally:
            process.terminate()
            process.wait(timeout=5)
        self.assert_success(result)
        self.assertNotIn("Text file busy", result.stderr)
        self.assertEqual((fixture.root / "opt/Listenarr/.af-version").read_text(), "2.1.0\n")
        commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()]
        self.assertIn(["systemctl", "stop", "--", "listenarr.service"], commands)
        self.assertIn(["systemctl", "restart", "listenarr.service"], commands)

    def test_nextcloud_update_failure_rolls_back_maintenance_mode_and_database_schema(self):
        for mode in ("upgrade-fails", "post-upgrade-configtest-fails"):
            with self.subTest(mode=mode):
                fixture = self.fixture("nextcloud")
                original_config = '<?php $CONFIG = ["maintenance" => false, "operator" => "retained"];\n'
                config = fixture.file("var/www/nextcloud/config/config.php", original_config)
                fixture.file("var/www/nextcloud/old-code.php", "previous-runtime\n")
                fixture.file("var/www/nextcloud/occ", "fixture-occ\n")
                version = fixture.file("var/www/nextcloud/.af-version", "31.0.0\n")
                schema = fixture.file("database-schema", "31.0.0")
                var_schema = fixture.file("var/lib/nextcloud/database-schema", "31.0.0")
                fixture.file("mock-bin/mysqldump", r'''#!/usr/bin/python3 -B
import json, os, pathlib, sys
root = pathlib.Path(os.environ['AF_FIXTURE_ROOT'])
with (root / 'commands.jsonl').open('a') as command_log:
    command_log.write(json.dumps(['mysqldump', *sys.argv[1:]]) + '\n')
sys.stdout.write((root / 'database-schema').read_text())
''').chmod(0o755)
                fixture.file("mock-bin/mysql", r'''#!/usr/bin/python3 -B
import json, os, pathlib, sys
root = pathlib.Path(os.environ['AF_FIXTURE_ROOT'])
with (root / 'commands.jsonl').open('a') as command_log:
    command_log.write(json.dumps(['mysql', *sys.argv[1:]]) + '\n')
(root / 'database-schema').write_text(sys.stdin.read())
''').chmod(0o755)
                vhost = fixture.file("etc/apache2/sites-available/nextcloud.conf", "previous-vhost\n")
                enabled = fixture.root / "etc/apache2/sites-enabled/nextcloud.conf"
                enabled.symlink_to(vhost)
                fixture.file("mock-bin/sudo", r'''#!/usr/bin/python3 -B
import os, pathlib, sys
root = pathlib.Path(os.environ['AF_FIXTURE_ROOT'])
arguments = sys.argv[1:]
config = root / 'var/www/nextcloud/config/config.php'
if 'maintenance:mode' in arguments:
    config.write_text('<?php $CONFIG = ["maintenance" => ' + ('true' if '--on' in arguments else 'false') + '];\n')
elif 'upgrade' in arguments:
    for relative in ('database-schema', 'var/lib/nextcloud/database-schema'):
        (root / relative).write_text('32.0.1')
    if os.environ['AF_PROBE_MODE'] == 'upgrade-fails': sys.exit(75)
elif 'php' not in arguments:
    os.execv(str(root / 'usr/bin/sudo'), [str(root / 'usr/bin/sudo'), *arguments])
''').chmod(0o755)
                if mode == "post-upgrade-configtest-fails":
                    fixture.file("mock-bin/apache2ctl", r'''#!/usr/bin/python3 -B
import os, pathlib, sys
root = pathlib.Path(os.environ['AF_FIXTURE_ROOT'])
sys.exit(74 if (root / 'database-schema').read_text() == '32.0.1' else 0)
''').chmod(0o755)
                result = fixture.run("update", AF_PROBE_MODE=mode)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(config.read_text(), original_config)
                self.assertEqual(schema.read_text(), "31.0.0")
                self.assertEqual(var_schema.read_text(), "31.0.0")
                self.assertTrue((fixture.root / "var/www/nextcloud/old-code.php").is_file())
                self.assertEqual(version.read_text(), "31.0.0\n")
                self.assertEqual(vhost.read_text(), "previous-vhost\n")
                self.assertTrue(enabled.is_symlink())
                self.assertEqual(enabled.resolve(), vhost)
                commands = (fixture.root / "commands.jsonl").read_text()
                self.assertIn('["mysql", "--host=localhost", "nextcloud"]', commands)
                self.assertIn('"--add-drop-database", "--databases", "nextcloud"', commands)

    def test_nextcloud_retained_install_does_not_call_missing_occ(self):
        fixture = self.fixture("nextcloud")
        self.assert_success(fixture.run("install"))
        config = fixture.root / "var/www/nextcloud/config/config.php"
        previous_config = config.read_bytes()
        self.assert_success(fixture.run("uninstall", DELETE_DATA="false"))
        self.assertFalse((fixture.root / "var/www/nextcloud/occ").exists())
        fixture.file("mock-bin/sudo", r'''#!/usr/bin/python3 -B
import os, pathlib, sys
root = pathlib.Path(os.environ['AF_FIXTURE_ROOT'])
arguments = sys.argv[1:]
if 'php' in arguments and not pathlib.Path(arguments[arguments.index('php') + 1]).is_file():
    sys.exit(2)
os.execv(str(root / 'usr/bin/sudo'), [str(root / 'usr/bin/sudo'), *arguments])
''').chmod(0o755)
        self.assert_success(fixture.run("install"))
        self.assertEqual(config.read_bytes(), previous_config)
        self.assertEqual((fixture.root / "var/www/nextcloud/.af-version").read_text(), "32.0.1\n")

    def test_fixture_rebases_roots_without_corrupting_runtime_filenames(self):
        fixture = self.fixture("seedcross")
        self.assertEqual(fixture.rewrite('/var/lib/seedcross/runtime.json'), str(fixture.root / 'var/lib/seedcross/runtime.json'))
        self.assertEqual(fixture.rewrite('"/tmp/install-xrdp.log"'), '"' + str(fixture.root / 'tmp/install-xrdp.log') + '"')

    def test_deluge_keeps_auth_and_concatenated_json_password_records(self):
        fixture = self.fixture("deluge")
        auth = fixture.file("var/lib/deluge/.config/deluge/auth", "operator:operator-password:10\n")
        header = {"file": 1, "format": 1}
        settings = {"pwd_salt": "operator-salt", "pwd_sha1": "operator-hash", "port": 8112,
                    "default_daemon": "192.0.2.8:58846", "https": True, "sessions": {"retained": "operator-session"}}
        config = fixture.file("var/lib/deluge/.config/deluge/web.conf", json.dumps(header) + json.dumps(settings))
        for action, port in (("update", 18112), ("reinstall", 18113)):
            self.assert_success(fixture.run(action, port))
            self.assertEqual(auth.read_text(), "operator:operator-password:10\n")
            decoder = json.JSONDecoder()
            actual_header, offset = decoder.raw_decode(config.read_text())
            actual = json.loads(config.read_text()[offset:])
            self.assertEqual(actual_header, header)
            settings.update(port=port, first_login=False)
            self.assertEqual(actual, settings)

    def test_transmission_keeps_password_authentication_and_whitelists(self):
        for action in ("install", "update", "reinstall"):
            with self.subTest(action=action):
                fixture = self.fixture("transmission")
                settings = {"rpc-username": "operator", "rpc-password": "{operator-hash}", "rpc-authentication-required": False,
                            "rpc-whitelist-enabled": True, "rpc-host-whitelist-enabled": True,
                            "rpc-whitelist": "192.0.2.7", "rpc-port": 9091, "download-dir": "/retained/downloads"}
                config = fixture.file("var/lib/transmission-daemon/info/settings.json", json.dumps(settings))
                self.assert_success(fixture.run(action, 19091))
                settings["rpc-port"] = 19091
                actual = json.loads(config.read_text())
                for key, value in settings.items():
                    self.assertEqual(actual.get(key), value, key)
                for key, value in actual.items():
                    if key in settings:
                        continue
                    if key == "rpc-bind-address":
                        self.assertIn(value, ("0.0.0.0", "127.0.0.1"))
                    elif key in ("rpc-host-whitelist-enabled", "rpc-whitelist-enabled"):
                        self.assertIn(value, (True, False))
                    elif key == "rpc-whitelist":
                        self.assertIn("127.0.0.1", str(value))
                    else:
                        self.fail(f"unexpected transmission setting {key}={value!r}")

    def test_notifiarr_keeps_ui_credentials_and_integration_keys(self):
        fixture = self.fixture("notifiarr")
        config = fixture.file("etc/notifiarr/notifiarr.conf", 'api_key = "operator-api-key"\nui_password = "operator:hash"\nbind_addr = "0.0.0.0:5454"\n[[sonarr]]\napi_key = "sonarr-secret"\n')
        for action, port in (("install", 15453), ("update", 15454), ("reinstall", 15455)):
            self.assert_success(fixture.run(action, port))
            text = config.read_text()
            self.assertIn('ui_password = "operator:hash"', text)
            self.assertIn('api_key = "operator-api-key"', text)
            self.assertIn('api_key = "sonarr-secret"', text)
            self.assertIn(f'bind_addr = "127.0.0.1:{port}"', text)

    def test_nzbget_keeps_control_credentials_in_retained_state(self):
        fixture = self.fixture("nzbget")
        config = fixture.file("var/lib/nzbget/nzbget.conf", "ControlUsername=operator\nControlPassword=operator-secret\nControlPort=6789\nMainDir=/retained/downloads\n")
        for action, port in (("update", 16789), ("reinstall", 16790)):
            self.assert_success(fixture.run(action, port))
            text = config.read_text()
            self.assertIn("ControlUsername=operator", text)
            self.assertIn("ControlPassword=operator-secret", text)
            self.assertIn("MainDir=/retained/downloads", text)
            self.assertRegex(text, rf"ControlPort\s*=\s*{port}")

    def test_pihole_retains_both_v5_and_v6_passwords(self):
        for filename, content in (("setupVars.conf", "WEBPASSWORD=operator-hash\nPIHOLE_INTERFACE=operator0\n"),
                                  ("pihole.toml", '[webserver]\nport = "8089o"\n[webserver.api]\npwhash = "operator-hash"\n')):
            with self.subTest(config=filename):
                fixture = self.fixture("pihole")
                config = fixture.file("etc/pihole/" + filename, content)
                access = fixture.file("etc/lighttpd/external.conf", 'server.port := 8089\n$HTTP["remoteip"] != "192.0.2.7" { url.access-deny = ( "" ) }\n')
                for action in ("update", "reinstall"):
                    self.assert_success(fixture.run(action, 18089))
                    self.assertIn("operator-hash", config.read_text())
                    self.assertIn('server.port := 18089', access.read_text())
                    self.assertIn('"192.0.2.7" { url.access-deny', access.read_text())
                commands = (fixture.root / "commands.jsonl").read_text()
                self.assertNotIn('"setpassword"', commands)
                self.assertNotIn('"-a", "-p"', commands)

    def test_quassel_keeps_initialized_database_certificate_and_defaults(self):
        fixture = self.fixture("quassel")
        database = fixture.file("var/lib/quassel/quassel-storage.sqlite", "operator-users-password-hashes")
        certificate = fixture.file("var/lib/quassel/quasselCert.pem", "operator-private-key")
        config = fixture.file("etc/default/quasselcore", 'PORT="4242"\nLISTEN="127.0.0.1"\nLOGLEVEL="Debug"\nCUSTOM="operator-secret"\n')
        for action in ("update", "reinstall"):
            self.assert_success(fixture.run(action, 14242))
            self.assertEqual(database.read_text(), "operator-users-password-hashes")
            self.assertEqual(certificate.read_text(), "operator-private-key")
            self.assertIn('CUSTOM="operator-secret"', config.read_text())
            self.assertRegex(config.read_text(), r'PORT\s*=\s*"14242"')
        retained_config = config.read_bytes()
        self.assert_success(fixture.run("uninstall", DELETE_DATA="false"))
        self.assertEqual(config.read_bytes(), retained_config)
        self.assertFalse((fixture.root / "var/lib/quassel/.af-version").exists())
        self.assert_success(fixture.run("install", 14242))
        self.assertEqual(config.read_bytes(), retained_config)
        self.assertEqual(database.read_text(), "operator-users-password-hashes")
        self.assertEqual(certificate.read_text(), "operator-private-key")
        self.assert_success(fixture.run("uninstall", DELETE_DATA="true"))
        self.assertFalse(config.exists())
        self.assertFalse(database.exists())
        self.assertFalse(certificate.exists())

    def test_scrutiny_preserves_nested_operator_settings(self):
        fixture = self.fixture("scrutiny")
        config = fixture.file("etc/scrutiny/scrutiny.yaml", 'version: 1\nweb:\n  listen:\n    host: "127.0.0.1"\n    port: 8098\n  database:\n    location: /retained/scrutiny.db\n    password: operator-secret\ncollector:\n  port: 9999\n')
        for action in ("update", "reinstall"):
            self.assert_success(fixture.run(action, 18098))
            self.assertIn("    port: 18098", config.read_text())
            self.assertIn("password: operator-secret", config.read_text())
            self.assertIn("location: /retained/scrutiny.db", config.read_text())
            self.assertIn("  port: 9999", config.read_text())

    def test_znc_changes_only_the_managed_listener_port(self):
        fixture = self.fixture("znc")
        config = fixture.file("var/lib/znc/configs/znc.conf", '<Listener l>\n    Port = 6501\n    SSL = true\n</Listener>\n<User operator>\n    Pass = sha256#operator-hash#operator-salt#\n    Admin = true\n</User>\n')
        for action, port in (("update", 16501), ("reinstall", 16502)):
            self.assert_success(fixture.run(action, port))
            self.assertIn(f"    Port = {port}\n    SSL = true", config.read_text())
            self.assertIn("sha256#operator-hash#operator-salt#", config.read_text())

    def test_thelounge_changes_port_without_touching_user_password(self):
        fixture = self.fixture("thelounge")
        config = fixture.file("var/lib/thelounge/config.js", 'module.exports = {\n    port: 9000,\n    public: false,\n    custom: "operator-setting"\n};\n')
        user = fixture.file("var/lib/thelounge/users/admin.json", '{"password":"operator-hash"}\n')
        for action, port in (("update", 19000), ("reinstall", 19001)):
            self.assert_success(fixture.run(action, port))
            self.assertIn(f"port: {port},", config.read_text())
            self.assertIn("operator-setting", config.read_text())
            self.assertEqual(json.loads(user.read_text())["password"], "operator-hash")

    def test_thelounge_rejects_symlinked_configuration(self):
        fixture = self.fixture("thelounge")
        outside = fixture.file("operator-file", "must not be overwritten\n")
        config = fixture.root / "var/lib/thelounge/config.js"
        config.parent.mkdir(parents=True)
        config.symlink_to(outside)
        result = fixture.run("update", 19000)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(outside.read_text(), "must not be overwritten\n")
        self.assertFalse(fixture.lock.exists())

    def test_sabnzbd_changes_misc_port_without_resetting_password_or_api_key(self):
        fixture = self.fixture("sabnzbd")
        config = fixture.file("var/lib/sabnzbd/sabnzbd.ini", "[misc]\nport = 8085\nusername = operator\npassword = operator-hash\napi_key = operator-api-key\n[nzb]\nport = 443\n")
        for action, port in (("update", 18085), ("reinstall", 18086)):
            self.assert_success(fixture.run(action, port))
            self.assertIn(f"port = {port}", config.read_text())
            self.assertIn("password = operator-hash", config.read_text())
            self.assertIn("api_key = operator-api-key", config.read_text())
            self.assertIn("port = 443", config.read_text())

    def test_wireguard_preserves_server_and_client_keys(self):
        fixture = self.fixture("wireguard")
        server = fixture.file("etc/wireguard/wg0.conf", "[Interface]\nPrivateKey = operator-server-key\nListenPort = 51820\n[Peer]\nPublicKey = operator-client-public-key\n")
        client = fixture.file("etc/wireguard/client.conf", "[Interface]\nPrivateKey = operator-client-key\n[Peer]\nPublicKey = operator-server-public-key\n")
        for action in ("update", "reinstall"):
            self.assert_success(fixture.run(action, 51821))
            self.assertIn("operator-server-key", server.read_text())
            self.assertIn("operator-client-public-key", server.read_text())
            self.assertIn("ListenPort = 51821", server.read_text())
            self.assertIn("operator-client-key", client.read_text())

    def test_rutorrent_preserves_htpasswd_and_apache_access_policy(self):
        fixture = self.fixture("rutorrent")
        credentials = fixture.file("etc/apache2/AetherFlow/rutorrent.htpasswd", "operator:operator-hash\n")
        config = fixture.file("var/www/rutorrent/conf/config.php", '<?php $scgi_port = 15111; $operator = "operator-secret";\n')
        vhost = fixture.file("etc/apache2/sites-available/rutorrent.conf", '<VirtualHost *:8087>\nAuthType Basic\nRequire valid-user\n</VirtualHost>\n')
        for action, port in (("update", 18087), ("reinstall", 18088)):
            self.assert_success(fixture.run(action, port))
            self.assertEqual(credentials.read_text(), "operator:operator-hash\n")
            self.assertIn("operator-secret", config.read_text())
            self.assertIn("15111", config.read_text())
            self.assertIn(f"<VirtualHost *:{port}>", vhost.read_text())
            self.assertIn("Require valid-user", vhost.read_text())

    def test_rutorrent_updates_upstream_plugins_and_retains_custom_plugins_after_uninstall(self):
        fixture = self.fixture("rutorrent")
        fixture.file("repository/plugins/bundled/init.php", "updated upstream plugin\n")
        fixture.file("repository/plugins/bundled/conf.php", "upstream defaults\n")
        upstream = fixture.file("var/www/rutorrent/plugins/bundled/init.php", "old upstream plugin\n")
        override = fixture.file("var/www/rutorrent/plugins/bundled/conf.php", "operator plugin settings\n")
        custom = fixture.file("var/www/rutorrent/plugins/custom/init.php", "operator custom plugin\n")
        credentials = fixture.file("etc/apache2/AetherFlow/rutorrent.htpasswd", "operator:operator-hash\n")
        settings = fixture.file("var/www/rutorrent/share/settings/operator.dat", "operator settings\n")
        for action in ("update", "reinstall"):
            self.assert_success(fixture.run(action))
            self.assertEqual(upstream.read_text(), "updated upstream plugin\n")
            self.assertEqual(override.read_text(), "operator plugin settings\n")
            self.assertEqual(custom.read_text(), "operator custom plugin\n")
        fixture.file("var/www/rutorrent/.runtime-cache", "runtime only\n")
        self.assert_success(fixture.run("uninstall", DELETE_DATA="false"))
        self.assertEqual({entry.name for entry in upstream.parents[2].iterdir()}, {"plugins", "share", "conf"})
        self.assertEqual(custom.read_text(), "operator custom plugin\n")
        self.assertEqual(override.read_text(), "operator plugin settings\n")
        self.assertEqual(settings.read_text(), "operator settings\n")
        self.assertTrue(credentials.exists())
        self.assert_success(fixture.run("install"))
        self.assertEqual(custom.read_text(), "operator custom plugin\n")
        self.assertEqual(override.read_text(), "operator plugin settings\n")
        self.assertEqual(settings.read_text(), "operator settings\n")
        self.assert_success(fixture.run("uninstall", DELETE_DATA="true"))
        self.assertFalse(credentials.exists())
        self.assertFalse((fixture.root / "var/www/rutorrent").exists())

    def test_filebot_failed_build_leaves_both_live_trees_untouched(self):
        fixture = self.fixture("filebot")
        runtime = fixture.file("opt/filebot/filebot.sh", "previous-filebot\n")
        node = fixture.file("opt/filebot-node/server/app.js", "previous-filebot-node\n")
        version = fixture.file("opt/filebot-node/.af-version", "1.0.0\n")
        result = fixture.run("update", AF_FIXTURE_FAILURE="build")
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(runtime.read_text(), "previous-filebot\n")
        self.assertEqual(node.read_text(), "previous-filebot-node\n")
        self.assertEqual(version.read_text(), "1.0.0\n")
        commands = (fixture.root / "commands.jsonl").read_text()
        self.assertIn('["npm", "install", "--include=dev"]', commands)

    def test_failed_activation_restores_all_newly_protected_installers(self):
        for app, paths, version_path in (
            ("filebot", ("opt/filebot/filebot.sh", "opt/filebot-node/server/app.js"), "opt/filebot-node/.af-version"),
            ("listenarr", ("opt/Listenarr/Listenarr.Api",), "opt/Listenarr/.af-version"),
            ("mcvnc", ("opt/mcvnc/operator-runtime", "usr/local/bin/mcvnc"), "var/lib/mcvnc/.af-version"),
            ("invidious", ("opt/invidious/source/invidious",), "opt/invidious/.af-version"),
        ):
            with self.subTest(app=app):
                fixture = self.fixture(app)
                previous = [fixture.file(path, "previous-runtime\n") for path in paths]
                version = fixture.file(version_path, "1.0.0\n")
                unit = fixture.metadata["service_name"] + ".service"
                unit_file = fixture.file("etc/systemd/system/" + unit, "previous-unit\n")
                state = fixture.file(f"var/lib/{app}/operator-state", "operator data\n")
                (fixture.root / ("active-" + unit)).touch()
                result = fixture.run("update", AF_FIXTURE_FAILURE="service", AF_FIXTURE_FAILURE_UNIT=unit)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue((fixture.root / "service-failed").exists(), result.stdout + result.stderr)
                for runtime in previous:
                    self.assertEqual(runtime.read_text(), "previous-runtime\n")
                self.assertEqual(version.read_text(), "1.0.0\n")
                self.assertEqual(unit_file.read_text(), "previous-unit\n")
                self.assertEqual(state.read_text(), "operator data\n")
                self.assertTrue((fixture.root / ("active-" + unit)).exists())

    def test_web_app_updates_keep_apache_operator_access_rules(self):
        for app, relative, content in (
            ("nextcloud", "var/www/nextcloud/config/config.php", '<?php $CONFIG = ["instanceid" => "operator-secret", "trusted_domains" => ["operator.example"]];\n'),
            ("organizr", "var/www/organizr/api/config/config.php", '<?php $operator_token = "operator-secret";\n'),
        ):
            with self.subTest(app=app):
                fixture = self.fixture(app)
                config = fixture.file(relative, content)
                vhost = fixture.file(f"etc/apache2/sites-available/{app}.conf", '<VirtualHost *:8080>\nRequire ip 192.0.2.7\nAuthName "operator-access"\n</VirtualHost>\n')
                for action, port in (("update", 18080), ("reinstall", 18081)):
                    self.assert_success(fixture.run(action, port))
                    self.assertEqual(config.read_text(), content)
                    self.assertIn(f"<VirtualHost *:{port}>", vhost.read_text())
                    self.assertIn("Require ip 192.0.2.7", vhost.read_text())
                    self.assertIn('AuthName "operator-access"', vhost.read_text())

    def test_netdata_apt_first_preserves_operator_settings_and_requires_readiness(self):
        fixture = self.fixture("netdata")
        config = fixture.file("etc/netdata/netdata.conf", "[global]\nhistory = 9876\n[web]\ndefault port = 19999\nallow connections from = 192.0.2.*\n")
        self.assert_success(fixture.run("update", 29999))
        self.assertIn("history = 9876", config.read_text())
        self.assertIn("allow connections from = 192.0.2.*", config.read_text())
        self.assertIn("default port = 29999", config.read_text())
        self.assertFalse((fixture.root / "bootstrap.log").exists())
        fixture.lock.unlink()
        result = fixture.run("update", 29999, AF_FIXTURE_FAILURE="service")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(fixture.lock.exists())

    def test_netdata_requires_a_digest_for_bootstrap_fallback(self):
        fixture = self.fixture("netdata")
        result = fixture.run(AF_FIXTURE_FAILURE="apt")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(fixture.lock.exists())
        result = fixture.run(AF_FIXTURE_FAILURE="apt", NETDATA_KICKSTART_SHA256="a" * 64)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(fixture.lock.exists())
        self.assertFalse((fixture.root / "bootstrap.log").exists())
        digest = hashlib.sha256(NETDATA_BOOTSTRAP_SCRIPT.encode()).hexdigest()
        self.assert_success(fixture.run(AF_FIXTURE_FAILURE="apt", NETDATA_KICKSTART_SHA256=digest))
        self.assertNotIn("SKIP", (fixture.root / "bootstrap.log").read_text())
        self.assertIn(f"[BOOTSTRAP-PROVENANCE] url=https://get.netdata.cloud/kickstart.sh sha256={digest}", (fixture.root / "var/log/aetherflow/install-netdata.log").read_text())

    def test_netdata_does_not_publish_receipts_without_unit_or_readiness(self):
        for failure in ("missing-unit", "service", "readiness"):
            with self.subTest(failure=failure):
                fixture = self.fixture("netdata")
                result = fixture.run(AF_FIXTURE_FAILURE=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(fixture.lock.exists())
                self.assertFalse((fixture.root / "etc/netdata/.af-version").exists())

    def test_keep_existing_secrets_takes_priority_over_rotation_request(self):
        for app, relative, content, setting in (
            ("transmission", "var/lib/transmission-daemon/info/settings.json", '{"rpc-username":"operator","rpc-password":"operator-secret","rpc-port":9091}', "operator-secret"),
            ("deluge", "var/lib/deluge/.config/deluge/web.conf", '{"file":1,"format":1}\n{"port":8112,"pwd_salt":"operator-salt","pwd_sha1":"operator-secret"}', "operator-secret"),
            ("autobrr", "var/lib/autobrr/config.toml", 'host = "127.0.0.1"\nport = 7474\nsessionSecret = "operator-secret"\n', "operator-secret"),
            ("grafana", "etc/grafana/grafana.ini", '[server]\nhttp_port = 3000\n[security]\nadmin_user = operator\nadmin_password = operator-secret\n', "operator-secret"),
            ("notifiarr", "etc/notifiarr/notifiarr.conf", 'bind_addr = "127.0.0.1:5454"\napi_key = "operator-key"\nui_password = "operator:operator-secret"\n', "operator-secret"),
            ("nzbget", "var/lib/nzbget/nzbget.conf", "ControlUsername=operator\nControlPassword=operator-secret\nControlPort=6789\n", "operator-secret"),
            ("pihole", "etc/pihole/setupVars.conf", "WEBPASSWORD=operator-secret\n", "operator-secret"),
            ("rclone", "etc/rclone/rclone.env", 'RCLONE_RC_USER="operator"\nRCLONE_RC_PASS="operator-secret"\n', "operator-secret"),
        ):
            for policy in ("1", None):
                with self.subTest(app=app, policy=policy):
                    fixture = self.fixture(app)
                    config = fixture.file(relative, content)
                    if app == "grafana":
                        fixture.file("var/lib/grafana/grafana.db", "operator-database")
                    if app == "autobrr":
                        fixture.file("var/lib/autobrr/autobrr.db", "operator-account-database")
                    self.assert_success(fixture.run("reinstall", AF_CONFIG_PASS="rotation-request", AF_KEEP_EXISTING_SECRETS=policy))
                    self.assertIn(setting, config.read_text())
                    self.assertNotIn("rotation-request", config.read_text())
                    if app == "autobrr":
                        commands = (fixture.root / "commands.jsonl").read_text()
                        self.assertNotIn("create-user", commands)
                        self.assertNotIn("change-password", commands)

    def test_transmission_initializes_vendor_empty_username_without_resetting_policy(self):
        fixture = self.fixture("transmission")
        config = fixture.file("var/lib/transmission-daemon/info/settings.json", '{"rpc-username":"","rpc-password":"","rpc-authentication-required":true,"rpc-whitelist-enabled":true,"rpc-port":9091}')
        self.assert_success(fixture.run("install", 19091))
        settings = json.loads(config.read_text())
        self.assertEqual(settings["rpc-username"], "admin")
        self.assertEqual(settings["rpc-password"], "bootstrap-password")
        self.assertIs(settings["rpc-authentication-required"], True)
        self.assertIs(settings["rpc-whitelist-enabled"], True)
        self.assertEqual(settings["rpc-port"], 19091)

    def test_scrutiny_adds_missing_listen_port_without_replacing_other_settings(self):
        fixture = self.fixture("scrutiny")
        config = fixture.file("etc/scrutiny/scrutiny.yaml", 'version: 1\nweb:\n  listen:\n    host: "127.0.0.1"\n  database:\n    location: /operator/scrutiny.db\nnotify:\n  urls: ["operator-secret"]\n')
        self.assert_success(fixture.run("reinstall", 18080))
        self.assertIn("    port: 18080\n", config.read_text())
        self.assertIn('    host: "127.0.0.1"\n', config.read_text())
        self.assertIn("location: /operator/scrutiny.db", config.read_text())
        self.assertIn('urls: ["operator-secret"]', config.read_text())

    def test_requestrr_migrates_legacy_runtime_credentials_before_replacing_release(self):
        fixture = self.fixture("requestrr")
        fixture.file("opt/requestrr/config/settings.json", '{"Port":4545,"DiscordBotToken":"operator-secret","Authentication":{"Username":"operator","Password":"operator-hash"}}')
        self.assert_success(fixture.run("update", 14545))
        actual = json.loads((fixture.root / "var/lib/requestrr/config/settings.json").read_text())
        self.assertEqual(actual["Port"], 14545)
        self.assertEqual(actual["DiscordBotToken"], "operator-secret")
        self.assertEqual(actual["Authentication"], {"Username": "operator", "Password": "operator-hash"})

    def test_seedcross_staged_source_failure_keeps_runtime_identity_and_retained_database(self):
        for failure in ("clone", "build", "migration", "service"):
            with self.subTest(failure=failure):
                fixture = self.fixture("seedcross")
                runtime = fixture.file("var/lib/seedcross/runtime.json", '{"secret_key":"operator-secret","allowed_hosts":["operator.example"],"csrf_trusted_origins":["https://operator.example"]}')
                database = fixture.file("var/lib/seedcross/db/db.sqlite3", "operator-database")
                fixture.file("opt/seedcross/csui/settings.py", "SECRET_KEY = 'operator-secret'\n")
                previous = fixture.file("opt/seedcross/start-seedcross.sh", "previous-runtime\n")
                fixture.lock.write_text("previous-receipt\n")
                receipt = fixture.lock.stat().st_mtime_ns
                result = fixture.run("update", AF_FIXTURE_FAILURE=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(database.read_text(), "operator-database")
                self.assertIn("operator-secret", runtime.read_text())
                self.assertEqual(previous.read_text(), "previous-runtime\n")
                self.assertEqual(fixture.lock.stat().st_mtime_ns, receipt)
                self.assertNotIn('"pull"', (fixture.root / "commands.jsonl").read_text())

    def test_seedcross_success_and_uninstall_keep_operator_identity_and_data(self):
        fixture = self.fixture("seedcross")
        runtime = fixture.file("var/lib/seedcross/runtime.json", '{"secret_key":"operator-secret","allowed_hosts":["operator.example"]}')
        database = fixture.file("var/lib/seedcross/db/db.sqlite3", "operator-database")
        for action, port in (("update", 18017), ("reinstall", 18018), ("uninstall", 18018)):
            self.assert_success(fixture.run(action, port))
            self.assertEqual(database.read_text(), "operator-database")
            self.assertEqual(json.loads(runtime.read_text())["secret_key"], "operator-secret")

    def test_seedcross_account_retention_without_keep_policy_on_update_and_reinstall(self):
        for action in ("update", "reinstall"):
            with self.subTest(action=action):
                fixture = self.fixture("seedcross")
                account = fixture.file("seedcross-account.json", json.dumps({
                    "username": "admin", "password": "operator-password-hash",
                    "email": "operator@example.invalid", "is_staff": False, "is_superuser": False,
                }))
                before = account.read_bytes()
                self.assert_success(fixture.run(action, AF_KEEP_EXISTING_SECRETS=None))
                self.assertEqual(account.read_bytes(), before)

    def test_seedcross_account_rotation_requires_password_and_explicit_opt_in(self):
        for policy, password, rotate in ((None, "rotation-request", False), ("0", "", False),
                                         ("1", "rotation-request", False), ("0", "rotation-request", True)):
            with self.subTest(policy=policy, password=password):
                fixture = self.fixture("seedcross")
                account = fixture.file("seedcross-account.json", json.dumps({
                    "username": "admin", "password": "operator-password-hash",
                    "email": "operator@example.invalid", "is_staff": False, "is_superuser": False,
                }))
                before = account.read_bytes()
                self.assert_success(fixture.run("update", AF_KEEP_EXISTING_SECRETS=policy, AF_CONFIG_PASS=password))
                if rotate:
                    self.assertEqual(json.loads(account.read_text()), {
                        "username": "admin", "password": password, "email": "admin@localhost",
                        "is_staff": True, "is_superuser": True,
                    })
                else:
                    self.assertEqual(account.read_bytes(), before)

    def test_failed_first_activation_restores_all_five_binary_and_tree_updates(self):
        for app, relative, version_file in (
            ("kavita", "opt/Kavita/Kavita", "opt/Kavita/.af-version"),
            ("autobrr", "usr/local/bin/autobrr", "var/lib/autobrr/.af-version"),
            ("gitea", "usr/local/bin/gitea", "var/lib/gitea/.af-version"),
            ("autoscan", "usr/local/bin/autoscan", "opt/autoscan/.af-version"),
            ("filebrowser", "usr/local/bin/filebrowser", "opt/filebrowser/.af-version"),
        ):
            with self.subTest(app=app):
                fixture = self.fixture(app)
                previous = fixture.file(relative, "#!/bin/sh\necho previous-runtime\n")
                previous.chmod(0o755)
                version = fixture.file(version_file, "1.0.0\n")
                fixture.lock.write_text("previous-marker\n")
                unit = fixture.metadata["service_name"] + ".service"
                (fixture.root / ("active-" + unit)).touch()
                companion = None
                if app == "autobrr":
                    companion = fixture.file("usr/local/bin/autobrrctl", "previous-control-runtime\n")
                if app == "kavita":
                    config = fixture.file("opt/Kavita/config/settings.json", '{"operator":"retained"}\n')
                result = fixture.run("update", AF_FIXTURE_FAILURE="service", AF_FIXTURE_FAILURE_UNIT=unit)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue((fixture.root / "service-failed").exists(), result.stdout + result.stderr)
                self.assertTrue(previous.exists())
                self.assertIn("previous-runtime", previous.read_text(errors="replace"))
                self.assertEqual(version.read_text(), "1.0.0\n")
                self.assertEqual(fixture.lock.read_text(), "previous-marker\n")
                self.assertTrue((fixture.root / ("active-" + unit)).exists())
                if companion:
                    self.assertEqual(companion.read_text(), "previous-control-runtime\n")
                if app == "kavita":
                    self.assertEqual(config.read_text(), '{"operator":"retained"}\n')

    def test_gitea_symlink_config_fails_closed_without_changing_outside_file(self):
        fixture = self.fixture("gitea")
        victim = fixture.file("outside-managed-config/victim.conf", "root-owned data\n[server]\nHTTP_PORT = 1234\n")
        config = fixture.root / "etc/gitea/app.ini"
        config.parent.mkdir(parents=True)
        config.symlink_to(victim)
        before = victim.read_bytes(), victim.stat().st_mode, victim.stat().st_mtime_ns
        result = fixture.run("update")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((victim.read_bytes(), victim.stat().st_mode, victim.stat().st_mtime_ns), before)
        self.assertTrue(config.is_symlink())

    def test_gitea_rejects_symlinked_config_directory_hardlinks_and_nonregular_files(self):
        for kind in ("directory-symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind):
                fixture = self.fixture("gitea")
                victim = fixture.file("outside-managed-config/app.ini", "operator-secret\n")
                directory = fixture.root / "etc/gitea"
                if kind == "directory-symlink":
                    directory.symlink_to(victim.parent, target_is_directory=True)
                else:
                    directory.mkdir()
                    if kind == "hardlink":
                        os.link(victim, directory / "app.ini")
                    else:
                        os.mkfifo(directory / "app.ini")
                self.assertNotEqual(fixture.run("update").returncode, 0)
                self.assertEqual(victim.read_text(), "operator-secret\n")

    def test_gitea_config_port_update_preserves_operator_settings_and_restricts_writes(self):
        fixture = self.fixture("gitea")
        config = fixture.file("etc/gitea/app.ini", '[server]\nHTTP_PORT = 3002\nROOT_URL = https://operator.example/\n[security]\nSECRET_KEY = operator-secret\n')
        config.parent.chmod(0o770)
        config.chmod(0o660)
        self.assert_success(fixture.run("update", 13002))
        self.assertIn("HTTP_PORT = 13002\n", config.read_text())
        self.assertIn("ROOT_URL = https://operator.example/\n", config.read_text())
        self.assertIn("SECRET_KEY = operator-secret\n", config.read_text())
        self.assertEqual(config.parent.stat().st_mode & 0o777, 0o750)
        self.assertEqual(config.stat().st_mode & 0o777, 0o640)

    def test_vaultwarden_port_update_preserves_secrets_and_rejects_config_links(self):
        fixture = self.fixture("vaultwarden")
        config = fixture.file("etc/vaultwarden/vaultwarden.env", "ROCKET_PORT=8343\nADMIN_TOKEN=operator-secret\nOTHER_PORT=1234\n")
        self.assert_success(fixture.run("update", 18343))
        text = config.read_text()
        self.assertIn("ROCKET_PORT=18343\n", text)
        self.assertIn("ADMIN_TOKEN=operator-secret\n", text)
        self.assertIn("OTHER_PORT=1234\n", text)
        address = re.search(r"(?m)^ROCKET_ADDRESS=(.*)$", text)
        if address:
            self.assertIn(address.group(1), ("0.0.0.0", "127.0.0.1"))
        signups = re.search(r"(?m)^SIGNUPS_ALLOWED=(.*)$", text)
        if signups:
            self.assertIn(signups.group(1), ("true", "false"))
        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                fixture = self.fixture("vaultwarden")
                victim = fixture.file("outside-managed-config/victim.conf", "ROCKET_PORT=8343\nADMIN_TOKEN=operator-secret\n")
                config = fixture.root / "etc/vaultwarden/vaultwarden.env"
                config.parent.mkdir()
                if kind == "symlink":
                    config.symlink_to(victim)
                else:
                    os.link(victim, config)
                self.assertNotEqual(fixture.run("update", 18343).returncode, 0)
                self.assertEqual(victim.read_text(), "ROCKET_PORT=8343\nADMIN_TOKEN=operator-secret\n")

    def test_vaultwarden_bad_layer_digest_cannot_install_runtime_or_receipt(self):
        fixture = self.fixture("vaultwarden")
        fixture.file("mock-bin/jq", HOST_COMMAND.replace(
            "elif '.layers' in query or '.manifests' in query: print('sha256:' + hashlib.sha256((root / 'release.tar.gz').read_bytes()).hexdigest())",
            "elif '.layers' in query or '.manifests' in query: print('sha256:' + '0' * 64)",
        )).chmod(0o755)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Vaultwarden OCI layer SHA-256 digest mismatch", result.stderr)
        self.assertFalse((fixture.root / "opt/vaultwarden/vaultwarden").exists())
        self.assertFalse(fixture.lock.exists())
        self.assertFalse(list((fixture.root / "tmp").glob("vw-oci-*")))

    def test_vaultwarden_malformed_layer_digest_is_rejected_before_download(self):
        fixture = self.fixture("vaultwarden")
        fixture.file("mock-bin/jq", HOST_COMMAND.replace(
            "elif '.layers' in query or '.manifests' in query: print('sha256:' + hashlib.sha256((root / 'release.tar.gz').read_bytes()).hexdigest())",
            "elif '.layers' in query or '.manifests' in query: print('sha256:fixture-layer')",
        )).chmod(0o755)
        result = fixture.run()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Invalid Vaultwarden OCI layer digest", result.stderr)
        self.assertNotIn("/blobs/", (fixture.root / "commands.jsonl").read_text())
        self.assertFalse((fixture.root / "opt/vaultwarden/vaultwarden").exists())
        self.assertFalse(fixture.lock.exists())

    def test_explicit_purge_erases_archive_copies_of_all_seven_app_secrets(self):
        for app, state in (
            ("vaultwarden", "var/lib/vaultwarden"), ("scrutiny", "etc/scrutiny"),
            ("rclone", "etc/rclone"), ("unpackerr", "etc/unpackerr"),
            ("recyclarr", "var/lib/recyclarr"), ("notifiarr", "etc/notifiarr"),
            ("requestrr", "var/lib/requestrr"),
        ):
            with self.subTest(app=app):
                fixture = self.fixture(app)
                fixture.file(state + "/secret.txt", "operator-secret\n")
                self.assert_success(fixture.run("install"))
                self.assertGreater(len(list(fixture.root.rglob("secret.txt"))), 1, "No archived secret was exercised")
                self.assert_success(fixture.run("uninstall", DELETE_DATA="true"))
                self.assertEqual(list(fixture.root.rglob("secret.txt")), [])

    def test_explicit_purge_removes_legacy_ownerless_backups_but_keeps_default_retention(self):
        for app, destination in (
            ("kavita", "opt/Kavita"), ("uptimekuma", "opt/uptime-kuma"),
            ("nextcloud", "var/www/nextcloud"), ("organizr", "var/www/organizr"),
            ("rutorrent", "var/www/rutorrent"),
            ("flood", "opt/flood"), ("n8n", "opt/n8n"), ("thelounge", "opt/thelounge"),
        ):
            with self.subTest(app=app):
                fixture = self.fixture(app)
                secret = fixture.file(destination + ".af-backup.legacy-secret/app/secret.txt", "operator-secret\n")
                self.assert_success(fixture.run("uninstall"))
                self.assertEqual(secret.read_text(), "operator-secret\n")
                self.assert_success(fixture.run("uninstall", DELETE_DATA="true"))
                self.assertFalse(secret.exists())

    def test_corrupt_archives_leave_previous_runtime_and_receipt_unchanged(self):
        for app, relative in (("radarr", "opt/Radarr/Radarr"), ("navidrome", "opt/navidrome/navidrome"),
                              ("qui", "usr/local/bin/qui"), ("ombi", "opt/Ombi/Ombi"),
                              ("notifiarr", "usr/local/bin/notifiarr")):
            with self.subTest(app=app):
                fixture = self.fixture(app)
                previous = fixture.file(relative, "#!/bin/sh\necho previous-runtime\n")
                previous.chmod(0o755)
                fixture.lock.write_text("previous-receipt\n")
                receipt = fixture.lock.stat().st_mtime_ns
                result = fixture.run("update", AF_FIXTURE_FAILURE="archive")
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("previous-runtime", previous.read_text())
                self.assertEqual(fixture.lock.read_text(), "previous-receipt\n")
                self.assertEqual(fixture.lock.stat().st_mtime_ns, receipt)

    def test_failed_restart_restores_runtime_config_version_and_receipt(self):
        for app, relative, version_file in (
            ("radarr", "opt/Radarr/Radarr", "opt/Radarr/.af-version"),
            ("notifiarr", "usr/local/bin/notifiarr", "etc/notifiarr/.af-version"),
            ("scrutiny", "opt/scrutiny/bin/scrutiny-web-linux-amd64", "opt/scrutiny/.af-version"),
            ("n8n", "opt/n8n/prior-runtime", "var/lib/n8n/.af-version"),
            ("unmanic", "opt/unmanic/prior-runtime", "opt/unmanic/.af-version"),
            ("navidrome", "opt/navidrome/navidrome", "opt/navidrome/.af-version"),
            ("nzbget", "opt/nzbget/nzbget", "opt/nzbget/.af-version"),
            ("threadfin", "usr/local/bin/threadfin", "var/lib/threadfin/.af-version"),
            ("requestrr", "opt/requestrr/Requestrr.WebApi", "opt/requestrr/.af-version"),
            ("recyclarr", "usr/local/bin/recyclarr", "opt/recyclarr/.af-version"),
            ("unpackerr", "usr/local/bin/unpackerr", "opt/unpackerr/.af-version"),
            ("rclone", "usr/bin/rclone", "var/lib/rclone/.af-version"),
            ("vaultwarden", "opt/vaultwarden/vaultwarden", "opt/vaultwarden/.af-version"),
            ("uptimekuma", "opt/uptime-kuma/server/server.js", "opt/uptime-kuma/.af-version"),
            ("thelounge", "opt/thelounge/prior-runtime", "var/lib/thelounge/.af-version"),
            ("pyload", "opt/pyload/prior-runtime", "opt/pyload/.af-version"),
            ("prometheus", "usr/local/bin/prometheus", "etc/prometheus/.af-version"),
            ("piped", "opt/piped/piped.jar", "opt/piped/.af-version"),
        ):
            with self.subTest(app=app):
                fixture = self.fixture(app)
                previous = fixture.file(relative, "#!/bin/sh\necho previous-runtime\n")
                previous.chmod(0o755)
                version = fixture.file(version_file, "1.0.0\n")
                if app == "rclone":
                    companion = fixture.file("etc/systemd/system/rclone-vfs.service", "operator-vfs-unit\n")
                    (fixture.root / "active-rclone-vfs.service").touch()
                fixture.lock.write_text("previous-receipt\n")
                receipt = fixture.lock.stat().st_mtime_ns
                unit = fixture.metadata["service_name"] + (".timer" if app == "recyclarr" else ".service")
                result = fixture.run("update", AF_FIXTURE_FAILURE="service", AF_FIXTURE_FAILURE_UNIT=unit)
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue((fixture.root / "service-failed").exists(), result.stdout + result.stderr)
                self.assertIn("previous-runtime", previous.read_text())
                self.assertEqual(version.read_text(), "1.0.0\n")
                self.assertEqual(fixture.lock.stat().st_mtime_ns, receipt)
                if app == "rclone":
                    self.assertEqual(companion.read_text(), "operator-vfs-unit\n")
                    self.assertTrue((fixture.root / "active-rclone-vfs.service").exists())

    def test_version_writes_are_symlink_safe_in_every_owned_installer(self):
        for path in sorted((ROOT / "packages/package/install").glob("installpackage-[n-z]*")):
            if path.name == "installpackage-template":
                continue
            with self.subTest(installer=path.name):
                self.assertNotRegex(path.read_text(), r">\s*[^\n]*\.af-version")
        fixture = self.fixture("znc")
        target = fixture.file("operator-secret", "do not truncate\n")
        version = fixture.root / "var/lib/znc/.af-version"
        version.parent.mkdir(parents=True)
        version.symlink_to(target)
        self.assert_success(fixture.run())
        self.assertEqual(target.read_text(), "do not truncate\n")
        self.assertFalse(version.is_symlink())

    def test_archive_staged_downgrade_without_allow_keeps_receipt_and_runtime(self):
        cases = (
            ("radarr", "opt/Radarr/Radarr", "opt/Radarr/.af-version"),
            ("navidrome", "opt/navidrome/navidrome", "opt/navidrome/.af-version"),
        )
        for app, runtime, receipt in cases:
            with self.subTest(app=app):
                fixture = self.fixture(app)
                binary = fixture.file(runtime, "#!/bin/sh\nprintf 'previous-runtime\\n'\n")
                binary.chmod(0o755)
                marker = fixture.file(str(Path(runtime).parent / "operator-runtime.marker"), "previous-tree\n")
                version = fixture.file(receipt, "99.0.0\n")
                unit = fixture.metadata["service_name"] + ".service"
                (fixture.root / ("active-" + unit)).touch()
                result = fixture.run("update", AF_FIXTURE_VERSION="2.1.0", AF_ALLOW_DOWNGRADE="")
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("downgrade", (result.stdout + result.stderr).lower())
                self.assertEqual(version.read_text().strip(), "99.0.0")
                self.assertIn("previous-runtime", binary.read_text())
                self.assertEqual(marker.read_text(), "previous-tree\n")
                self.assertFalse(fixture.lock.exists())

    def test_secret_configs_and_credential_logs_are_mode_0600_under_umask_022(self):
        cases = (
            ("tautulli", ("var/lib/tautulli/config.ini",), False),
            ("sabnzbd", ("var/lib/sabnzbd/sabnzbd.ini",), False),
            ("nzbget", ("var/lib/nzbget/nzbget.conf",), False),
            ("filebrowser", ("opt/AetherFlow/logs/filebrowser_credentials.txt",), True),
            ("nextcloud", ("opt/AetherFlow/logs/nextcloud_credentials.txt",), True),
            ("vaultwarden", ("etc/vaultwarden/vaultwarden.env", "opt/AetherFlow/logs/vaultwarden_admin_token.txt"), True),
        )
        previous_umask = os.umask(0o022)
        try:
            for app, relatives, check_log_directory in cases:
                with self.subTest(app=app):
                    fixture = self.fixture(app)
                    result = fixture.run("install")
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    paths = [fixture.root / relative for relative in relatives]
                    if check_log_directory:
                        logs = [path for path in (fixture.root / "opt/AetherFlow/logs").iterdir() if path.is_file()]
                        self.assertTrue(logs, "credential log directory is empty")
                        paths.extend(logs)
                    self.assertTrue(paths)
                    for path in paths:
                        self.assertTrue(path.is_file(), path)
                        self.assertEqual(path.stat().st_mode & 0o077, 0, f"{path} mode {oct(path.stat().st_mode & 0o777)}")
        finally:
            os.umask(previous_umask)

    def test_explicit_af_config_pass_rotation_writes_requested_password(self):
        password = "rotation-request"
        for app in ("autobrr", "deluge", "grafana"):
            with self.subTest(app=app):
                fixture = self.fixture(app)
                if app == "autobrr":
                    fixture.file("var/lib/autobrr/config.toml", 'host = "127.0.0.1"\nport = 7474\nsessionSecret = "operator-secret"\n')
                elif app == "deluge":
                    salt = "ab" * 16
                    previous = hashlib.sha1((salt + "operator-secret").encode()).hexdigest()
                    fixture.file(
                        "var/lib/deluge/.config/deluge/web.conf",
                        json.dumps({"file": 1, "format": 1}) + json.dumps({"port": 8112, "pwd_salt": salt, "pwd_sha1": previous, "first_login": False}),
                    )
                    fixture.file("var/lib/deluge/.config/deluge/auth", "operator:operator-secret:10\n")
                else:
                    fixture.file("etc/grafana/grafana.ini", "[server]\nhttp_port = 3000\n[security]\nadmin_user = operator\nadmin_password = operator-secret\n")
                    fixture.file("var/lib/grafana/grafana.db", "operator-database")
                self.assert_success(fixture.run("reinstall", AF_CONFIG_PASS=password, AF_KEEP_EXISTING_SECRETS="0"))
                if app == "autobrr":
                    stored = "\n".join(
                        path.read_text(errors="replace")
                        for path in (fixture.root / "var/lib/autobrr").rglob("*")
                        if path.is_file()
                    )
                    self.assertIn(password, stored)
                elif app == "deluge":
                    text = (fixture.root / "var/lib/deluge/.config/deluge/web.conf").read_text()
                    decoder = json.JSONDecoder()
                    _header, offset = decoder.raw_decode(text)
                    body = json.loads(text[offset:])
                    self.assertEqual(hashlib.sha1((body["pwd_salt"] + password).encode()).hexdigest(), body["pwd_sha1"])
                    auth = (fixture.root / "var/lib/deluge/.config/deluge/auth").read_text()
                    self.assertIn("operator:operator-secret:10", auth)
                    self.assertIn(f"admin:{password}:10", auth)
                else:
                    match = re.search(r"(?m)^;?\s*admin_password\s*=\s*(\S+)\s*$", (fixture.root / "etc/grafana/grafana.ini").read_text())
                    self.assertIsNotNone(match)
                    self.assertEqual(match.group(1).strip('"\''), password)


class R15SharedInstallerRegressions(unittest.TestCase):
    def shell(self, fixture, program, **environment):
        variables = {
            **os.environ, "PATH": str(fixture.commands) + ":/usr/bin:/bin",
            "AF_FIXTURE_ROOT": str(fixture.root), "AF_FIXTURE_APP": fixture.app,
            "AF_FIXTURE_VERSION": "2.1.0", "AF_FIXTURE_FAILURE": "",
            "LOGFILE": str(fixture.root / "helper.log"), "TMPDIR": str(fixture.root / "tmp"), **environment,
        }
        return subprocess.run(["bash", "-euc", 'source "$1"; ' + program, "fixture",
                               str(fixture.root / "packages/common.sh")], env=variables,
                              text=True, capture_output=True, timeout=30)

    def test_remote_companion_manifests_match_the_downloaded_asset(self):
        for manifest in ("checksums.txt", "sha256sums.txt", "SHA256SUMS", "SHA256SUMS.txt", "vendor_v2_checksums.txt"):
            with self.subTest(manifest=manifest), InstallerFixture("navidrome") as fixture:
                source = "https://github.com/vendor/app/releases/download/v2.1.0/release.tar.gz"
                metadata = {"assets": [{"name": manifest, "browser_download_url": source.rsplit("/", 1)[0] + "/" + manifest}]}
                result = self.shell(fixture, 'download_file "$AF_TEST_SOURCE" "$AF_FIXTURE_ROOT/tmp/artifact"',
                                    AF_TEST_SOURCE=source, AF_TEST_CHECKSUM_MANIFEST=manifest,
                                    AF_TEST_CHECKSUM_ASSET="release.tar.gz", RELEASE_JSON=json.dumps(metadata))
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                actual = fixture.root / "tmp/artifact"
                self.assertEqual(actual.read_bytes(), (fixture.root / "release.tar.gz").read_bytes())
                actual.unlink()
                failed = self.shell(fixture, 'download_file "$AF_TEST_SOURCE" "$AF_FIXTURE_ROOT/tmp/artifact"',
                                    AF_TEST_SOURCE=source, AF_TEST_CHECKSUM_MANIFEST=manifest,
                                    AF_TEST_CHECKSUM_ASSET="release.tar.gz", RELEASE_JSON=json.dumps(metadata),
                                    AF_TEST_CHECKSUM_LISTING="0" * 64 + "  release.tar.gz\n")
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)

    def test_companion_manifest_cannot_authorize_an_unrelated_filename_or_bare_digest(self):
        for listing in ("{digest}  other.tar.gz\n", "{digest}\n"):
            with self.subTest(listing=listing), InstallerFixture("navidrome") as fixture:
                digest = hashlib.sha256((fixture.root / "release.tar.gz").read_bytes()).hexdigest()
                result = self.shell(fixture, 'download_file https://fixture.invalid/release.tar.gz "$AF_FIXTURE_ROOT/tmp/artifact"',
                                    AF_TEST_CHECKSUM_MANIFEST="checksums.txt", AF_TEST_CHECKSUM_ASSET="release.tar.gz",
                                    AF_TEST_CHECKSUM_LISTING=listing.format(digest=digest))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_rclone_uses_a_versioned_asset_with_its_companion_manifest(self):
        with InstallerFixture("rclone") as fixture:
            result = fixture.run(AF_TEST_CHECKSUM_MANIFEST="SHA256SUMS", AF_TEST_CHECKSUM_ASSET="rclone-v2.1.0-linux-amd64.zip")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            commands = (fixture.root / "commands.jsonl").read_text()
            self.assertIn("https://downloads.rclone.org/v2.1.0/rclone-v2.1.0-linux-amd64.zip", commands)
            self.assertIn("https://downloads.rclone.org/v2.1.0/SHA256SUMS", commands)
            self.assertNotIn("rclone-current-linux", commands)

    def test_download_verification_failure_reaches_the_fallback(self):
        with InstallerFixture("navidrome") as fixture:
            digest = hashlib.sha256((fixture.root / "release.tar.gz").read_bytes()).hexdigest()
            result = self.shell(fixture, 'download_file https://fixture.invalid/primary "$AF_FIXTURE_ROOT/tmp/artifact" threadfin "$AF_BAD_DIGEST" || download_file https://fixture.invalid/fallback "$AF_FIXTURE_ROOT/tmp/artifact" threadfin "$AF_GOOD_DIGEST"',
                                AF_BAD_DIGEST="0" * 64, AF_GOOD_DIGEST=digest)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            commands = (fixture.root / "commands.jsonl").read_text()
            self.assertIn("https://fixture.invalid/fallback", commands)

    def test_vendor_apt_signing_keys_require_a_pin_even_with_a_matching_sidecar(self):
        urls = (
            "https://repo.jellyfin.org/jellyfin_team.gpg.key",
            "https://downloads.plex.tv/plex-keys/PlexSign.key",
            "https://apt.grafana.com/gpg.key",
            "https://advplyr.github.io/audiobookshelf-ppa/KEY.gpg",
            "https://syncthing.net/release-key.gpg",
            "https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg",
        )
        for source in urls:
            with self.subTest(source=source), InstallerFixture("navidrome") as fixture:
                digest = hashlib.sha256((fixture.root / "release.tar.gz").read_bytes()).hexdigest()
                program = 'download_file "$AF_TEST_SOURCE" "$AF_FIXTURE_ROOT/tmp/signing-key"'
                rejected = self.shell(fixture, program, AF_TEST_SOURCE=source, AF_TRUSTED_KEY_SHA256="")
                self.assertNotEqual(rejected.returncode, 0, rejected.stdout + rejected.stderr)
                accepted = self.shell(fixture, program, AF_TEST_SOURCE=source, AF_TRUSTED_KEY_SHA256=digest)
                self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)

    def test_in_place_updates_reject_numeric_and_prefixed_downgrades(self):
        for app in ("cloudplow", "calibreweb", "overseerr", "homeassistant", "maintainerr"):
            for previous in ("99.0.0", "v99.0.0", "V99.0.0"):
                with self.subTest(app=app, previous=previous), InstallerFixture(app) as fixture:
                    relative = VERSION_RECEIPT_EXPECTATIONS[app][0]
                    receipt = fixture.file(relative, previous + "\n")
                    sentinel = fixture.file(str(Path(relative).parent / "operator-retained"), "operator-state\n")
                    failed = fixture.run("update", AF_ALLOW_DOWNGRADE="0")
                    self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                    self.assertIn("Refusing to downgrade", failed.stderr + failed.stdout)
                    self.assertEqual(receipt.read_text(), previous + "\n")
                    self.assertEqual(sentinel.read_text(), "operator-state\n")
                    self.assertFalse(fixture.lock.exists())

    def test_receipt_guard_normalizes_both_versions_and_snapshots_before_queueing(self):
        for previous, candidate in (("99.0.0", "v2.1.0"), ("v99.0.0", "2.1.0"), ("V99.0.0", "V2.1.0"),
                                    ("release-99.0.0", "release-2.1.0"), ("2.1.0", "abcdef123"),
                                    ("2.1.0", "123abcd"), ("2.1.0", "nightly"), ("2.1.0", "release-1.0"),
                                    ("20261108", "abcdef123"),
                                    ("abcdef123", "not-a-git-sha")):
            with self.subTest(previous=previous, candidate=candidate), InstallerFixture("threadfin") as fixture:
                receipt = fixture.file("opt/test/.af-version", previous + "\n")
                transaction = fixture.root / "tmp/transaction"
                transaction.mkdir()
                result = self.shell(fixture, 'queue_app_version "$AF_TEST_RECEIPT" "$AF_TEST_CANDIDATE"',
                                    AF_TX_DIR=str(transaction), AF_TEST_RECEIPT=str(receipt),
                                    AF_TEST_CANDIDATE=candidate, AF_ALLOW_DOWNGRADE="0")
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                snapshot = transaction / "pre_versions" / str(receipt).lstrip("/")
                self.assertEqual(snapshot.read_text(), previous + "\n")
                self.assertEqual(receipt.read_text(), previous + "\n")
                allowed = self.shell(fixture, 'write_app_version "$AF_TEST_RECEIPT" "$AF_TEST_CANDIDATE"',
                                     AF_TX_DIR=str(transaction), AF_TEST_RECEIPT=str(receipt),
                                     AF_TEST_CANDIDATE=candidate, AF_ALLOW_DOWNGRADE="1")
                self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
                self.assertEqual(receipt.read_text(), candidate + "\n")

    def test_calibreweb_runtime_directory_and_receipt_are_readable(self):
        with InstallerFixture("calibreweb") as fixture:
            result = fixture.run()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual((fixture.root / "opt/calibre-web").stat().st_mode & 0o777, 0o755)
            self.assertEqual((fixture.root / "opt/calibre-web/.af-version").stat().st_mode & 0o777, 0o644)

    def test_cloudplow_copies_configuration_after_service_shutdown_flushes(self):
        with InstallerFixture("cloudplow") as fixture:
            installed = fixture.run()
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            config = fixture.file("opt/cloudplow/config.json", '{"shutdown": 0}\n')
            CatalogLifecycleMatrix.patch_host_command(self, fixture, "systemctl", "if command == 'systemctl':\n", """if command == 'systemctl':
    if arguments[0] == 'stop' and 'cloudplow' in arguments and not (root / 'shutdown-flushed').exists():
        (root / 'opt/cloudplow/config.json').write_text('{"shutdown": 1}\\n')
        (root / 'shutdown-flushed').touch()
""")
            updated = fixture.run("update")
            self.assertEqual(updated.returncode, 0, updated.stdout + updated.stderr)
            self.assertEqual(json.loads(config.read_text()), {"shutdown": 1})

    def test_filebot_rollback_snapshot_includes_final_service_shutdown_writes(self):
        with InstallerFixture("filebot") as fixture:
            installed = fixture.run()
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            state = fixture.file("var/lib/filebot/shutdown-state", "before-stop\n")
            CatalogLifecycleMatrix.patch_host_command(self, fixture, "systemctl", "if command == 'systemctl':\n", """if command == 'systemctl':
    if 'filebot.service' in arguments:
        state = root / 'var/lib/filebot/shutdown-state'
        if arguments[0] == 'stop' and not (root / 'shutdown-flushed').exists():
            state.write_text('after-stop\\n')
            (root / 'shutdown-flushed').touch()
        elif arguments[0] in ('start', 'restart') and not (root / 'activation-wrote-state').exists():
            state.write_text('failed-startup\\n')
            (root / 'activation-wrote-state').touch()
""")
            failed = fixture.run("update", AF_FIXTURE_FAILURE="readiness")
            self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
            self.assertTrue((fixture.root / "shutdown-flushed").exists())
            self.assertTrue((fixture.root / "activation-wrote-state").exists())
            self.assertEqual(state.read_text(), "after-stop\n")

    def test_servarr_bootstrap_failure_cannot_commit_an_install(self):
        for app in ("sonarr", "radarr", "lidarr", "readarr", "prowlarr"):
            with self.subTest(app=app), InstallerFixture(app) as fixture:
                installed = fixture.run()
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                receipt = fixture.root / VERSION_RECEIPT_EXPECTATIONS[app][0]
                before = receipt.read_bytes()
                failed = fixture.run("update", AF_FIXTURE_FAILURE="bootstrap-python", AF_FIXTURE_VERSION="2.2.0")
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                self.assertEqual(receipt.read_bytes(), before)

    def test_secret_files_are_created_private_under_a_legacy_umask(self):
        paths = {
            "filebot": "var/lib/filebot/filebot-node.env", "novnc": "var/lib/novnc/.vnc/passwd",
            "qbittorrent": "var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
            "autobrr": "var/lib/autobrr/config.toml", "adguardhome": "opt/AdGuardHome/AdGuardHome.yaml",
        }
        audit = '''import os, pathlib
target = pathlib.Path(os.environ['AF_TEST_SECRET_PATH'])
if target.exists():
    with (pathlib.Path(os.environ['AF_FIXTURE_ROOT']) / 'creation-modes').open('a') as output:
        output.write(str(target.stat().st_mode & 0o777) + '\\n')
'''
        previous_umask = os.umask(0o022)
        try:
            for app, relative in paths.items():
                with self.subTest(app=app), InstallerFixture(app) as fixture:
                    fixture.file("mock-bin/cat", "#!/usr/bin/python3\nimport sys\n" + audit + "os.execv('/usr/bin/cat', ['/usr/bin/cat', *sys.argv[1:]])\n").chmod(0o755)
                    if app == "novnc":
                        CatalogLifecycleMatrix.patch_host_command(self, fixture, "vncpasswd", "version = os.environ.get", audit + "version = os.environ.get")
                    result = fixture.run(AF_TEST_SECRET_PATH=str(fixture.root / relative))
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    recorded = [int(mode) for mode in (fixture.root / "creation-modes").read_text().splitlines()]
                    self.assertTrue(recorded)
                    self.assertEqual(set(recorded), {0o600}, recorded)
                    self.assertEqual((fixture.root / relative).stat().st_mode & 0o777, 0o600)
        finally:
            os.umask(previous_umask)

    def test_fresh_loopback_defaults_and_retained_operator_listener_policy(self):
        cases = {
            "qbittorrent": ("var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
                            ("WebUI\\Address=127.0.0.1", "WebUI\\HostHeaderValidation=true", "WebUI\\CSRFProtection=true")),
            "sabnzbd": ("var/lib/sabnzbd/sabnzbd.ini", ("host = 127.0.0.1", "inet_exposure = 0")),
            "adguardhome": ("opt/AdGuardHome/AdGuardHome.yaml", ("address: 127.0.0.1:",)),
            "n8n": ("etc/systemd/system/n8n.service", ("N8N_LISTEN_ADDRESS=127.0.0.1",)),
            "flaresolverr": ("etc/systemd/system/flaresolverr.service", ("HOST=127.0.0.1",)),
            "autobrr": ("var/lib/autobrr/config.toml", ('host = "127.0.0.1"',)),
            "qui": ("var/lib/qui/config.toml", ('host = "127.0.0.1"',)),
            "nzbget": ("var/lib/nzbget/nzbget.conf", ("ControlIP = 127.0.0.1",)),
            "bazarr": ("var/lib/bazarr/config/config.yaml", ("ip: 127.0.0.1",)),
            "tautulli": ("var/lib/tautulli/config.ini", ("http_host = 127.0.0.1",)),
            "gitea": ("etc/gitea/app.ini", ("HTTP_ADDR = 127.0.0.1",)),
            "flood": ("etc/systemd/system/flood.service", ("--host 127.0.0.1",)),
            "navidrome": ("var/lib/navidrome/navidrome.toml", ('Address = "127.0.0.1"',)),
            "thelounge": ("var/lib/thelounge/config.js", ('host: "127.0.0.1"',)),
            "homeassistant": ("home/homeassistant/.homeassistant/configuration.yaml", ("server_host: 127.0.0.1",)),
            "kavita": ("etc/systemd/system/kavita.service", ("ASPNETCORE_URLS=http://127.0.0.1:",)),
            "dispatcharr": ("etc/systemd/system/dispatcharr.service", ("daphne -b 127.0.0.1",)),
            "audiobookshelf": ("etc/systemd/system/audiobookshelf.service", ("HOST=127.0.0.1",)),
            "filebot": ("var/lib/filebot/filebot-node.env", ("FILEBOT_NODE_HOST=127.0.0.1",)),
            "librespeed": ("opt/librespeed/settings.toml", ('bind_address="127.0.0.1"',)),
            "pyload": ("var/lib/pyload/settings/pyload.cfg", ('ip host : "IP address" = 127.0.0.1',)),
            "scrutiny": ("etc/scrutiny/scrutiny.yaml", ('host: "127.0.0.1"',)),
            "paperless-ngx": ("etc/paperless.conf", ("PAPERLESS_BIND_ADDR=127.0.0.1", "PAPERLESS_ALLOWED_HOSTS=localhost,127.0.0.1,[::1]")),
        }
        for app, (relative, settings) in cases.items():
            with self.subTest(app=app), InstallerFixture(app) as fixture:
                installed = fixture.run()
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                config = fixture.root / relative
                for setting in settings:
                    self.assertIn(setting, config.read_text())
                unit_policy = {
                    "sabnzbd": ("etc/systemd/system/sabnzbd.service", " -s {host}:"),
                    "paperless-ngx": ("etc/systemd/system/paperless-webserver.service", "gunicorn -b {host}:"),
                }.get(app)
                if unit_policy:
                    unit, listener = unit_policy
                    self.assertIn(listener.format(host="127.0.0.1"), (fixture.root / unit).read_text())
                if app not in ("adguardhome", "n8n", "flaresolverr"):
                    operator_settings = [setting.replace("127.0.0.1", "192.0.2.45").replace("=true", "=false").replace("= 0", "= 4") for setting in settings]
                    text = config.read_text()
                    for before, after in zip(settings, operator_settings):
                        text = text.replace(before, after)
                    config.write_text(text)
                    for action in ("update", "reinstall"):
                        retained = fixture.run(action)
                        self.assertEqual(retained.returncode, 0, retained.stdout + retained.stderr)
                        for setting in operator_settings:
                            self.assertIn(setting, config.read_text())
                        if unit_policy:
                            self.assertIn(listener.format(host="192.0.2.45"), (fixture.root / unit).read_text())

    def test_account_bootstrap_and_rotation_fail_closed_and_restore_state(self):
        for app in ("qui", "autobrr"):
            with self.subTest(app=app, phase="bootstrap"), InstallerFixture(app) as fixture:
                failed = fixture.run(AF_FIXTURE_FAILURE="account-create")
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                self.assertFalse(fixture.lock.exists())
                self.assertFalse((fixture.root / f"active-{app}.service").exists())
                self.assertFalse((fixture.root / f"var/lib/{app}/config.toml").exists())
            with self.subTest(app=app, phase="rotation"), InstallerFixture(app) as fixture:
                installed = fixture.run()
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                config = fixture.root / f"var/lib/{app}/config.toml"
                database = fixture.root / f"var/lib/{app}/{app}.db"
                previous_config, previous_database, previous_marker = config.read_bytes(), database.read_bytes(), fixture.lock.read_bytes()
                failed = fixture.run("update", AF_CONFIG_PASS="rotated-password", AF_KEEP_EXISTING_SECRETS="0", AF_FIXTURE_FAILURE="account-rotate")
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                self.assertEqual(config.read_bytes(), previous_config)
                self.assertEqual(database.read_bytes(), previous_database)
                self.assertEqual(fixture.lock.read_bytes(), previous_marker)
                commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()]
                self.assertTrue(any("change-password" in command for command in commands))
                rotated = fixture.run("update", AF_CONFIG_PASS="rotated-password", AF_KEEP_EXISTING_SECRETS="0", AF_FIXTURE_FAILURE="account-exists")
                self.assertEqual(rotated.returncode, 0, rotated.stdout + rotated.stderr)

    def test_rollback_requires_quiescence_and_retains_recovery_on_systemd_errors(self):
        cases = {
            "n8n": ("stop", "active", "daemon-reload", "restart"),
            "flood": ("stop", "active", "daemon-reload", "restart"),
            "prometheus": ("stop", "active", "daemon-reload", "restart"),
            "bazarr": ("stop", "active"), "tautulli": ("stop", "active"),
            "sabnzbd": ("stop", "active"), "invidious": ("stop", "active"),
            "piped": ("stop", "active"), "navidrome": ("stop", "active", "daemon-reload", "restart"),
            "palate": ("stop", "active"),
        }
        injection = """if command == 'systemctl':
    triggered = root / 'rollback-triggered'
    fault = os.environ.get('AF_ROLLBACK_FAULT')
    if fault and triggered.exists():
        if arguments[0] == 'stop' and fault == 'stop': sys.exit(73)
        if arguments[0] == 'stop' and fault == 'active': sys.exit(0)
        if arguments[0] == fault or arguments[0] == 'start' and fault == 'restart': sys.exit(74)
    targets_app = any(unit.removesuffix('.service') == os.environ.get('AF_ROLLBACK_UNIT', '').removesuffix('.service') for unit in units())
    if fault and targets_app and not triggered.exists() and (arguments[0] in ('restart', 'start') or arguments[0] == 'enable' and '--now' in arguments):
        (root / os.environ['AF_ROLLBACK_STATE']).write_text('failed-runtime-state')
        for unit in units(): (root / ('active-' + unit)).touch()
        triggered.touch()
        sys.exit(75)
"""
        for app, faults in cases.items():
            for fault in faults:
                with self.subTest(app=app, fault=fault), InstallerFixture(app) as fixture:
                    installed = fixture.run()
                    self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                    relative = f"var/lib/{app}/" + ("navidrome.db" if app == "navidrome" else "rollback-state")
                    state = fixture.file(relative, "previous-runtime-state")
                    CatalogLifecycleMatrix.patch_host_command(self, fixture, "systemctl", "if command == 'systemctl':\n", injection)
                    failed = fixture.run("update", AF_ROLLBACK_FAULT=fault, AF_ROLLBACK_STATE=relative,
                                         AF_ROLLBACK_UNIT=fixture.metadata["service_name"])
                    self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                    self.assertTrue((fixture.root / "rollback-triggered").exists())
                    if fault in ("stop", "active"):
                        self.assertEqual(state.read_text(), "failed-runtime-state")
                        self.assertIn("Incomplete rollback: failed to stop", failed.stdout + failed.stderr)
                    else:
                        self.assertEqual(state.read_text(), "previous-runtime-state")
                    recoveries = [path for path in fixture.root.rglob("*")
                                  if path.name in ("rollback-state", "data-1") and path != state
                                  and path.is_file() and path.read_text() == "previous-runtime-state"]
                    self.assertTrue(recoveries, failed.stdout + failed.stderr)
                    self.assertIn("recovery backup preserved", failed.stdout + failed.stderr)

    def test_shared_state_rollback_preserves_live_trees_when_stopping_fails(self):
        for stopped_status, active_status in ((73, 3), (0, 0)):
            with self.subTest(stop=stopped_status, active=active_status), InstallerFixture("threadfin") as fixture:
                state = fixture.file("var/lib/threadfin/rollback-state", "previous-state")
                program = r'''
PACKAGE_NAME=threadfin
begin_state_transaction threadfin 34400 / "$AF_FIXTURE_ROOT/var/lib/threadfin"
printf 'live-state' > "$AF_FIXTURE_ROOT/var/lib/threadfin/rollback-state"
systemctl() {
    case "$1" in
        stop) return "$AF_STOP_STATUS" ;;
        is-active) return "$AF_ACTIVE_STATUS" ;;
        *) return 0 ;;
    esac
}
exit 1
'''
                failed = self.shell(fixture, program, AF_STOP_STATUS=str(stopped_status), AF_ACTIVE_STATUS=str(active_status))
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                self.assertEqual(state.read_text(), "live-state")
                backups = list((fixture.root / "tmp").glob("af-state-*"))
                self.assertEqual(len(backups), 1)
                self.assertEqual((backups[0] / "state/0/rollback-state").read_text(), "previous-state")
                self.assertEqual(backups[0].stat().st_mode & 0o777, 0o700)
                self.assertIn("Incomplete rollback: failed to stop threadfin", failed.stderr)

    def test_versioned_python_interpreters_resolve_to_the_fixture(self):
        with InstallerFixture("dispatcharr") as fixture:
            for version in ("3.13", "3.12", "3.11", "3.10"):
                path = fixture.commands / ("python" + version)
                self.assertEqual(path.read_bytes(), (fixture.commands / "python3").read_bytes())
            result = fixture.run()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_youtube_assets_with_null_digest_use_companion_checksums(self):
        with InstallerFixture("invidious") as fixture:
            CatalogLifecycleMatrix.patch_host_command(self, fixture, "jq",
                "elif 'digest' in query: print('sha256:' + hashlib.sha256((root / 'release.tar.gz').read_bytes()).hexdigest())",
                "elif 'digest' in query: pass")
            result = fixture.run(AF_TEST_NO_LOCAL_SHA256="1")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            commands = (fixture.root / "commands.jsonl").read_text()
            self.assertIn("crystal-1.22.2-1-linux-x86_64-bundled.tar.gz.sha256", commands)
            failed = fixture.run("update", AF_TEST_DISABLE_CHECKSUM_URLS="1")
            self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)

    def test_invidious_build_path_includes_nested_crystal_toolchain_bins(self):
        with InstallerFixture("invidious") as fixture:
            nested = fixture.file("opt/invidious/crystal/crystal-1.22.2/bin/crystal", "fixture\n").parent
            result = fixture.run()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()]
            builds = [command for command in commands if command[0] == "runuser" and any("make" in argument for argument in command)]
            self.assertTrue(any(str(nested) in argument for command in builds for argument in command if argument.startswith("PATH=")))

    def test_legacy_cli_preserves_hyphenated_names_and_exports_the_guard_fd(self):
        with InstallerFixture("threadfin") as fixture:
            cli = fixture.file("packages/system/af", fixture.rewrite((ROOT / "packages/system/af").read_text()))
            fixture.file("packages/package/install/installpackage-paperless-ngx", 'printf "%s\\n" "$AF_MAINTENANCE_GUARD_FD" > "$AF_FIXTURE_ROOT/guard-fd"\n')
            fixture.file("opt/AetherFlow/packages/package/install/installpackage-paperless-ngx", 'printf "%s\\n" "$AF_MAINTENANCE_GUARD_FD" > "$AF_FIXTURE_ROOT/guard-fd"\n')
            variables = {**os.environ, "AF_FIXTURE_ROOT": str(fixture.root), "AF_FIXTURE_APP": fixture.app,
                         "PATH": str(fixture.commands) + ":/usr/bin:/bin", "bold": "", "normal": ""}
            for terminal in ("dumb", "", "xterm-256color"):
                with self.subTest(TERM=terminal):
                    variables["TERM"] = terminal
                    listed = subprocess.run(["bash", str(cli), "list"], env=variables, text=True, capture_output=True, timeout=15)
                    self.assertEqual(listed.returncode, 0, listed.stdout + listed.stderr)
                    self.assertIn("paperless-ngx", listed.stdout)
                    installed = subprocess.run(["bash", str(cli), "install", "paperless-ngx"], env=variables, text=True, capture_output=True, timeout=15)
                    self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                    self.assertEqual((fixture.root / "guard-fd").read_text(), "200\n")
                    invalid = subprocess.run(["bash", str(cli), "preinstall", "paperless-ngx"], env=variables, text=True, capture_output=True, timeout=15)
                    self.assertIn("invalid command", invalid.stdout)

    def test_piped_copies_a_modern_root_toolchain_for_the_service_user(self):
        with InstallerFixture("piped") as fixture:
            compiler = fixture.file("root/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/rustc", '#!/bin/sh\ntouch "$AF_FIXTURE_ROOT/compiler-probed-directly"\nprintf "rustc 1.90.0 (fixture)\\n"\n')
            compiler.chmod(0o755)
            fixture.file("root/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/bin/cargo", "#!/bin/sh\nexit 0\n").chmod(0o755)
            result = fixture.run(AF_FIXTURE_RUST_VERSION="1.85.1")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()]
            builds = [command for command in commands if command[0] == "runuser" and "cargo" in command and "build" in command]
            self.assertTrue(builds)
            self.assertTrue(any("rust-toolchain-" in argument and "/bin:" in argument for argument in builds[-1]))
            self.assertFalse((fixture.root / "compiler-probed-directly").exists())
        with InstallerFixture("piped") as fixture:
            failed = fixture.run(AF_FIXTURE_RUST_VERSION="1.85.1")
            self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
            self.assertIn("requires Rust >= 1.89", failed.stdout + failed.stderr)

    def test_kasmvnc_uses_a_private_service_certificate_and_stops_failed_activation(self):
        with InstallerFixture("kasmvnc") as fixture:
            installed = fixture.run()
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            certificate = fixture.root / "var/lib/kasmvnc/.vnc/aetherflow-cert.pem"
            key = fixture.root / "var/lib/kasmvnc/.vnc/aetherflow-key.pem"
            for path in (certificate, key):
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            unit = (fixture.root / "etc/systemd/system/af-kasmvnc.service").read_text()
            self.assertIn("-cert " + str(certificate), unit)
            self.assertIn("-key " + str(key), unit)
            self.assertNotIn("snakeoil", unit)
            failed = fixture.run("update", AF_FIXTURE_FAILURE="service", AF_FIXTURE_FAILURE_UNIT="af-kasmvnc.service")
            self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
            self.assertTrue((fixture.root / "active-af-kasmvnc.service").exists())
            self.assertTrue((fixture.root / "enabled-af-kasmvnc.service").exists())
            commands = [json.loads(line) for line in (fixture.root / "commands.jsonl").read_text().splitlines()]
            self.assertNotIn(["systemctl", "disable", "af-kasmvnc.service"], commands)


class R16ShellInstallerRegressions(unittest.TestCase):
    def commands(self, fixture):
        log = fixture.root / 'commands.jsonl'
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def test_adguard_download_and_extraction_failures_do_not_change_resolver_policy(self):
        for failure in ('download', 'archive'):
            with self.subTest(failure=failure), InstallerFixture('adguardhome') as fixture:
                resolved = fixture.file('etc/systemd/resolved.conf', '[Resolve]\n#DNSStubListener=yes\nDNS=192.0.2.1\n')
                resolved.chmod(0o644)
                before = resolved.read_bytes()
                if failure == 'archive':
                    fixture.file('release.tar.gz', 'not-an-archive')
                failed = fixture.run(AF_FIXTURE_FAILURE='download' if failure == 'download' else '')
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                if failure == 'download':
                    self.assertEqual(failed.returncode, 22)
                self.assertEqual(resolved.read_bytes(), before)
                self.assertEqual(resolved.stat().st_mode & 0o777, 0o644)
                self.assertFalse((fixture.root / 'etc/systemd/resolved.conf.d/aetherflow-adguardhome.conf').exists())
                self.assertFalse(fixture.lock.exists())
                self.assertNotIn(['systemctl', 'restart', 'systemd-resolved'], self.commands(fixture))

    def test_adguard_failed_activation_restores_resolver_and_owned_dropin_exactly(self):
        for retained_dropin in (None, '[Resolve]\nDNSStubListener=yes\nDNS=192.0.2.2\n'):
            with self.subTest(retained_dropin=retained_dropin), InstallerFixture('adguardhome') as fixture:
                resolved = fixture.file('etc/systemd/resolved.conf', '[Resolve]\nDNSStubListener=yes\nDNS=192.0.2.1\n')
                resolved.chmod(0o640)
                before = resolved.read_bytes()
                relative = 'etc/systemd/resolved.conf.d/aetherflow-adguardhome.conf'
                if retained_dropin is not None:
                    fixture.file(relative, retained_dropin).chmod(0o600)
                failed = fixture.run(AF_FIXTURE_FAILURE='service', AF_FIXTURE_FAILURE_UNIT='adguardhome.service')
                self.assertEqual(failed.returncode, 73, failed.stdout + failed.stderr)
                self.assertEqual(resolved.read_bytes(), before)
                self.assertEqual(resolved.stat().st_mode & 0o777, 0o640)
                dropin = fixture.root / relative
                if retained_dropin is None:
                    self.assertFalse(dropin.exists())
                else:
                    self.assertEqual(dropin.read_text(), retained_dropin)
                    self.assertEqual(dropin.stat().st_mode & 0o777, 0o600)
                self.assertFalse(fixture.lock.exists())
                self.assertEqual(self.commands(fixture).count(['systemctl', 'restart', 'systemd-resolved']), 2)

    def test_adguard_uninstall_changes_only_aetherflow_owned_resolver_policy(self):
        for setting in ('no', 'yes'):
            with self.subTest(setting=setting), InstallerFixture('adguardhome') as fixture:
                resolved = fixture.file('etc/systemd/resolved.conf', f'[Resolve]\nDNSStubListener={setting}\nDNS=192.0.2.1\n')
                before = resolved.read_bytes()
                installed = fixture.run()
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                dropin = fixture.root / 'etc/systemd/resolved.conf.d/aetherflow-adguardhome.conf'
                self.assertEqual(dropin.exists(), setting == 'yes')
                self.assertEqual(resolved.read_bytes(), before)
                removed = fixture.run('uninstall')
                self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
                self.assertEqual(resolved.read_bytes(), before)
                self.assertFalse(dropin.exists())
                self.assertEqual(self.commands(fixture).count(['systemctl', 'restart', 'systemd-resolved']), 0 if setting == 'no' else 2)

    def test_adguard_rejects_unsafe_retained_config_before_staging_or_chmod(self):
        for kind in ('symlink', 'parent-symlink', 'hardlink', 'directory'):
            with self.subTest(kind=kind), InstallerFixture('adguardhome') as fixture:
                target = fixture.file('outside-adguard/operator-config', 'operator-secret\n')
                target.chmod(0o644)
                directory = fixture.root / 'opt/AdGuardHome'
                if kind == 'parent-symlink':
                    directory.symlink_to(target.parent, target_is_directory=True)
                else:
                    directory.mkdir()
                    config = directory / 'AdGuardHome.yaml'
                    if kind == 'symlink':
                        config.symlink_to(target)
                    elif kind == 'hardlink':
                        os.link(target, config)
                    else:
                        config.mkdir()
                failed = fixture.run('reinstall')
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                self.assertEqual(target.read_text(), 'operator-secret\n')
                self.assertEqual(target.stat().st_mode & 0o777, 0o644)
                self.assertFalse(list((fixture.root / 'opt').glob('AdGuardHome.af-backup.*')))
                self.assertFalse(any(command[0] in ('chown', 'setcap', 'apt-get') for command in self.commands(fixture)))

    def test_adguard_retained_reinstall_updates_both_http_ports_and_preserves_policy(self):
        for endpoint in ('192.0.2.45:3080', '"[::1]:3080"'):
            with self.subTest(endpoint=endpoint), InstallerFixture('adguardhome') as fixture:
                retained = ('bind_host: 192.0.2.45\nbind_port: 3080\nhttp:\n'
                            '  pprof:\n    port: 6060\n    enabled: false\n'
                            f'  address: {endpoint}\n  session_ttl: 720h\n'
                            'users:\n  - name: operator\n    password: retained-hash\n'
                            'dns:\n  bind_hosts:\n    - 192.0.2.46\n  port: 53\n  upstream_dns:\n    - 9.9.9.9\n')
                config = fixture.file('opt/AdGuardHome/AdGuardHome.yaml', retained)
                installed = fixture.run('reinstall', port=18380)
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                self.assertEqual(config.read_text(), retained.replace('bind_port: 3080', 'bind_port: 18380').replace(endpoint, endpoint.replace(':3080', ':18380')))
                self.assertEqual(config.stat().st_mode & 0o777, 0o600)

    def test_grafana_failed_update_reconciles_dpkg_runtime_and_retry_receipt(self):
        for rollback_failure in ('0', '1'):
            with self.subTest(rollback_failure=rollback_failure), InstallerFixture('grafana') as fixture:
                environment = {'AF_FIXTURE_PERSISTENT_APT': '1'}
                installed = fixture.run(AF_FIXTURE_VERSION='1.0.0', **environment)
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                runtime = fixture.root / 'usr/share/grafana/bin/grafana-server'
                receipt = fixture.root / 'var/lib/grafana/.af-version'
                failed = fixture.run('update', AF_FIXTURE_VERSION='2.2.0', AF_FIXTURE_FAILURE='service',
                                     AF_FIXTURE_APT_ROLLBACK_FAILURE=rollback_failure, **environment)
                self.assertEqual(failed.returncode, 73 if rollback_failure == '0' else 1, failed.stdout + failed.stderr)
                self.assertEqual(runtime.read_text(), 'package-runtime-1.0.0\n')
                self.assertEqual(receipt.read_text(), '1.0.0\n')
                state = json.loads((fixture.root / 'dpkg-state.json').read_text())
                self.assertEqual(state['grafana'], '1.0.0' if rollback_failure == '0' else '2.2.0')
                marker = fixture.root / 'var/lib/aetherflow/apt-reinstall-required/grafana'
                self.assertEqual(marker.exists(), rollback_failure == '1')
                self.assertTrue(any(command[:2] == ['apt-get', 'install'] and '--allow-downgrades' in command and '--reinstall' in command and 'grafana=1.0.0' in command for command in self.commands(fixture)))
                count = len(self.commands(fixture))
                retried = fixture.run('update', AF_FIXTURE_VERSION='2.2.0', **environment)
                self.assertEqual(retried.returncode, 0, retried.stdout + retried.stderr)
                self.assertEqual(json.loads((fixture.root / 'dpkg-state.json').read_text())['grafana'], '2.2.0')
                self.assertEqual(runtime.read_text(), 'package-runtime-2.2.0\n')
                self.assertEqual(receipt.read_text(), '2.2.0\n')
                self.assertFalse(marker.exists())
                if rollback_failure == '1':
                    self.assertTrue(any(command[:2] == ['apt-get', 'install'] and '--reinstall' in command and 'grafana' in command for command in self.commands(fixture)[count:]))

    def test_grafana_mismatched_receipt_forces_reinstall_even_without_recovery_marker(self):
        with InstallerFixture('grafana') as fixture:
            environment = {'AF_FIXTURE_PERSISTENT_APT': '1'}
            installed = fixture.run(AF_FIXTURE_VERSION='1.0.0', **environment)
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            fixture.file('dpkg-state.json', json.dumps({'grafana': '2.2.0'}))
            count = len(self.commands(fixture))
            retried = fixture.run('update', AF_FIXTURE_VERSION='2.2.0', **environment)
            self.assertEqual(retried.returncode, 0, retried.stdout + retried.stderr)
            self.assertEqual((fixture.root / 'usr/share/grafana/bin/grafana-server').read_text(), 'package-runtime-2.2.0\n')
            self.assertTrue(any(command[:2] == ['apt-get', 'install'] and '--reinstall' in command and 'grafana' in command for command in self.commands(fixture)[count:]))

    def test_apt_metapackage_retry_reinstalls_marked_runtime_dependency(self):
        with InstallerFixture('jellyfin') as fixture:
            transaction = fixture.root / 'tmp/apt-transaction'
            transaction.mkdir()
            receipt = fixture.file('var/lib/jellyfin/.af-version', '2.1.0\n')
            fixture.file('var/lib/aetherflow/apt-reinstall-required/jellyfin-server', '1.0.0\n')
            variables = {**os.environ, 'PATH': str(fixture.commands) + ':/usr/bin:/bin',
                         'AF_FIXTURE_ROOT': str(fixture.root), 'AF_FIXTURE_APP': fixture.app,
                         'AF_FIXTURE_VERSION': '2.1.0', 'AF_TX_DIR': str(transaction)}
            result = subprocess.run(['bash', '-euc', 'source "$1"; prepare_apt_package_transaction "$2" jellyfin jellyfin-server jellyfin-web; apt-get install -y jellyfin',
                                     'fixture', str(fixture.root / 'packages/common.sh'), str(receipt)],
                                    env=variables, text=True, capture_output=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(['apt-get', 'install', '--reinstall', '-y', 'jellyfin', 'jellyfin-server'], self.commands(fixture))

    def run_legacy_cli(self, fixture, *arguments, **environment):
        cli = fixture.file('packages/system/af', fixture.rewrite((ROOT / 'packages/system/af').read_text()))
        variables = {**os.environ, 'AF_FIXTURE_ROOT': str(fixture.root), 'AF_FIXTURE_APP': fixture.app,
                     'PATH': str(fixture.commands) + ':/usr/bin:/bin', 'AETHERFLOW_CLI_BIN': '',
                     'AETHERFLOW_USE_RUNNER': '0', 'AF_KEEP_EXISTING_SECRETS': '0', **environment}
        return subprocess.run(['bash', str(cli), *arguments], env=variables, text=True, capture_output=True, timeout=15)

    def test_legacy_cli_rejects_usage_errors_and_invalid_package_names(self):
        cases = [('unknown-command',), ('install',), ('reinstall',), ('remove',),
                 ('self-update', 'threadfin'), ('list', 'threadfin'), ('upgrade', 'threadfin')]
        cases += [(action, package) for action in ('install', 'reinstall', 'update', 'remove')
                  for package in ('missing-package', '../threadfin', '')]
        for arguments in cases:
            with self.subTest(arguments=arguments), InstallerFixture('threadfin') as fixture:
                result = self.run_legacy_cli(fixture, *arguments)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertFalse(any(command[0] == 'git' for command in self.commands(fixture)))

    def test_legacy_cli_dispatches_lifecycle_updates_instead_of_repo_pulls(self):
        for action in ('install', 'reinstall', 'update', 'remove'):
            with self.subTest(action=action), InstallerFixture('threadfin') as fixture:
                directory = 'remove' if action == 'remove' else 'install'
                fixture.file(f'opt/AetherFlow/packages/package/{directory}/{directory}package-paperless-ngx',
                             'printf "%s|%s|%s\\n" "$AF_LIFECYCLE_ACTION" "$AF_PACKAGE_ACTION" "$AF_KEEP_EXISTING_SECRETS" > "$AF_FIXTURE_ROOT/cli-lifecycle"\nexit "${AF_FIXTURE_CLI_STATUS:-0}"\n')
                if action != 'install':
                    fixture.file('install/.paperless-ngx.lock', 'installed\n')
                result = self.run_legacy_cli(fixture, action, 'paperless-ngx')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                lifecycle = action
                keep = '1' if action in ('reinstall', 'update') else '0'
                self.assertEqual((fixture.root / 'cli-lifecycle').read_text(), f'{lifecycle}|{action}|{keep}\n')
                self.assertFalse(any(command[0] == 'git' for command in self.commands(fixture)))
                failed = self.run_legacy_cli(fixture, action, 'paperless-ngx', AF_FIXTURE_CLI_STATUS='73')
                self.assertEqual(failed.returncode, 73, failed.stdout + failed.stderr)

    def test_legacy_cli_forwards_all_lifecycle_arguments_to_authoritative_cli(self):
        with InstallerFixture('threadfin') as fixture:
            authoritative = fixture.file('usr/local/bin/af-cli', '#!/bin/bash\nprintf "%s\\n" "$@" > "$AF_FIXTURE_ROOT/cli-arguments"\nexit 31\n')
            authoritative.chmod(0o755)
            for action in ('install', 'reinstall', 'update', 'remove'):
                with self.subTest(action=action):
                    arguments = (action, 'paperless-ngx', 'threadfin', '--fixture-option')
                    result = self.run_legacy_cli(fixture, *arguments)
                    self.assertEqual(result.returncode, 31, result.stdout + result.stderr)
                    self.assertEqual((fixture.root / 'cli-arguments').read_text().splitlines(), list(arguments))


class R17ShellInstallerRegressions(unittest.TestCase):
    commands = R16ShellInstallerRegressions.commands
    shell = R15SharedInstallerRegressions.shell
    run_legacy_cli = R16ShellInstallerRegressions.run_legacy_cli
    patch_host_command = CatalogLifecycleMatrix.patch_host_command

    def database_probe(self, fixture):
        injection = """if command in ('mysqldump', 'pg_dump'):
    if os.environ.get('AF_PROBE_BACKUP') == 'fail': sys.exit(71)
    if os.environ.get('AF_PROBE_BACKUP') != 'empty':
        print((root / os.environ['AF_PROBE_DATABASE']).read_text(), end='')
    (root / 'database-backup-password').write_text(os.environ.get('MYSQL_PWD', os.environ.get('PGPASSWORD', '')))
    sys.exit(0)
if command == 'psql':
    if '--quiet' in arguments:
        print('SELECT 1;')
    elif '--command=ROLLBACK' not in arguments:
        backup = next(argument.split('=', 1)[1] for argument in arguments if argument.startswith('--file=') and argument.endswith('/database.sql'))
        (root / os.environ['AF_PROBE_DATABASE']).write_text(pathlib.Path(backup).read_text())
    sys.exit(0)
if command == 'mysql':
    (root / os.environ['AF_PROBE_DATABASE']).write_text(sys.stdin.read())
    sys.exit(0)
if command == 'systemctl':
"""
        for command in ('mysqldump', 'pg_dump', 'mysql', 'psql'):
            self.patch_host_command(fixture, command, "if command == 'systemctl':\n", injection)

    def test_nextcloud_configured_databases_restore_before_old_runtime_restart(self):
        for backend in ('mysql', 'pgsql', 'sqlite3'):
            with self.subTest(backend=backend), InstallerFixture('nextcloud') as fixture:
                data = fixture.root / 'var/lib/operator-nextcloud'
                relative = 'var/lib/operator-nextcloud/owncloud.db' if backend == 'sqlite3' else 'database-operator_nextcloud'
                schema = fixture.file(relative, 'schema-v31\n')
                unrelated = fixture.file('database-nextcloud', 'unrelated-database\n')
                config = fixture.file('var/www/nextcloud/config/config.php',
                    f"<?php /* 'dbname' => 'nextcloud' */ $CONFIG = ['dbtype' => '{backend}', 'dbname' => 'operator_nextcloud', "
                    f"'dbhost' => 'db.example:5432', 'dbuser' => 'operator', 'dbpassword' => 'retained-password', 'datadirectory' => '{data}'];\n")
                original_config = config.read_bytes()
                runtime = fixture.file('var/www/nextcloud/old-code.php', 'previous-runtime\n')
                fixture.file('var/www/nextcloud/occ', 'previous-occ\n')
                version = fixture.file('var/www/nextcloud/.af-version', '31.0.0\n')
                fixture.file('install/.nextcloud.lock', 'prior-receipt\n')
                before_lock = fixture.lock.stat().st_mtime_ns
                self.database_probe(fixture)
                self.patch_host_command(fixture, 'sudo', "if command == 'systemctl':\n", r"""if command == 'sudo' and 'upgrade' in arguments:
    (root / os.environ['AF_PROBE_DATABASE']).write_text('schema-v32\n')
    sys.exit(75)
if command == 'systemctl':
""")
                failed = fixture.run('update', AF_PROBE_DATABASE=relative)
                self.assertEqual(failed.returncode, 75, failed.stdout + failed.stderr)
                self.assertEqual(schema.read_text(), 'schema-v31\n')
                self.assertEqual(unrelated.read_text(), 'unrelated-database\n')
                self.assertEqual(config.read_bytes(), original_config)
                self.assertEqual(runtime.read_text(), 'previous-runtime\n')
                self.assertEqual(version.read_text(), '31.0.0\n')
                self.assertEqual(fixture.lock.stat().st_mtime_ns, before_lock)
                commands = self.commands(fixture)
                if backend != 'sqlite3':
                    dump = next(command for command in commands if command[0] in ('mysqldump', 'pg_dump'))
                    self.assertEqual(dump[-1], 'operator_nextcloud')
                    self.assertIn('--host=db.example', dump)
                    self.assertIn('--port=5432', dump)
                    self.assertNotIn('retained-password', json.dumps(commands))
                    self.assertEqual((fixture.root / 'database-backup-password').read_text(), 'retained-password')

    def test_database_dump_failure_or_empty_output_never_runs_migrations(self):
        for app in ('nextcloud', 'gitea'):
            for failure in ('fail', 'empty'):
                with self.subTest(app=app, failure=failure), InstallerFixture(app) as fixture:
                    if app == 'nextcloud':
                        fixture.file('var/www/nextcloud/config/config.php', "<?php $CONFIG = ['dbname' => 'operator_nextcloud'];\n")
                        fixture.file('var/www/nextcloud/occ', 'previous-occ\n')
                        runtime = fixture.file('var/www/nextcloud/old-code.php', 'previous-runtime\n')
                    else:
                        fixture.file('etc/gitea/app.ini', '[database]\nDB_TYPE = postgres\nNAME = operator_gitea\n')
                        runtime = fixture.file('usr/local/bin/gitea', 'previous-runtime\n')
                    self.database_probe(fixture)
                    failed = fixture.run('update', AF_PROBE_DATABASE='external-schema', AF_PROBE_BACKUP=failure)
                    self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                    self.assertEqual(runtime.read_text(), 'previous-runtime\n')
                    self.assertFalse(any('upgrade' in command or 'migrate' in command for command in self.commands(fixture)))
                    self.assertFalse(fixture.lock.exists())

    def test_gitea_external_databases_rollback_after_activation_failure(self):
        for backend in ('postgres', 'mysql', 'sqlite3'):
            with self.subTest(backend=backend), InstallerFixture('gitea') as fixture:
                installed = fixture.run()
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                binary = fixture.root / 'usr/local/bin/gitea'
                previous_binary = binary.read_bytes()
                version = fixture.root / 'var/lib/gitea/.af-version'
                previous_version = version.read_bytes()
                schema = fixture.file('srv/operator-gitea/gitea.db', 'schema-v1\n')
                config = fixture.file('etc/gitea/app.ini',
                    f'[database]\nDB_TYPE = {backend}\nNAME = operator_gitea\nHOST = db.example:5432\nUSER = operator\nPASSWD = retained-password\nPATH = {schema}\n')
                previous_config = config.read_bytes()
                self.database_probe(fixture)
                command_offset = len(self.commands(fixture))
                failed = fixture.run('update', AF_FIXTURE_FAILURE='service', AF_FIXTURE_FAILURE_UNIT='gitea.service',
                    AF_FIXTURE_MIGRATION_STATE='srv/operator-gitea/gitea.db', AF_PROBE_DATABASE='srv/operator-gitea/gitea.db')
                self.assertEqual(failed.returncode, 73, failed.stdout + failed.stderr)
                self.assertEqual(schema.read_text(), 'schema-v1\n')
                self.assertEqual(binary.read_bytes(), previous_binary)
                self.assertEqual(config.read_bytes(), previous_config)
                self.assertEqual(version.read_bytes(), previous_version)
                commands = self.commands(fixture)[command_offset:]
                migration = next(index for index, command in enumerate(commands) if 'migrate' in command)
                if backend != 'sqlite3':
                    backup = next(index for index, command in enumerate(commands) if command[0] in ('pg_dump', 'mysqldump'))
                    restore = next(index for index, command in enumerate(commands) if command[0] in ('psql', 'mysql'))
                    restart = max(index for index, command in enumerate(commands) if command[:2] == ['systemctl', 'restart'])
                    self.assertLess(backup, migration)
                    self.assertLess(restore, restart)

    def test_unsupported_backends_and_unsafe_names_fail_before_runtime_mutation(self):
        for app in ('nextcloud', 'gitea'):
            for backend, name in (('oracle', 'operator'), ('mysql', 'operator;DROP_DATABASE')):
                with self.subTest(app=app, backend=backend, name=name), InstallerFixture(app) as fixture:
                    if app == 'nextcloud':
                        fixture.file('var/www/nextcloud/config/config.php', f"<?php $CONFIG = ['dbtype' => '{backend}', 'dbname' => '{name}'];\n")
                    else:
                        fixture.file('etc/gitea/app.ini', f'[database]\nDB_TYPE = {backend}\nNAME = {name}\n')
                    failed = fixture.run('update')
                    self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                    self.assertFalse(any(command[0] in ('apt-get', 'curl', 'sudo') for command in self.commands(fixture)))
        for config in ("<?php $CONFIG = require '/operator/database.php';",
                       "<?php $CONFIG = ['dbname' => getenv('DATABASE_NAME')];",
                       "<?php $CONFIG = ['db' . 'name' => 'operator'];",
                       "<?php $CONFIG = ['dbname' => 'operator' . '_nextcloud'];",
                       "<?php $CONFIG = ['dbname' => 'nextcloud']; $CONFIG['dbname'] = 'operator';"):
            with self.subTest(config=config), InstallerFixture('nextcloud') as fixture:
                fixture.file('var/www/nextcloud/config/config.php', config)
                failed = fixture.run('update')
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                self.assertFalse(any(command[0] in ('apt-get', 'curl', 'sudo') for command in self.commands(fixture)))

    def test_servarr_urlbase_avoids_307_redirects_for_get_put_and_readiness(self):
        requests = []
        class RedirectHandler(BaseHTTPRequestHandler):
            def log_message(self, *arguments):
                pass

            def do_GET(self):
                requests.append(('GET', self.path))
                if not self.path.startswith('/sonarr/'):
                    self.send_response(307)
                    self.send_header('Location', '/sonarr' + self.path)
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps({'id': 1, 'authenticationMethod': 'none'}).encode())

            def do_PUT(self):
                requests.append(('PUT', self.path))
                self.rfile.read(int(self.headers.get('Content-Length', '0')))
                self.send_response(200 if self.path.startswith('/sonarr/') else 307)
                self.send_header('Location', '/sonarr' + self.path)
                self.end_headers()

        server = ThreadingHTTPServer(('127.0.0.1', 0), RedirectHandler)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            with InstallerFixture('sonarr') as fixture:
                fixture.file('var/lib/sonarr/config.xml', '<Config><ApiKey>retained-key</ApiKey><UrlBase> /sonarr/ </UrlBase></Config>')
                fixture.file('mock-bin/python3', '#!/bin/bash\nexec /usr/bin/python3 "$@"\n').chmod(0o755)
                port = str(server.server_port)
                seeded = self.shell(fixture, 'seed_servarr_master_user sonarr "$AF_PROBE_PORT" v3; application_readiness_url sonarr "$AF_PROBE_PORT"', AF_PROBE_PORT=port)
                self.assertEqual(seeded.returncode, 0, seeded.stdout + seeded.stderr)
                self.assertEqual(requests, [('GET', '/sonarr/api/v3/config/host'), ('PUT', '/sonarr/api/v3/config/host/1')])
                self.assertEqual(seeded.stdout.strip(), f'http://127.0.0.1:{port}/sonarr/ping')
        finally:
            server.shutdown()
            server.server_close()
            worker.join(timeout=5)

    def test_six_http_apps_rollback_when_systemd_active_but_http_fails(self):
        runtimes = {'bazarr': 'opt/bazarr', 'overseerr': 'opt/overseerr', 'tautulli': 'opt/Tautulli',
                    'flaresolverr': 'opt/flaresolverr', 'sabnzbd': 'opt/SABnzbd', 'listenarr': 'opt/Listenarr'}
        for app, directory in runtimes.items():
            with self.subTest(app=app), InstallerFixture(app) as fixture:
                retained = {
                    'bazarr': ('var/lib/bazarr/config/config.yaml', 'general:\n  ip: 127.0.0.1\n  base_url: /bazarr/\n'),
                    'tautulli': ('var/lib/tautulli/config.ini', '[General]\nhttp_host = 0.0.0.0\nhttp_root = /tautulli/\n'),
                    'sabnzbd': ('var/lib/sabnzbd/sabnzbd.ini', '__version__ = 19\n[misc]\nhost = 127.0.0.1\nurl_base = /sabnzbd/\n'),
                }
                if app in retained:
                    fixture.file(*retained[app])
                installed = fixture.run()
                self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
                sentinel = fixture.file(directory + '/operator-runtime', 'previous-runtime\n')
                version = fixture.root / directory / '.af-version'
                previous_version = version.read_bytes()
                previous_lock = fixture.lock.stat().st_mtime_ns
                self.patch_host_command(fixture, 'curl', "if command == 'systemctl':\n", """if command == 'curl' and any(argument.startswith(('http://127.0.0.1:', 'http://[::1]:')) for argument in arguments):
    sys.exit(7)
if command == 'systemctl':
""")
                offset = len(self.commands(fixture))
                failed = fixture.run('update')
                self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
                self.assertEqual(sentinel.read_text(), 'previous-runtime\n')
                self.assertEqual(version.read_bytes(), previous_version)
                self.assertEqual(fixture.lock.stat().st_mtime_ns, previous_lock)
                commands = self.commands(fixture)[offset:]
                self.assertTrue(any(command[0] == 'curl' and any('http://127.0.0.1:' in argument for argument in command) for command in commands))
                if app in retained:
                    self.assertTrue(any(command[0] == 'curl' and any(f'/{app}/' in argument for argument in command) for command in commands))

    def test_wireguard_fresh_identity_failure_rolls_back_apt_and_state(self):
        with InstallerFixture('wireguard') as fixture:
            sentinel = fixture.file('etc/wireguard/operator-config', 'previous-config\n')
            self.patch_host_command(fixture, 'wg', "if command == 'systemctl':\n", """if command == 'wg' and 'pubkey' in arguments:
    sys.exit(76)
if command == 'systemctl':
""")
            failed = fixture.run(AF_FIXTURE_PERSISTENT_APT='1')
            self.assertNotEqual(failed.returncode, 0, failed.stdout + failed.stderr)
            self.assertEqual(sentinel.read_text(), 'previous-config\n')
            self.assertFalse((fixture.root / 'etc/wireguard/wg0.conf').exists())
            self.assertEqual(json.loads((fixture.root / 'dpkg-state.json').read_text()), {})
            self.assertFalse(list((fixture.root / 'tmp').glob('af-state-*')))
            self.assertFalse(fixture.lock.exists())
        with InstallerFixture('wireguard') as fixture:
            installed = fixture.run(AF_FIXTURE_PERSISTENT_APT='1')
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            self.assertFalse(list((fixture.root / 'tmp').glob('af-state-*')))
            self.assertFalse(list((fixture.root / 'etc/wireguard').glob('.aetherflow-install.*')))

    def test_kasmvnc_failed_update_preserves_enabled_and_active_state(self):
        with InstallerFixture('kasmvnc') as fixture:
            installed = fixture.run()
            self.assertEqual(installed.returncode, 0, installed.stdout + installed.stderr)
            sentinel = fixture.file('var/lib/kasmvnc/operator-settings', 'previous-settings\n')
            offset = len(self.commands(fixture))
            failed = fixture.run('update', AF_FIXTURE_FAILURE='service', AF_FIXTURE_FAILURE_UNIT='af-kasmvnc.service')
            self.assertEqual(failed.returncode, 73, failed.stdout + failed.stderr)
            self.assertEqual(sentinel.read_text(), 'previous-settings\n')
            self.assertTrue((fixture.root / 'active-af-kasmvnc.service').exists())
            self.assertTrue((fixture.root / 'enabled-af-kasmvnc.service').exists())
            self.assertNotIn(['systemctl', 'disable', 'af-kasmvnc.service'], self.commands(fixture)[offset:])

    def test_legacy_cli_checks_all_update_locks_and_exports_remove_contract(self):
        with InstallerFixture('threadfin') as fixture:
            fixture.file('opt/AetherFlow/packages/package/install/installpackage-threadfin', 'touch "$AF_FIXTURE_ROOT/installer-ran"\n')
            failed = self.run_legacy_cli(fixture, 'update', 'threadfin')
            self.assertEqual(failed.returncode, 1, failed.stdout + failed.stderr)
            self.assertFalse((fixture.root / 'installer-ran').exists())
            self.assertIn('not installed', failed.stderr)
            fixture.file('etc/Swizzin/.threadfin.lock', 'installed\n')
            updated = self.run_legacy_cli(fixture, 'update', 'threadfin')
            self.assertEqual(updated.returncode, 0, updated.stdout + updated.stderr)
            fixture.file('opt/AetherFlow/packages/package/remove/removepackage-threadfin',
                'printf "%s|%s|%s\\n" "$AF_LIFECYCLE_ACTION" "$AF_PACKAGE_ACTION" "$DELETE_DATA" > "$AF_FIXTURE_ROOT/remove-contract"\n')
            for action in ('remove', 'uninstall'):
                for purge in (False, True):
                    removed = self.run_legacy_cli(fixture, action, *(['--purge'] if purge else []), 'threadfin', DELETE_DATA='true')
                    self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
                    self.assertEqual((fixture.root / 'remove-contract').read_text(), f'remove|remove|{str(purge).lower()}\n')

    def test_removers_use_safe_tree_deletion_and_refuse_mounts_and_symlink_parents(self):
        for path in (ROOT / 'packages/package/remove').glob('removepackage-*'):
            self.assertNotRegex(path.read_text(), r'\brm\s+-[rf]*r[rf]*f\b', path.name)
        with InstallerFixture('bazarr') as fixture:
            sentinel = fixture.file('srv/operator-data/sentinel', 'unrelated\n')
            target = fixture.root / 'opt/bazarr'
            target.symlink_to(sentinel.parent, target_is_directory=True)
            removed = self.shell(fixture, 'safe_rm_rf "$AF_FIXTURE_ROOT/opt/bazarr/"')
            self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
            self.assertFalse(target.is_symlink())
            self.assertEqual(sentinel.read_text(), 'unrelated\n')
            target.symlink_to(sentinel.parent, target_is_directory=True)
            refused = self.shell(fixture, 'safe_rm_rf "$AF_FIXTURE_ROOT/opt/bazarr/sentinel"')
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(sentinel.read_text(), 'unrelated\n')
            target.unlink()
            target.mkdir()
            sentinel = fixture.file('opt/bazarr/sentinel', 'mounted-data\n')
            refused = self.shell(fixture, 'mountpoint() { return 0; }; safe_rm_rf "$AF_FIXTURE_ROOT/opt/bazarr"')
            self.assertNotEqual(refused.returncode, 0)
            self.assertEqual(sentinel.read_text(), 'mounted-data\n')


if __name__ == "__main__":
    unittest.main()
