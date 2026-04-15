import urllib.request
import os

icons = [
    'jellyfin', 'readarr', 'prowlarr', 'bazarr', 'overseerr', 'ombi',
    'flaresolverr', 'navidrome', 'flood', 'autobrr', 'filebrowser',
    'wireguard', 'pihole', 'fail2ban', 'vaultwarden', 'grafana',
    'prometheus', 'netdata', 'uptime-kuma', 'home-assistant',
    'portainer', 'gitea', 'organizr'
]

base_url = "https://raw.githubusercontent.com/walkxcode/dashboard-icons/main/png/{}.png"

for icon in icons:
    url = base_url.format(icon)
    # the application ID in packages.json
    save_name = icon
    if icon == 'uptime-kuma': save_name = 'uptimekuma'
    elif icon == 'home-assistant': save_name = 'homeassistant'
    
    out_path = f"c:/Users/armyw/OneDrive/Documents/Antigravity/Projects/AetherFlow/frontend/public/img/{save_name}.png"
    if not os.path.exists(out_path):
        try:
            print(f"Downloading {save_name}...")
            urllib.request.urlretrieve(url, out_path)
            print(f"Success: {save_name}")
        except Exception as e:
            print(f"Failed to download {save_name}: {e}")
