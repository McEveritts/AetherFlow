# AetherMarketplace

The AetherMarketplace is your portal to extending the capabilities of your infrastructure. It features a curated collection of 50+ applications tailored for automation, media management, and system optimization.

## Key Features

- **One-Click Deploy**: Fully automated installation and configuration.
- **Hyperspeed Feedback**: Real-time installation progress tracked via circular indicators in the UI.
- **Native Orchestration**: Every app is installed as a native `systemd` service.
- **Safe Uninstallation**: Robust removal scripts that clean up data and services reliably.

---

## Managed Application Library

AetherFlow manages a wide range of services across multiple categories.

### Media & Downloaders
- **Video & IPTV**: Plex, Jellyfin, Emby, Dispatcharr, Threadfin, Tautulli, Overseerr, Jellyseerr, Requestrr, FileBot, Unmanic.
- **Automation (The Arrs)**: Sonarr, Radarr, Lidarr, Readarr, Listenarr, Bazarr, Prowlarr, Notifiarr.
- **Downloaders**: qBittorrent, Qui, Autobrr, Flood, SeedCross, pyLoad, Deluge, Transmission, Sabnzbd, NZBGet, rTorrent, ruTorrent.

### System & Utilities
- **Observability**: Netdata, Grafana, Prometheus, Uptime Kuma, Scrutiny.
- **File & Backup Management**: Nextcloud, FileBrowser, Syncthing, Duplicati, Rclone, MergerFS, Cloudplow, Paperless-ngx.
- **Security & Network**: Vaultwarden, Fail2Ban, WireGuard, Pi-hole, AdGuard Home, The Lounge, ZNC, Quassel.
- **Core & Remote Desktop**: Gitea, Home Assistant, n8n, Organizr, noVNC, X2Go.

> [!NOTE]
> The availability of certain applications depends on your host OS and architecture. AetherFlow performs a compatibility check before allowing an installation.

---

## Operating Marketplace Apps

### Installing an App
1. Navigate to the **Marketplace** tab.
2. Search for or select your desired application.
3. Click **Install**. 
4. **Action Gate**: If FlowAI is active and you are in Assistant mode, it may propose the installation for you. You will need to approve it in the **Approval Inbox**.

### Monitoring Progress
Installation scripts communicate their state back to the dashboard over WebSockets.
- **Blue (Spinning)**: Dependency resolution and binary download.
- **Green (Check)**: Service has been successfully created and started.
- **Red (Alert)**: Installation failed. You can inspect the logs directly in the **System Logs** panel.

### Removing an App
To uninstall, click the **Uninstall** button on an active application card.
- **Warning**: Most removal scripts offer a prompt to "Delete Data". If selected, this will permanently remove your configuration and database for that application.

---

## System Integration

When you install an app through AetherMarketplace:
1. **User Creation**: A dedicated system user (e.g., `af-plex`) is often created.
2. **Service Unit**: A systemd file is generated at `/etc/systemd/system/af-<appname>.service`.
3. **Log Rotation**: Logs are automatically handled by `journald`.

> [!TIP]
> You can manually control any marketplace app from the CLI using standard commands: `sudo systemctl restart af-plex`.
