# AetherFlow

[![AetherFlow](https://cdn.aetherflow.io/files/2018/04/af_logo.svg "AetherFlow")](https://github.com/AetherFlow/MediaNexus)

---

## Welcome to AetherFlow

**AetherFlow** is a powerful, lightweight, and modern seedbox management environment. Optimized for performance and ease of use, it serves as the central "Dock" for your media universe.

> **Note:** This project is a modernized fork of the AetherFlow Community Edition, tailored for streamlined performance and enhanced UI aesthetics.

---

## Features

*   **AetherFlow Dashboard**: A comprehensive web interface to manage your server.
*   **Multi-User Environment**: Secure isolation for multiple users.
*   **App Store**: One-click installation for popular apps:
    *   **Media Servers**: Plex, Emby, Jellyfin
    *   **Downloaders**: rTorrent, Deluge, qBittorrent, SABnzbd
    *   **Automation**: Sonarr, Radarr, Lidarr, Bazarr, Readarr
    *   **Utilities**: Tautulli, Ombi, Jackett, Prowlarr
*   **System Monitoring**: Real-time stats for CPU, RAM, Disk, and Bandwidth.
*   **Optimization**: Enhanced process monitoring for low-latency dashboard performance.

---

## Installation

To install AetherFlow, run the following command as root:

```bash
wget -qO AetherFlow-Setup https://raw.githubusercontent.com/McEveritts/AetherFlow/master/setup/AetherFlow-Setup && bash AetherFlow-Setup
```

This will download the latest setup script and initiate the installation process.

---

## Commands

After installation, you can use these commands in your terminal:

*   `af install <package>`: Install an application (e.g., `af install plex`).
*   `af remove <package>`: Remove an application.
*   `setdisk`: Manage user disk quotas.
*   `createSeedboxUser`: Add a new user.
*   `changeUserpass`: Update passwords.
*   `upgradeBox`: Update AetherFlow to the latest version `v3.0.1-PreAlpha.01`.

---

## Credits
