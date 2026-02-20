# AetherFlow

[![AetherFlow](https://ptpimg.me/1l3y37.png) "AetherFlow")](https://github.com/AetherFlow/MediaNexus)

---

## Welcome to AetherFlow

**AetherFlow** is a powerful, lightweight, and modern seedbox management environment. Optimized for performance and ease of use, it serves as the central "Dock" for your media universe.

> **Note:** This project is a modernized fork of the AetherFlow Community Edition, tailored for streamlined performance and enhanced UI aesthetics.

---

## Features

*   **AetherFlow Decoupled Dashboard**: A lightning-fast, modern web interface.
    *   **Frontend**: Next.js (React) Single Page Application utilizing a custom `Glassmorphism Engine` built on tailwind and Bootstrap 5.
    *   **Backend API**: High-performance Go (Golang) REST API.
    *   **Legacy Bridge**: Secured PHP-FPM abstraction layer for legacy OS interactions.
*   **Multi-User Environment**: Secure isolation for multiple users and resource quotas.
*   **App Store**: One-click installation for popular apps:
    *   **Media Servers**: Plex, Emby, Jellyfin
    *   **Downloaders**: rTorrent, Deluge, qBittorrent, SABnzbd
    *   **Automation**: Sonarr, Radarr, Lidarr, Bazarr, Readarr
*   **Intelligent System Monitoring**: Go-native hardware telemetry (reads `/proc` asynchronously) for zero-impact CPU, RAM, and Disk polling.
*   **AI Integration**: Features an OAuth 2.0 secured proxy to Google's Gemini Ultra AI for AI-assisted command generation.

---

## Installation

AetherFlow uses an intelligent, self-bootstrapping installer that automatically deploys the Next.js and Go components, alongside the web server (Nginx/Apache), PM2 daemons, and package managers.

To install the entire ecosystem, login as root and run the following command:

```bash
wget -qO AetherFlow-Setup https://raw.githubusercontent.com/McEveritts/AetherFlow/master/setup/AetherFlow-Setup && bash AetherFlow-Setup
```

*Note: The script will automatically clone the repository to `/opt/MediaNexus` and compile the dashboard from source.*

---

## Commands

After installation, you can use these commands in your terminal:

*   `af install <package>`: Install an application (e.g., `af install plex`).
*   `af remove <package>`: Remove an application.
*   `setdisk`: Manage user disk quotas.
*   `createSeedboxUser`: Add a new user.
*   `changeUserpass`: Update passwords.
*   `upgradeBox`: Update AetherFlow to the latest version `v3.0.1`.

---

## Credits
