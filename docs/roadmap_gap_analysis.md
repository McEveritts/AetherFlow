# AetherFlow Ecosystem Gap Analysis & Strategic Bare-Metal Roadmap (v3.2)

## Executive Summary

AetherFlow v3.2 marks a decisive architectural evolution: transitioning from a mixed package-and-container footprint into a **100% Bare-Metal Sovereign Homelab Operating System**. 

In previous iterations, AetherFlow relied on container management tools (such as Portainer) to bridge gaps in personal cloud services and automation. Under the **Strict Zero-Docker Mandate**, AetherFlow v3.2 has completely purged Docker, Docker Compose, and all container runtimes from the core platform, configuration registries, installer scripts, and systemd sandboxing rules. In their place stands an expanded **55-package bare-metal application catalog** (36 retained base packages + 19 newly authored bare-metal services), running natively on Debian 13 (Trixie) under granular `systemd` process supervision, atomic privilege boundaries via `aetherflow-runner.service`, automated UnionFS sandboxing (`af-systemd-sandbox`), and zero-touch configuration pipelines.

This document details the v3.2 ecosystem snapshot, the architecture of the 19 added bare-metal packages, the automated multi-unit and Zero-Touch Arr wiring mechanisms, the complete ruTorrent plugin modernization, and the long-term sovereign roadmap.

---

## 1. Current AetherFlow Ecosystem Snapshot (v3.2)

### 1.1 Internal Architecture

AetherFlow operates as a sovereign software platform defined by its decoupled, high-performance architecture:
*   **Frontend:** Built on Next.js 16 with the Obsidian V2 visual design system, rendering GPU-composited 120Hz cosmic aurora atmospheres, chromatic refraction glass panels, and a responsive tri-mode layout (desktop rail, tablet icon rail, mobile bottom dock).
*   **Backend Control Plane:** A Go 1.25 service layer (`aetherflow-api`) executing as an unprivileged system user (`aetherflow`) under `NoNewPrivileges=yes` and `ProtectSystem=strict`.
*   **Privileged Boundary (`aetherflow-runner`):** A dedicated, zero-sudo UNIX socket daemon (`/run/aetherflow/runner.sock`) that executes privileged operations (package script execution, systemd daemon reloads, Apache2 Certbot SAN / DNS configuration, and quota adjustments) without granting unrestricted root or `sudo` access to the API server.
*   **Reverse Proxy & Ingress:** Apache2 + embedded AetherFlow Subdomain Gateway orchestrating dynamic reverse proxy routes, automated Let's Encrypt SAN TLS certificates (`af-certbot-sync`), and LAN/WAN split ingress for all catalog services without containerized proxies.

### 1.2 Strict Zero-Docker Mandate

AetherFlow strictly rejects container runtimes:
*   **Portainer Purged:** The legacy `portainer` package (port `9443`) and its installer/uninstaller scripts have been permanently removed from `packages.json`, `package_automation.json`, `app_catalog.go`, and frontend service mappings.
*   **Zero Container Overheads:** No Docker daemon, `containerd`, Podman, or Compose files are installed or utilized. Services execute directly against Linux kernel primitives, dramatically reducing memory footprint, CPU overhead, and network bridging latency.
*   **Pure Native systemd:** Every service runs natively as a systemd unit or native web service (e.g., Apache2/PHP for ruTorrent), managed via standard systemd lifecycle states (`active`, `activating`, `deactivating`, `failed`).

### 1.3 55-Package Bare-Metal Catalog Breakdown

The catalog consists of exactly 55 bare-metal packages categorized across 7 core homelab domains:
1.  **Media & Streaming (14):** Plex, Jellyfin, Emby, Navidrome, Jellyseerr, Overseerr, Audiobookshelf, Kavita, Calibre-Web, Unpackerr, Autoscan, Recyclarr, Tautulli, Ombi.
2.  **Automation & Management (Arr Stack) (6):** Sonarr, Radarr, Lidarr, Readarr, Prowlarr, Bazarr.
3.  **Downloaders (6):** qBittorrent, SABnzbd, Deluge, Transmission, rTorrent, ruTorrent.
4.  **Cloud & Storage (7):** Nextcloud, Syncthing, File Browser, Rclone, MergerFS, Cloudplow, Paperless-ngx.
5.  **Network, DNS & IRC (10):** WireGuard, Tailscale, Pi-hole, AdGuard Home, Librespeed, The Lounge, ZNC, Fail2ban, Quassel, Shellinabox.
6.  **Monitoring & Diagnostics (7):** Grafana, Prometheus, Netdata, Uptime Kuma, Scrutiny, LFD, CSF.
7.  **Productivity & Workflow (5):** n8n, Vaultwarden, Gitea, Organizr, Jackett.

---

## 2. The 19 Added Bare-Metal Packages

Milestone 2 through Milestone 5 introduced 19 high-impact bare-metal packages, bringing the catalog from 36 base packages to 55 packages. Each package features clean-room native installer and uninstaller scripts, update tracking automation, and unified blueprint definitions:

| # | Package | Category | Default Port | Service / Companion Units | Native Implementation Architecture |
|---|---|---|---|---|---|
| 1 | **jellyseerr** | Media | 5055 | `jellyseerr.service` | Standalone Node.js native service; requests proxy for Jellyfin/Emby/Arr stack. |
| 2 | **adguardhome** | Network | 3080 | `adguardhome.service` | Upstream official Go binary with native DNS, DoH, DoT, and DNS-over-QUIC filtering. |
| 3 | **rtorrent** | Downloaders | 0 (SCGI) | `rtorrent.service` | Native C++ BitTorrent daemon with dual SCGI socket (`/run/rtorrent/rpc.sock`) and loopback port (`127.0.0.1:15000`). |
| 4 | **rutorrent** | Downloaders | 8087 | `apache2.service` | Web UI deployed at `/var/www/rutorrent` (with `/srv/rutorrent` symlink) communicating via SCGI bridge to rTorrent. |
| 5 | **rclone** | Cloud | 5572 | `rclone.service`, `rclone-vfs.service` | Upstream Go binary running `rclone rcd --rc-web-gui` plus companion `rclone-vfs` mount unit for `/mnt/remote`. |
| 6 | **mergerfs** | Cloud | 0 | `mergerfs.service` | High-performance FUSE union filesystem pooling `/mnt/local` and `/mnt/remote` into `/mnt/unionfs`. |
| 7 | **cloudplow** | Cloud | 0 | `cloudplow.service` | Automated cloud uploader running in isolated Python virtualenv (`/opt/cloudplow/.venv`) with blueprint dependencies on `rclone` and `mergerfs`. |
| 8 | **unpackerr** | Media | 0 | `unpackerr.service` | Upstream Go binary extracting downloaded media archives with Zero-Touch Arr discovery. |
| 9 | **autoscan** | Media | 3030 | `autoscan.service` | Upstream Go binary triggering atomic library scans across Plex/Jellyfin/Emby with Zero-Touch Arr discovery. |
| 10 | **recyclarr** | Media | 0 | `recyclarr.service`, `recyclarr.timer` | Native C# binary synchronizing TRaSH guides into Sonarr/Radarr via companion systemd timer and oneshot unit. |
| 11 | **audiobookshelf** | Media | 13378 | `audiobookshelf.service` | Upstream official bare-metal package for self-hosted audiobooks and podcasts with sqlite storage. |
| 12 | **kavita** | Media | 5002 | `kavita.service` | Native .NET binary server providing dedicated web reader for comics, manga, and ebooks. |
| 13 | **calibreweb** | Media | 8083 | `calibreweb.service` | Python application providing an intuitive web interface for browsing and reading Calibre e-book libraries. |
| 14 | **librespeed** | Network | 8988 | `librespeed.service` | Lightweight standalone Go binary (`speedtest-go`) providing local network speed benchmarking. |
| 15 | **thelounge** | Network | 9000 | `thelounge.service` | Modern self-hosted web IRC client running natively under Node.js with push notifications and rich embeds. |
| 16 | **znc** | Network | 6501 | `znc.service` | Upstream native IRC network bouncer supporting multi-network connections and SSL. |
| 17 | **scrutiny** | Monitoring | 8098 | `scrutiny.service`, `scrutiny-collector.timer` | Hard drive SMART health dashboard with companion periodic SMART collector timer. |
| 18 | **paperless-ngx** | Cloud | 8010 | `paperless-webserver.service`, `paperless-worker.service`, `paperless-scheduler.service` | Native bare-metal deployment utilizing `redis-server`, `tesseract-ocr`, Gunicorn webserver, Celery workers, and Beat scheduler. |
| 19 | **n8n** | Automation | 5678 | `n8n.service` | Native Node.js enterprise low-code workflow automation platform. |

---

## 3. Core Architectural Modernizations

### 3.1 Zero-Touch Arr API Key Auto-Discovery

AetherFlow v3.2 eliminates manual copy-pasting of API keys when configuring companion tools. The installer scripts for `unpackerr`, `autoscan`, and `recyclarr` execute automated local inspection:
*   When installed, each script scans `/var/lib/{sonarr,radarr,lidarr,readarr}/config.xml`.
*   The script parses `<ApiKey>` nodes directly via regex and streams verified tokens into target configuration files:
    *   `/etc/unpackerr/unpackerr.conf`: Configures active Sonarr/Radarr/Lidarr/Readarr integration sections.
    *   `/etc/autoscan/config.yml`: Auto-registers active Arr webhook triggers.
    *   `/var/lib/recyclarr/recyclarr.yml`: Populates base URLs and API keys for TRaSH quality profiles.
*   If an Arr application is not yet installed, safe placeholders are generated, allowing zero-friction operation once the application is added.

### 3.2 ruTorrent Plugin Architecture & Script Repair

Legacy ruTorrent plugin installers suffered from script fragility, artificial delay loops, and unhandled errors under strict shell settings. In v3.2:
*   **Unbound Variable Elimination:** All 52 `installplugin-*` and `removeplugin-*` scripts explicitly bind `rutorrent="${rutorrent:-/var/www/rutorrent/}"`, preventing fatal `rutorrent: unbound variable` aborts under `common.sh`'s `set -euo pipefail`.
*   **Zero Artificial Delays:** Stripped all legacy `sleep 5` loops (and typos like `sleep5`), saving 15 seconds per plugin installation and 10 seconds per plugin removal.
*   **Directory Safety & 3-Tier Fallback:**
    *   Guaranteed directory creation (`mkdir -p "${rutorrent}plugins"`).
    *   3-Tier asset acquisition: checks local plugin vault `/etc/AetherFlow/rtplugins/` first; checks existing destination; and cleanly falls back to upstream Git cloning if local archives are absent.
*   **Retired Script Purge:** Completely removed deprecated `autodl-irssi` plugin scripts (`installplugin-autodl-irssi`, `removeplugin-autodl-irssi`, `removeplugin-autodl`) and `packages/system/upgradeIRSSI`.

### 3.3 Storage Sandboxing & Systemd Isolation (`af-systemd-sandbox` & UnionFS)

To provide security without the virtualization penalty of containers, AetherFlow implements strict kernel sandboxing via systemd drop-in configurations:
*   **UnionFS (`/mnt/unionfs`):** All media, downloader, and cloud applications declare optional bind mounts `-/mnt/unionfs` in `sandbox_rw_paths`. The leading `-` ensures services start without error if union mounts are unmounted or absent.
*   **Hardware and FUSE Exemptions:** Privileged units requiring direct hardware access or FUSE kernel capabilities are exempted from restrictive sandbox drop-ins:
    *   `mergerfs.service` (requires `CAP_SYS_ADMIN` and `/dev/fuse`)
    *   `rclone-vfs.service` (requires `/dev/fuse` and mount permissions)
    *   `scrutiny-collector.service` (requires raw disk ioctl access for `smartctl`)
*   **Multi-Unit Service Resolution:** In `backend/services/service_manager.go`, `ResolveServiceUnits()` and `MatchesUnitFilter()` resolve companion services dynamically. Operations on `paperless-ngx` manage `paperless-webserver`, `paperless-worker`, and `paperless-scheduler` in unison; `scrutiny` manages both the web dashboard and `scrutiny-collector`; `recyclarr` manages both unit and timer; and `rclone` manages both `rclone.service` and `rclone-vfs.service`.

---

## 4. Strategic Road Ahead & Sovereign Bare-Metal Horizon

### 4.1 Resolution of Container-Centric Gaps

Previous roadmaps recommended Docker-heavy applications such as `Immich` and `Mailcow`. Under AetherFlow's strict Zero-Docker mandate, these have been strategically resolved:
1.  **Document Management:** Fully solved via bare-metal **Paperless-ngx** (native OCR, Redis caching, Gunicorn/Celery orchestration).
2.  **Workflow Automation:** Fully solved via native **n8n** (Node.js engine, webhook routing, Arr stack event integration).
3.  **Unified Ingress & SSL:** Fully solved via **Apache2 + AetherFlow Subdomain Gateway** (dynamic SQLite host routing, automated Let's Encrypt SAN expansion via `af-certbot-sync`, LAN split-horizon).
4.  **Network Mesh & VPN:** Fully solved via native **WireGuard** and **Tailscale** kernel integration.
5.  **Personal Photo Management:** Rather than introducing fragile Docker workarounds for Immich, AetherFlow prioritizes native bare-metal options (such as PhotoPrism or future native Go/Rust implementations) that execute directly against local filesystem trees with zero container overhead.

### 4.2 Quality Assurance & Verification Invariants

AetherFlow v3.2 maintains a zero-regression invariant verified by automated pipelines:
*   **Catalog Blueprint Integrity:** 100% of the 55 packages have corresponding non-nil blueprints, matching `default_port` mappings, and valid `shouldTrackPackage` update metadata.
*   **Script Parity:** Exactly 55 `installpackage-*` and 55 `removepackage-*` scripts exist, all passing `bash -n` syntax validation with zero Docker references.
*   **Zero Port Collisions:** Every port-bearing application possesses a unique listen port with zero collisions against core system ports (`80`, `443`, `8080`).
*   **Surgical Audit:** Zero `P0_CRITICAL` and zero `P1_HIGH` defects across the working tree via McSurgeon static pre-scan and multi-lens verification.
