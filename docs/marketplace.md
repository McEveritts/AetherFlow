# AetherMarketplace

The AetherMarketplace is your portal to extending the capabilities of your bare-metal infrastructure. It features a curated catalog of **77 native Linux applications** tailored for media streaming, `*Arr` automation, downloaders, mesh VPNs, observability, remote desktops, and culinary AI.

## Key Features

- **One-Click Deploy & In-Place Updates**: Automated installation, update checking, and configuration backed by 15 native declarative Rust recipes (`af-runner`) and idempotent `common.sh` installers.
- **Hyperspeed Feedback**: Real-time `[PROGRESS:<pct>]` installation telemetry streamed over WebSockets to circular progress indicators in the UI.
- **Native Orchestration**: Every app runs as a native `systemd` service (`af-<app>.service`) with optional `af-systemd-sandbox` isolation and automatic `<app>.<baseDomain>` subdomain routing.
- **Safe Uninstallation & Rollbacks**: Transactional rollback journals and removal scripts that preserve application data by default unless `DELETE_DATA=true` is explicitly requested.

---

## Managed Application Library (77 Packages)

AetherFlow manages 77 native services across multiple infrastructure domains.

### Media & Downloaders
- **Video & IPTV**: Plex, Jellyfin, Emby, Dispatcharr, Threadfin, Tautulli, Overseerr, Jellyseerr, Maintainerr, Requestrr, FileBot, Unmanic.
- **Experimental YouTube Frontends**: Piped and Invidious. See [native installation requirements and limitations](experimental-youtube.md).
- **Automation (The Arrs)**: Sonarr, Radarr, Lidarr, Readarr, Listenarr, Bazarr, Prowlarr, Notifiarr.
- **Downloaders**: qBittorrent, Qui, Autobrr, Flood, SeedCross, pyLoad, Deluge, Transmission, Sabnzbd, NZBGet, rTorrent, ruTorrent.

### System & Utilities
- **Observability**: Netdata, Grafana, Prometheus, Uptime Kuma, Scrutiny.
- **File & Backup Management**: Nextcloud, FileBrowser, Syncthing, Duplicati, Rclone, MergerFS, Cloudplow, Paperless-ngx.
- **Security & Network**: Vaultwarden, Fail2Ban, WireGuard, Tailscale, Pi-hole, AdGuard Home, The Lounge, ZNC, Quassel.
- **Core & Remote Desktop**: Gitea, Home Assistant, n8n, Organizr, noVNC, KasmVNC, McVNC, XRDP, X2Go.
- **Recipes & Nutrition**: Palate, with meal planning, nutrition tracking, and Sage AI.

> [!NOTE]
> The availability of certain applications depends on your host OS and architecture. AetherFlow performs a compatibility check before allowing an installation.

---

## Operating Marketplace Apps

### Palate

- **Palate** ([McEveritts/Palate](https://github.com/McEveritts/Palate)) builds the latest stable release tag with a private, checksum-verified Node.js 22 runtime and runs as `af-palate.service`. It listens on `127.0.0.1:28014`, or AetherFlow's allocated port, behind the AetherFlow gateway.
- **Login requires Jellyfin.** Install and configure Jellyfin first, or point `JELLYFIN_INTERNAL_URL` in `/etc/palate/palate.env` at an existing server. The default is `http://jellyfin.aether.local`. Set `NEXT_PUBLIC_JELLYFIN_PUBLIC_URL` to the Jellyfin URL users can open, and `NEXTAUTH_URL` to the exact Palate URL they will use. The installer defaults to `https://palate.<base-domain>` when a base domain is configured, otherwise `http://palate.aether.local`. Use HTTPS for camera/PWA features.
- The installer creates the native PostgreSQL database/role `af_palate`, preserves recipes and nutrition caches in `/var/lib/palate/vault`, and generates separate session, encryption, rate limit, and curation secrets in `/etc/palate/palate.env`. Keep this file with your backups: its encryption secret is needed to read stored API keys. Set a Gemini key in Palate's Settings to use Sage; `GEMINI_API_KEY` and `USDA_API_KEY` in the environment file are optional system integrations.
- After changing environment settings, rerun the installer to rebuild client-side settings and restart the service. Upgrades back up the database, vault, and environment to `/var/backups/aetherflow-palate.*` before applying Prisma's schema without accepting data loss. Review any rejected schema change before proceeding.
- Removal preserves the database, vault, secrets, and service account. `DELETE_DATA=true` explicitly removes Palate's database/role and data; the shared PostgreSQL service and existing backups remain installed.

### Maintainerr

- **Maintainerr** ([maintainerr.info](https://maintainerr.info/), [source](https://github.com/Maintainerr/Maintainerr)) finds unwatched or unwanted media using rule-based collections for Plex, Jellyfin, and Emby. Configure your media server and optional Sonarr, Radarr, Seerr, and Tautulli integrations in Maintainerr after installation; AetherFlow does not require or automatically install a particular media server.
- Builds the latest stable release natively with a private, checksum-verified Node.js 26 runtime and the release's bundled Yarn 4 under a dedicated unprivileged build identity (`af-maintainerr-build`) with an isolated build-local workspace. Runs as the unprivileged `maintainerr` user under `af-maintainerr.service`, on `127.0.0.1:6246` or AetherFlow's allocated port, behind the AetherFlow gateway. No containers or host Node.js replacement are needed.
- SQLite, integration credentials, rules, logs, and uploaded assets persist in `/var/lib/maintainerr`. Updates build before stopping the service, back up the application, service unit, and data to `/var/backups/aetherflow-maintainerr.*`, and restore the previous installation if activation or database readiness fails. The readiness endpoint is `/api/health/ready`.
- Uninstall removes the service and application bundle but retains the service account and data by default. `DELETE_DATA=true` explicitly removes the account and `/var/lib/maintainerr`; existing upgrade backups remain available for recovery.
- **Review cleanup rules carefully:** Maintainerr can delete media through connected services. Installing it does not configure integrations or enable cleanup rules on your behalf.

### Mesh VPN & Subnet Routing
- **Tailscale** installs the official upstream `tailscale` package and `tailscaled.service` daemon from `pkgs.tailscale.com` (verified via `/etc/apt/keyrings/tailscale-archive-keyring.gpg`) and enables IPv4/IPv6 packet forwarding (`/etc/sysctl.d/99-tailscale.conf`). Authenticate the node from **Network → Tailscale Mesh → Connect / Login** (or supply `AF_TAILSCALE_AUTHKEY` / `TAILSCALE_AUTHKEY` during installation). The Network page manages mesh peers, subnet routes, exit-node preferences and service diagnostics. See [Network VPN management](network-vpn.md).

### Remote Desktop Access
- **KasmVNC** installs an XFCE desktop under the dedicated `af-kasmvnc` service account. Open it through the AetherFlow gateway with username `admin`; retrieve its generated password with `sudo cat /etc/kasmvnc/aetherflow-password`. The backend listens only on `127.0.0.1:6081` (or AetherFlow's allocated fallback port), with TLS terminated at the gateway. Use HTTPS for remote access; do not expose the unencrypted backend port. Without a gateway, use an SSH tunnel to the loopback port. Display `:20` is reserved for this desktop. Existing KasmVNC credentials survive reinstall/update.
- KasmVNC uses upstream Debian/Ubuntu `.deb` releases on `amd64` and `arm64`, verifies the release asset's SHA-256 digest, and fails when no matching OS release asset exists. APT is not allowed to remove conflicting packages automatically (including other VNC servers); resolve any conflict explicitly before installing.
- **McVNC** (`McEveritts/McVNC`) compiles and runs the Rust headless GPU remote desktop under the `af-mcvnc` service account (`video` and `render` groups) with zero-copy EGL/GLES2 GBM `dma-buf` compositing, an embedded Wayland compositor (`WAYLAND_DISPLAY=wayland-mcvnc-0`), VA-API `EncSlice` H.264 / `EncPicture` JPEG on Intel & AMD, and NVENC on NVIDIA. The dashboard listens on `127.0.0.1:6900` (or AetherFlow's allocated fallback port) and stores fleet pairing state in `/var/lib/mcvnc/.local/share/mcvnc/fleet.json`.
- **XRDP** uses the distribution's `xrdp` and `xrdp-sesman` services with `xorgxrdp` and XFCE. Connect using an RDP client to TCP **3389**, or your existing custom port, with an existing non-root Linux account and its Linux password, not the AetherFlow web login. XRDP has no browser interface, HTTP gateway route, or automatic HTTP port allocation. Restrict RDP access to a trusted network or VPN; the installer does not open firewall ports or change Linux account passwords.
- Removal preserves desktop data/configuration unless `DELETE_DATA=true` is supplied. XRDP removal restores the original session startup script; neither package removes shared XFCE dependencies or Linux users/home directories.

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

### Reinstalling and Removing an App
Use **Reinstall** on an installed application to reapply its installer in place. The confirmation describes retaining configuration, data, secrets, and the allocated port. Installers can restart the application during this operation.

**Uninstall** opens a confirmation and keeps application data by default. Reinstall settings are archived separately from active ingress routes so a later install can reuse the port and domain without retaining a gateway route to the removed app.

To request destructive removal, select **Permanently delete application data and configuration** and type the application's identifier. Only this confirmed purge sends `purge=true` and `DELETE_DATA=true` to the remover. Existing backups can remain; the application-specific remover defines which managed data and accounts it can remove. A failed stop blocks destructive teardown unless the service is positively confirmed inactive or absent. Required teardown failures prevent a successful completion receipt; partial removal can still require administrator inspection.

Dispatcharr uses dedicated, ownership-marked storage at `/var/lib/dispatcharr` and an exclusive `/data` compatibility link. An existing real/shared `/data` directory or nonempty unmarked legacy storage requires an audited manual migration before install or update. AetherFlow refuses to adopt that storage automatically; purge also refuses ambiguous ownership and retains the data and credentials. Ordinary uninstall retains Dispatcharr storage and its compatibility path.

Lifecycle responses include a server job ID. Completion messages require a matching terminal receipt. A failed update does not imply that rollback or database recovery succeeded. An API restart alone does not prove that its installer stopped: a surviving command keeps maintenance reserved until it exits. Once recovery can prove that the owner and its commands are gone, an unfinished job becomes **interrupted**; check application state and authorized logs before retrying. Unknown owner or command state remains unresolved rather than being reported as success.

The Rust API and runner keep a durable reservation for the package and its complete catalog service set across pre-stop, script execution, and required ingress persistence/service restoration. Apps that share a companion, such as Apache, cannot run conflicting orchestration at the same time. Direct Rust CLI package requests use the runner to acquire and finish their own durable job; the CLI confirms completion only from its matching durable terminal receipt. An installer progress line or a lost connection alone cannot confirm success. An admitted runner job continues its required callbacks if that CLI disconnects. Service controls and sandbox application honor these reservations; only the exact owning job can perform its callbacks. Core API/runner restarts and system releases cannot interrupt an active lifecycle. Service mutations also share the global maintenance lock with application jobs and releases. Unrelated service cards can remain visible and enabled, but start/stop/restart returns a retryable `409 LIFECYCLE_BUSY` while maintenance holds that lock. Retry once the active operation completes.

After a crash, standalone `af release ... --local` can reconcile a known abandoned API job without starting the API. Reconciliation requires a released UUID owner lease and exclusive maintenance admission; surviving installer subprocesses retain the maintenance lock. It records **interrupted**, never successful recovery. Missing/unknown owner evidence stays unresolved. Do not delete the persistent `*.lifecycle-owners` lease directory or release recovery journal to clear a busy message: those files protect restored database snapshots and real work. Inspect the reported owner/maintenance conflict and application state before retrying.

System-update receipts distinguish **launching** from **running**. A live launcher retains admission before systemd creates its unit; an abandoned launcher is reconciled against systemd, and unknown systemd state returns an actionable unavailable response rather than false completion. Deferred core restarts have their own durable receipt covering the timer delay and restart worker. Their successful receipt confirms the restart command and active unit, not HTTP/UDS application readiness. Use the normal health checks before treating the application as ready.

---

## System Integration

When you install an app through AetherMarketplace:
1. **User Creation**: A dedicated system user (e.g., `af-plex`) is often created.
2. **Service Unit**: A systemd file is generated at `/etc/systemd/system/af-<appname>.service`.
3. **Log Rotation**: Logs are automatically handled by `journald`.

> [!TIP]
> You can manually control any marketplace app from the CLI using standard commands: `sudo systemctl restart af-plex`.
> Prefer runner-mediated `af` controls while AetherFlow manages lifecycle work; raw administrator `systemctl` commands bypass its admission safeguards.
