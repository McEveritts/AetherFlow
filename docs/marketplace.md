# AetherMarketplace

AetherMarketplace manages a catalog of **77 native Linux applications** for media streaming, `*Arr` automation, downloaders, mesh VPNs, observability, remote desktops, and culinary AI.

## Key Features

- **Install & Update**: `af-runner` executes each package's Bash installer by default. Nine packages also support the [opt-in Rust package engine](./v4-native-packages.md) when `AETHERFLOW_ENABLE_RUST_PACKAGES=1` is set in `/etc/aetherflow/aetherflow.env` or an `aetherflow-runner.service` drop-in (`systemctl edit aetherflow-runner`) and `aetherflow-runner.service` is restarted.
- **Live Progress Feedback**: `[PROGRESS:<pct>]` installation telemetry rendered in horizontal `<progress max="100">` bars and the **Deployment Status** drawer via 2-second HTTP polling of `/api/v1/auth/packages/{id}/progress`, while WebSocket `package:progress` events trigger catalog status refreshes.
- **Native Orchestration**: Packages use their upstream systemd units, AetherFlow-managed units, or shared services such as Apache2. HTTP-capable applications can route through the AetherFlow Subdomain Gateway.
- **Data-Preserving Uninstall & Rollback Support**: Removal scripts retain application data by default unless explicit purge (`?purge=true` / `--purge`, setting `DELETE_DATA=true`) is requested. The 9 opt-in declarative Rust recipes use `RollbackJournal`, and supported Bash installers stage pre-cutover backups (note that APT maintainer scripts are not automatically reversible).

---

## Managed Application Library (77 Packages)

AetherFlow manages the following packages. The [catalog](../config/packages.json) supplies package IDs, service names, default ports, and web paths. The [automation metadata](../config/package_automation.json) supplies update sources, sandbox profiles, and managed units.

| Marketplace category | Applications |
| :--- | :--- |
| Media | Plex Media Server, Jellyfin, Emby, Sonarr, Radarr, Lidarr, Readarr (retired upstream), Prowlarr, Bazarr, Overseerr, Ombi, Maintainerr, Tautulli, Jackett, FlareSolverr, Navidrome, Threadfin, Jellyseerr (Seerr), Unpackerr, Autoscan, Recyclarr, Audiobookshelf, Kavita, Calibre-Web, Dispatcharr, FileBot, Listenarr, Requestrr, Unmanic, Piped, Invidious |
| Downloaders | qBittorrent, Deluge, Transmission, SABnzbd, NZBGet, Flood, Autobrr, Qui, rTorrent, ruTorrent, pyLoad, SeedCross |
| Cloud | Nextcloud, Syncthing, File Browser, Rclone, MergerFS, Cloudplow, Paperless-ngx, Duplicati |
| Network | WireGuard, Tailscale, Pi-hole, AdGuard Home, LibreSpeed, The Lounge, ZNC, Quassel |
| Security | Fail2ban, Vaultwarden |
| Monitoring | Grafana, Prometheus, Netdata, Uptime Kuma, Scrutiny |
| Automation | Home Assistant, n8n |
| Utilities | Palate, Organizr, Notifiarr, noVNC, KasmVNC, McVNC, XRDP, X2Go |
| DevOps | Gitea |

Piped and Invidious are experimental and have [additional installation requirements](./experimental-youtube.md).

> [!NOTE]
> Package availability depends on host OS and CPU architecture (for example, Listenarr requires Linux `amd64`). AetherFlow checks host compatibility and port availability before starting an installation.

---

## Operating Marketplace Apps

### ruTorrent and rTorrent

- ruTorrent requires a working rTorrent SCGI backend. For a fresh installation, start Marketplace rTorrent with its default `127.0.0.1:15000` endpoint, or have an existing backend ready at the endpoint configured for ruTorrent.
- Install, update, and reinstall check Apache and issue a read-only rTorrent version request as `www-data` using ruTorrent's PHP configuration and the first login in `/etc/apache2/AetherFlow/rutorrent.htpasswd` (created on first install by `installpackage-rutorrent` using the host's initial provisioning credentials stored encrypted in `/var/lib/aetherflow/.master.creds` / SQLite `system_config.master_credentials`, distinct from the skipped legacy `/etc/htpasswd` Digest file; set or rotate ruTorrent logins anytime with `sudo htpasswd -B /etc/apache2/AetherFlow/rutorrent.htpasswd <user>`). Set the endpoint in `/var/www/rutorrent/conf` so both CLI and web processes can read it. If the SCGI check fails, verify that `www-data` can connect to the host/port or Unix socket; the job rolls back and records the error in the deployment log (`/var/log/aetherflow/install-rutorrent.log`, visible in **System Logs**).
- Removing Marketplace rTorrent stops `rtorrent.service` and retains its configuration and session data unless explicit purge is requested. Any ruTorrent instance configured to use this service needs another working SCGI endpoint to remain usable.

### Palate

- **Palate** ([McEveritts/Palate](https://github.com/McEveritts/Palate)) builds the latest stable release tag with a private, checksum-verified Node.js 22 runtime and runs as `af-palate.service`. It listens on `127.0.0.1:28014` (or AetherFlow's allocated fallback port — inspect active ports in **Services** or via `PORT=` in `/etc/palate/palate.env`; `sudo af package info palate` shows static catalog metadata only) behind the AetherFlow Subdomain Gateway.
- **Login requires Jellyfin.** Install and configure Jellyfin first, or point `JELLYFIN_INTERNAL_URL` in `/etc/palate/palate.env` at an existing server (default `http://jellyfin.aether.local`). Set `NEXT_PUBLIC_JELLYFIN_PUBLIC_URL` to the Jellyfin URL users open and `NEXTAUTH_URL` to the exact Palate URL they use. When SQLite `app_ingress_configs` has external access enabled (`external_access_enabled=1`, toggled per app in **Network → Automatic subdomain ingress & TLS** [checkbox **Enable external access**, also linked from Marketplace's **External access** button] and off by default) for `palate`, the installer defaults `NEXTAUTH_URL` to `https://palate.<baseDomain>` (or `http://` if TLS is disabled, or the configured custom domain); otherwise it falls back to `http://palate.aether.local` when `aether.local` is configured on the host, or `http://127.0.0.1:<app_port>`. Use HTTPS for camera/PWA features.
- The installer creates the native PostgreSQL database and role `af_palate`, preserves recipes and nutrition caches in `/var/lib/palate/vault`, and generates separate session, encryption, rate-limit, and curation secrets in `/etc/palate/palate.env`. Back up this file: its encryption secret is required to decrypt stored API keys. Set a Gemini API key in Palate's Settings to enable Palate's built-in Sage culinary AI assistant; `GEMINI_API_KEY` and `USDA_API_KEY` in `/etc/palate/palate.env` are optional system integrations.
- After changing environment settings, reinstall Palate to rebuild client-side settings and restart the service. Upgrades temporarily back up the database, vault, and environment to `/var/backups/aetherflow-palate.*` before applying Prisma schema migrations without accepting data loss, retaining `/var/backups/aetherflow-palate.*` on any post-backup failure (even when rollback succeeds) and deleting the temporary backup directory only after successful activation. If a Prisma migration is rejected due to potential data loss, inspect `/var/log/aetherflow/install-palate.log`, back up `af_palate`, and resolve the schema change manually before retrying.
- Ordinary uninstall preserves the database, vault, secrets, and service account. Explicit purge (`DELETE_DATA=true`) removes Palate's database/role, `/var/lib/palate`, `/etc/palate`, the `af-palate` service account, and `/var/backups/aetherflow-palate*` backups while leaving the shared PostgreSQL service installed.

### Maintainerr

- **Maintainerr** ([maintainerr.info](https://maintainerr.info/), [source](https://github.com/Maintainerr/Maintainerr)) manages rule-based media cleanup collections for Plex, Jellyfin, and Emby. Configure your media server and optional Sonarr, Radarr, Jellyseerr (Seerr), and Tautulli integrations inside Maintainerr after installation; AetherFlow does not automatically configure integrations or enable cleanup rules.
- Builds the latest stable release natively with a private, checksum-verified Node.js 26 runtime and bundled Yarn 4 under an unprivileged build user (`af-maintainerr-build`) in an isolated workspace. Runs as `maintainerr` under `af-maintainerr.service` on `127.0.0.1:6246` (or AetherFlow's allocated fallback port) behind the AetherFlow Subdomain Gateway.
- SQLite data, credentials, rules, logs, and uploads persist in `/var/lib/maintainerr`. Updates build before stopping the service, back up the application, service unit, and data to `/var/backups/aetherflow-maintainerr.*`, verify `/api/health/ready`, attempt automatic rollback on activation failure, and retain the current plus one prior successful backup.
- Ordinary uninstall removes the service and application bundle while retaining the service account, `/var/lib/maintainerr`, and upgrade backups. Explicit purge (`DELETE_DATA=true`) removes the service account, `/var/lib/maintainerr`, and `/var/backups/aetherflow-maintainerr*` backups.
- **Review cleanup rules carefully:** Maintainerr can delete media through connected services.

### Listenarr

- **Listenarr** ([Listenarrs/Listenarr](https://github.com/Listenarrs/Listenarr)) tracks official GitHub prereleases (`update_channel: "prerelease"`, scoped strictly to Listenarr) because upstream currently publishes prereleases only and has zero stable releases. If upstream publishes a stable release in the future, standard SemVer precedence prefers it over a same-version prerelease.
- **Linux x64 (`amd64`) only:** upstream currently provides `linux-x64.zip` archives only and zero Linux ARM64 assets. On ARM64 or other non-x64 hosts, install, update discovery, and dispatch fail early with an actionable architecture error before making host changes.
- Every standard or pinned-version install/update verifies the selected tag's official `Listenarrs/Listenarr` asset URL and SHA-256 digest before extracting the self-contained `Listenarr.Api` executable (pin an update via `sudo af package update listenarr --target-version <ver>`, or its shorthand `sudo af update listenarr --target-version <ver>`, which passes `target_version` in the runner request; for a pinned fresh install, run `sudo env AF_TARGET_VERSION=<ver> bash /opt/AetherFlow/current/packages/package/install/installpackage-listenarr` directly as root because `af package install` does not accept `--target-version` and does not forward caller shell env vars over `runner.sock`). Installed versions are read from `/opt/Listenarr/.af-version` without executing the server binary.
- Listenarr stores its runtime database, `appsettings.json`, and keys under `/var/lib/listenarr/config`, mounted onto the real directory `/opt/Listenarr/config` via systemd `BindPaths=/var/lib/listenarr/config:/opt/Listenarr/config` (not a symlink, because Listenarr >= v1.10.6 rejects symlinks outside its content root). Updates and reinstalls preserve configured port, bind address, and custom service `Environment=` lines and safely migrate legacy `/opt/Listenarr/config` directories with rollback protection. Ordinary uninstall retains `/var/lib/listenarr`; explicit `DELETE_DATA=true` purges it.

### Dispatcharr

- Dispatcharr stores application state in dedicated, ownership-marked storage at `/var/lib/dispatcharr` (identified by `/var/lib/dispatcharr/.aetherflow-data-owner`, `root:root` mode `0600`, containing `aetherflow-dispatcharr-data-v1:/var/lib/dispatcharr`) and wires `/data` exclusively to that store. If the host already has a real or shared `/data` directory or unmarked legacy storage, AetherFlow refuses automatic adoption during install or update — back up and move the existing directory aside, let the installer initialize `/var/lib/dispatcharr` and its ownership marker, and then copy your data into `/var/lib/dispatcharr`.
- Ordinary uninstall retains `/var/lib/dispatcharr` and its `/data` compatibility path; explicit purge refuses ambiguous unmarked ownership and retains the data and credentials.

### Autoscan

- Autoscan's **Open App** link opens its health endpoint. Configure media targets and webhook senders (such as Sonarr or Radarr Connect) after installation.
- Optional mount-anchor files (regular files checked by Autoscan to verify storage mounts before scanning) must be regular files. If a retained host configuration specifies a custom port, either reuse that port during reinstall or update the configuration before assigning a different port.

### Mesh VPN & Subnet Routing

- **Tailscale** installs the official upstream `tailscale` package and `tailscaled.service` daemon from `pkgs.tailscale.com` (verified via `/etc/apt/keyrings/tailscale-archive-keyring.gpg`) and enables IPv4/IPv6 packet forwarding (`/etc/sysctl.d/99-tailscale.conf`). After installing via Marketplace UI or `sudo af package install tailscale`, authenticate from **Network → Tailscale Mesh VPN → Up / Interactive login** or run `sudo tailscale login --auth-key=file:<0600-key-file>`. (`AF_TAILSCALE_AUTHKEY` / `TAILSCALE_AUTHKEY` is honored only when invoking `/opt/AetherFlow/current/packages/package/install/installpackage-tailscale` directly as root via `sudo env` or when set in `aetherflow-runner.service`'s environment; `af package install` sends JSON over `/run/aetherflow/runner.sock` without forwarding caller shell env vars.) See [Network: WireGuard & Tailscale](./network-vpn.md).

### Remote Desktop Access

- **KasmVNC** installs an XFCE desktop under the dedicated `af-kasmvnc` service account. Open it through the AetherFlow Subdomain Gateway with username `admin` and retrieve its generated password with `sudo cat /etc/kasmvnc/aetherflow-password`. The backend serves HTTPS on `127.0.0.1:6081` (or the allocated fallback port), and `/usr/local/bin/af-kasmvnc-start` dynamically claims the first unused X display in `:20`..`:59`. For direct access from another machine, use an SSH tunnel and a client that trusts the KasmVNC certificate. Existing KasmVNC credentials survive reinstall and updates.
- KasmVNC uses upstream Debian/Ubuntu `.deb` releases on `amd64` and `arm64`, verifies SHA-256 digests, and fails when no matching OS release asset exists. APT is not permitted to remove conflicting packages automatically; resolve conflicts explicitly before installing.
- **McVNC** (`McEveritts/McVNC`) compiles and runs the Rust headless GPU remote desktop under `af-mcvnc` (`video` and `render` groups) with EGL/GLES2 GBM `dma-buf` compositing, an embedded Wayland compositor (`WAYLAND_DISPLAY=wayland-mcvnc-0`), VA-API on Intel/AMD, and NVENC on NVIDIA. The dashboard listens on `127.0.0.1:6900` (or the allocated fallback port) and stores paired-client metadata in `/var/lib/mcvnc/.local/share/mcvnc/fleet.json`.
- **XRDP** uses the distribution's `xrdp` and `xrdp-sesman` services with `xorgxrdp` and XFCE. Connect with an RDP client on TCP **3389** (or your custom port) using an existing non-root Linux account and its Linux password, not the AetherFlow web login. XRDP has no browser interface, HTTP gateway route, or automatic HTTP port allocation. Restrict RDP access to a trusted network or VPN.
- **Removal & Purge**: Ordinary removal (`DELETE_DATA=false`) preserves desktop configuration and data, and XRDP restores its original `/etc/xrdp/startwm.sh` via `rollback_file`. Explicit purge (`DELETE_DATA=true`) never removes shared XFCE packages or interactive Linux user accounts/home directories:
  - **XRDP**: purges `xrdp`/`xorgxrdp` and deletes `/etc/xrdp` and `/var/lib/xrdp`.
  - **KasmVNC**: purges `kasmvncserver`, deletes `/var/lib/kasmvnc` and `/etc/kasmvnc`, and removes its dedicated `af-kasmvnc` service account.
  - **McVNC**: deletes `/var/lib/mcvnc` and `/etc/mcvnc` and removes its dedicated `af-mcvnc` service account.

---

## Installing, Updating & Removing Apps

### Installing an App

1. Sign in as an administrator and open **Marketplace** (or run `sudo af package install <pkg>`).
2. Select the application and click **Install**. The UI immediately dispatches `POST /api/v1/admin/packages/{id}/install` with automatic server-side port allocation (no port/configuration form modal is shown; if the default port is already taken, AetherFlow automatically assigns an available fallback port and records it in `app_ingress_configs` and the **Services** view; custom port overrides can be supplied via `sudo af package install <pkg> --port <port>`).

### Monitoring Progress

The **Deployment Status** drawer renders live progress bars and logs by polling `/api/v1/auth/packages/{id}/progress` every 2 seconds until terminal receipt completion. If an operation fails, inspect the deployment drawer or **System Logs** (`/var/log/aetherflow/install-<app>.log` or `remove-<app>.log`) before retrying.

### Reinstalling and Removing an App

- **Reinstall** (**Repair** in the UI): Reapplies the installer in place while retaining application data, configuration, secrets, and the allocated port (restarting the service during cutover).
- **Ordinary Uninstall (Data-Preserving Default)**: Opens a confirmation dialog and keeps application data and configuration by default. Reinstall settings are archived separately from active ingress routes so a later reinstall can reuse the port and domain without leaving a stale route active.
- **Destructive Purge**: In the UI, check **Permanently purge application data (?purge=true)** and type the exact package ID to confirm (`POST /api/v1/admin/packages/{id}/uninstall?purge=true`), or run `sudo af package remove <pkg> --purge`. Only confirmed purges pass `DELETE_DATA=true` to the remover. If a service fails to stop and cannot be confirmed inactive, destructive teardown aborts fail-closed so running processes are not deleted underneath active files.

### Concurrency Locks, Busy Responses, and Recovery

AetherFlow serializes package installations, service mutations, and platform self-updates using coordinated locks in `aetherflow-runner.service` (see [Rust Package Executor](./rust-package-executor.md) and [Self-Update Lifecycle](./self-update.md)):

- **Job Receipts & Failure Semantics**: Every package request creates a server job ID and durable receipt. A lost UI or CLI connection does not cancel an admitted runner job, and an update failure does not automatically guarantee that rollback or database recovery succeeded — verify application state and `/var/log/aetherflow/install-<app>.log` before retrying.
- **Exclusive Reservations & HTTP `409` Contention Codes**: Active package operations reserve the package's catalog units (including shared services such as `apache2`) and hold the global maintenance lock alongside `af-release` self-updates. Concurrent conflicting requests return HTTP `409` with a surface-specific error code (`CONFLICT` for a duplicate in-progress package mutation, `LIFECYCLE_ADMISSION_UNAVAILABLE` on admission lock contention, `PACKAGE_LIFECYCLE_IN_PROGRESS` for service control targeting an actively mutating package, `SYSTEM_UPDATE_IN_PROGRESS` during an active or pending-recovery `af-release` self-update, and `LIFECYCLE_BUSY` when `aetherflow-runner` rejects service control due to maintenance-lock contention); wait for the active job to finish and retry.
- **Crash & Interrupted-Job Recovery**: An `aetherflow-api` restart does not kill a running installer in `aetherflow-runner`; the maintenance lock remains held until the subprocess exits. After an unexpected crash, check active jobs and release state with `sudo af release status` and `sudo systemctl status aetherflow-runner aetherflow-api`. If a self-update stopped after swapping `/opt/AetherFlow/current`, recover with `sudo af release rollback --local` (`--channel` is optional on rollback). Never manually delete lock directories, lease files, or `/opt/AetherFlow/releases/.recovery_state.json` to clear a busy error.
- **Deferred Core Restarts**: Restarting `aetherflow-api` or `aetherflow-runner` through the UI queues a deferred restart worker with its own durable receipt confirming the unit restart; verify `/health/ready` before assuming full API readiness.

---

## System Integration

- **API & Port Allocation**: Marketplace install, reinstall, update, and uninstall call the [package API](./API.md). The API allocates or reuses the application port, dispatches the job to `aetherflow-runner.service`, and exposes install/remove logs in **System Logs**.
- **Single-Sign-On Launch Tickets**: Clicking **Open App** opens the app's configured address. On a managed public HTTPS route for the 9 apps without built-in authentication routed through the Rust gateway (**Autoscan**, **FlareSolverr**, **Jackett**, **McVNC**, **Netdata**, **Prometheus**, **Scrutiny**, **Threadfin**, and **Unmanic**), an administrator's dashboard session authorizes a one-time launch ticket exchanged on the app host for a host-scoped session cookie (revoked automatically when the dashboard session signs out or is revoked). Non-admin users do not receive gateway launch tickets for these administrative apps. **ruTorrent** enforces `/etc/apache2/AetherFlow/rutorrent.htpasswd` on its local Apache vhost (`sites-available/rutorrent.conf`) and bypasses the Rust gateway on managed external subdomain ingress (`aetherflow-ext-rutorrent.conf`), where `af-runner` also enforces `/etc/apache2/AetherFlow/htpasswd` (`AuthMerging And`, failing closed if absent/empty; see [Security & Hardening](./security.md)).
- **First-Launch Setup Caution**: Per-app external HTTPS access is **off by default** (`external_access_enabled=0`) even after `baseDomain` is configured. If an application prompts you to create an admin account on first launch, reach its loopback listener first via an SSH tunnel (`ssh -L <port>:127.0.0.1:<port> <host>`) or `http://<app>.aether.local` (when host-local/LAN DNS is synced via `af hosts`; see [Unified Rust Admin CLI](./rust-admin-cli.md)) to complete initial setup, then enable external HTTPS for that app in **Network → Automatic subdomain ingress & TLS** (checkbox **Enable external access**, or via Marketplace's **External access** button).
- **CLI Service Control**: Use the catalog's exact service name with `af service` (for example `sudo af service status plexmediaserver` or `sudo af service status jellyfin`; see [Unified Rust Admin CLI](./rust-admin-cli.md)). Packages that share `apache2` (such as Nextcloud and ruTorrent) share the impact of reloading or restarting `apache2`.
