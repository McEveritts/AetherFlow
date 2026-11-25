<div align="center">

<img src="./docs/assets/banner.svg?v=4.0.0" alt="AetherFlow — Sovereign bare-metal control plane" width="100%">

<br>

[![Latest Release](https://img.shields.io/github/v/release/McEveritts/AetherFlow?style=flat-square&logo=github&label=Stable&color=6366f1)](https://github.com/McEveritts/AetherFlow/releases/latest)
[![Nightly](https://img.shields.io/github/v/release/McEveritts/AetherFlow?include_prereleases&style=flat-square&logo=github&label=Nightly&color=8b5cf6)](https://github.com/McEveritts/AetherFlow/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/McEveritts/AetherFlow/ci.yml?branch=master&style=flat-square&logo=githubactions&logoColor=white&label=CI)](https://github.com/McEveritts/AetherFlow/actions/workflows/ci.yml)
[![Security Gate](https://img.shields.io/github/actions/workflow/status/McEveritts/AetherFlow/security.yml?branch=master&style=flat-square&logo=githubactions&logoColor=white&label=Security)](https://github.com/McEveritts/AetherFlow/actions/workflows/security.yml)
<br>
[![Rust](https://img.shields.io/badge/Control_Plane-Rust_·_Axum_+_Tokio-DEA584?style=flat-square&logo=rust&logoColor=white)](./backend-rs)
[![WebAssembly](https://img.shields.io/badge/Dashboard-Leptos_·_WebAssembly-654ff0?style=flat-square&logo=webassembly&logoColor=white)](./frontend-rs)
[![Catalog](https://img.shields.io/badge/Marketplace-77_native_apps-9333ea?style=flat-square)](./docs/marketplace.md)
[![OS](https://img.shields.io/badge/Debian_12%2F13_·_Ubuntu_22.04%2F24.04-A81D33?style=flat-square&logo=debian&logoColor=white)](./setup)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-10b981?style=flat-square)](./LICENSE.md)

**[Install](#-quick-install)** · **[What's new](#-whats-new-in-v400)** · **[Features](#-features)** · **[Peer Clustering](#-peer-clustering)** · **[Architecture](#-architecture)** · **[Catalog](#-77-app-native-catalog)** · **[Docs](./docs/README.md)** · **[Changelog](./CHANGELOG.md)**

</div>

---

**AetherFlow** turns a bare-metal Linux server into a self-hosted media and infrastructure appliance, with no containers. A memory-safe **Rust control plane** and a **Leptos WebAssembly dashboard** install, update, and supervise **77 native applications** directly through `systemd`. The same dashboard handles real-time hardware telemetry, a scoped file manager, streaming analytics, WireGuard and Tailscale networking, human-approved AI operations, and, new in v4.0.0, **peer clustering** across independent servers.

<div align="center">
  <picture><source media="(prefers-color-scheme: light)" srcset="./docs/assets/screenshots/light/overview.png?v=4.0.0"><img src="./docs/assets/screenshots/dark/overview.png?v=4.0.0" alt="AetherFlow Overview dashboard showing live CPU, GPU, memory, network, and storage telemetry" width="100%"></picture>
  <sub><i>Overview: live hardware telemetry, service health, and storage in one open-canvas view. Screenshots follow your GitHub theme (dark or light); 1440p, fixture data.</i></sub>
</div>

---

## ✨ What's new in v4.0.0

v4.0.0 is the largest release in AetherFlow's history. It promotes **373 commits** from `nightly` to the stable `master` track ([`v3.2.7...v4.0.0`](https://github.com/McEveritts/AetherFlow/compare/v3.2.7...v4.0.0)).

<img src="./docs/assets/v4-by-the-numbers.svg?v=4.0.0" alt="AetherFlow v4.0.0 by the numbers" width="100%">

| | Since v3.2.7 |
| :--- | :--- |
| 🦀 **All-Rust control plane** | The Go backend is gone. A **12-crate** Rust workspace (`backend-rs`) built on Axum and Tokio ships `aetherflow-api`, the privileged runner, the `af` admin CLI, the native LibreSpeed backend, and the new `af-transcode` worker. **Zero Go, zero Redis, zero Node.js** in the control plane. |
| 🕸️ **WebAssembly dashboard** | The Next.js UI has been replaced by a **4-crate Leptos/WASM** application (`frontend-rs`) with dedicated Web Workers, 16 dashboard tabs, and the obsidian "open canvas" design language, served as external `web/dist` assets. |
| ⬡ **Peer Clustering** | Pair independent AetherFlow servers over a dedicated WireGuard mesh, grant scoped remote access, manage a peer from your own dashboard, share media folders over NFSv4.2, and offload Jellyfin transcoding to a paired worker. |
| 📂 **Native McBrowser** | Capability-scoped (`openat2`) per-user file manager with resumable 64 GiB uploads, conflict-aware editing, archives, previews, and public shares. |
| 🔐 **Supply-chain & sandboxing** | Sigstore/SLSA v1 provenance verification for every release artifact, a zero-sudo privileged runner socket, hardened `systemd` sandboxes, OIDC provider with PKCE and device flow, and DNS-pinned SSRF guards. |
| ♻️ **Atomic self-update** | Isolated transient `systemd` update units with WAL-safe snapshots, readiness checks, durable receipts, and automatic rollback on `stable` and `nightly` channels. |

Full notes: **[v4.0.0 release notes](./docs/releases/v4.0.0.md)** · **[CHANGELOG](./CHANGELOG.md)** · **[Upgrading from v3.2.x](./docs/upgrading.md)**

> [!IMPORTANT]
> **Upgrading a v3.2.x node?** Database Migration 26 removes the legacy master/worker cluster (`CLUSTER_*` settings and `/api/v1/admin/cluster/*` routes). Take a WAL-safe backup first with `sudo af backup create`, then re-pair servers from the **Cluster** tab after the upgrade. See [Upgrading & Rollbacks](./docs/upgrading.md).

---

## 🧭 Features

<table>
<tr>
<td width="50%" valign="top">

<img src="./docs/assets/feature-icons/rust-core.svg" width="28" align="left">&nbsp;**Rust control plane**<br>
`aetherflow-api` runs unprivileged as the `aetherflow` user under `ProtectSystem=strict`. Bundled SQLite in WAL mode, AES-256-GCM secret encryption (`enc:v1:`), JWT + TOTP + OIDC auth, and zero-fork `/proc` and NVML GPU telemetry.

</td>
<td width="50%" valign="top">

<img src="./docs/assets/feature-icons/marketplace.svg" width="28" align="left">&nbsp;**77-app native Marketplace**<br>
One-click bare-metal installs, in-place updates with certified version receipts, live install progress, automatic `<app>.<baseDomain>` ingress, and `*Arr` API-key discovery, all serialized behind a single package lock.

</td>
</tr>
<tr>
<td valign="top">

<img src="./docs/assets/feature-icons/cluster.svg" width="28" align="left">&nbsp;**Peer Clustering**<br>
Six-digit verified pairing over the `afpeer0` WireGuard tunnel, zero access by default with eight scoped grant areas, remote management, NFSv4.2 storage federation, and distributed Jellyfin transcoding.

</td>
<td valign="top">

<img src="./docs/assets/feature-icons/mcbrowser.svg" width="28" align="left">&nbsp;**McBrowser & File Share**<br>
Per-user `0700` roots confined with `openat2`, storage quotas, resumable TUS uploads up to 64 GiB, a 45-mode code editor with Markdown/MathML preview, 9 archive formats, and password-protected shares.

</td>
</tr>
<tr>
<td valign="top">

<img src="./docs/assets/feature-icons/streaming.svg" width="28" align="left">&nbsp;**Streaming intelligence**<br>
Live Jellyfin, Plex, and Emby sessions, canonical playback history with server-identity verification, Plex/Tautulli import, distribution charts, and CSV/JSON portability.

</td>
<td valign="top">

<img src="./docs/assets/feature-icons/flowai.svg" width="28" align="left">&nbsp;**Human-gated FlowAI**<br>
Diagnostics with Gemini, Claude, OpenAI, Ollama, or LM Studio, grounded in live telemetry. Every proposed service action waits in the **Approval Inbox** until an administrator approves it.

</td>
</tr>
<tr>
<td valign="top">

<img src="./docs/assets/feature-icons/network-vpn.svg" width="28" align="left">&nbsp;**Networking & ingress**<br>
WireGuard peers with one-time QR handoff, Tailscale routes and exit nodes, Apache2 auto-subdomain ingress, Let's Encrypt SAN sync (`af-certbot-sync`), and `.aether.local` split-horizon DNS.

</td>
<td valign="top">

<img src="./docs/assets/feature-icons/security.svg" width="28" align="left">&nbsp;**Defense in depth**<br>
Root operations go only through the allowlisted `/run/aetherflow/runner.sock` IPC. Route-scoped CSP, CSRF, DNS-rebinding-pinned outbound requests, an admin audit log, and Sigstore-verified releases.

</td>
</tr>
<tr>
<td valign="top">

<img src="./docs/assets/feature-icons/cli.svg" width="28" align="left">&nbsp;**`af` admin CLI**<br>
Packages, services, quotas, sandbox drop-ins, releases, verified backups and staged restores, host maintenance, DNS sync, `af cluster diagnose`, and the resumable `af provision` foundation.

</td>
<td valign="top">

<img src="./docs/assets/feature-icons/plugins.svg" width="28" align="left">&nbsp;**Plugins SDK**<br>
Manifest-discovered plugins run in isolated `DynamicUser=yes` transient units with scoped JWTs and proxied ports (`21000–21999`). Start from the [Rust plugin template](./plugins/sdk-template-rust/README.md).

</td>
</tr>
</table>

### Platform tour

| **Marketplace** | **Cluster** |
| :---: | :---: |
| <picture><source media="(prefers-color-scheme: light)" srcset="./docs/assets/screenshots/light/marketplace.png?v=4.0.0"><img src="./docs/assets/screenshots/dark/marketplace.png?v=4.0.0" alt="AetherMarketplace catalog of 77 native applications"></picture> | <picture><source media="(prefers-color-scheme: light)" srcset="./docs/assets/screenshots/light/cluster.png?v=4.0.0"><img src="./docs/assets/screenshots/dark/cluster.png?v=4.0.0" alt="Cluster tab showing paired peers, link health, and grants"></picture> |
| 77 native apps in 9 categories with live install progress and certified updates. | Paired servers, link health, protocol compatibility, RTT, grants, and transcode workers. |
| **Streaming** | **McBrowser** |
| <picture><source media="(prefers-color-scheme: light)" srcset="./docs/assets/screenshots/light/streaming.png?v=4.0.0"><img src="./docs/assets/screenshots/dark/streaming.png?v=4.0.0" alt="Streaming analytics with live sessions and playback history"></picture> | <picture><source media="(prefers-color-scheme: light)" srcset="./docs/assets/screenshots/light/mcbrowser.png?v=4.0.0"><img src="./docs/assets/screenshots/dark/mcbrowser.png?v=4.0.0" alt="McBrowser scoped file manager"></picture> |
| Live sessions, playback history, filters, and distribution charts. | Scoped per-user files, previews, uploads, editing, and shares. |
| **FlowAI** | **Network** |
| <picture><source media="(prefers-color-scheme: light)" srcset="./docs/assets/screenshots/light/flowai.png?v=4.0.0"><img src="./docs/assets/screenshots/dark/flowai.png?v=4.0.0" alt="FlowAI assistant grounded in live telemetry"></picture> | <picture><source media="(prefers-color-scheme: light)" srcset="./docs/assets/screenshots/light/network.png?v=4.0.0"><img src="./docs/assets/screenshots/dark/network.png?v=4.0.0" alt="Network tab with WireGuard, Tailscale, and ingress"></picture> |
| Multi-provider diagnostics with the human-approval gate. | WireGuard, Tailscale, interfaces, and external access. |

<details>
<summary><b>All 16 tabs: Approval Inbox, Services, File Share, MediaFlow, Users, Audit Trail, Settings, Security, Notifications, Quotas</b></summary>
<br>

| **Approval Inbox** | **Services** |
| :---: | :---: |
| <picture><source media="(prefers-color-scheme: light)" srcset="./docs/assets/screenshots/light/inbox.png?v=4.0.0"><img src="./docs/assets/screenshots/dark/inbox.png?v=4.0.0" alt="Approval Inbox tab"></picture> | <picture><source media="(prefers-color-scheme: light)" srcset="./docs/assets/screenshots/light/services.png?v=4.0.0"><img src="./docs/assets/screenshots/dark/services.png?v=4.0.0" alt="Services tab"></picture> |
| Pending FlowAI and self-heal actions awaiting an administrator decision. | `systemd` status, logs, restart receipts, and update checks. |
| **File Share** | **MediaFlow** |
| <picture><source media="(prefers-color-scheme: light)" srcset="./docs/assets/screenshots/light/fileshare.png?v=4.0.0"><img src="./docs/assets/screenshots/dark/fileshare.png?v=4.0.0" alt="File Share tab"></picture> | <picture><source media="(prefers-color-scheme: light)" srcset="./docs/assets/screenshots/light/mediaflow.png?v=4.0.0"><img src="./docs/assets/screenshots/dark/mediaflow.png?v=4.0.0" alt="MediaFlow tab"></picture> |
| Managed share links, uploads, expiry, and download tracking. | Automated media scan and approval queue. |
| **Users** | **Audit Trail** |
| <picture><source media="(prefers-color-scheme: light)" srcset="./docs/assets/screenshots/light/users.png?v=4.0.0"><img src="./docs/assets/screenshots/dark/users.png?v=4.0.0" alt="Users tab"></picture> | <picture><source media="(prefers-color-scheme: light)" srcset="./docs/assets/screenshots/light/audit.png?v=4.0.0"><img src="./docs/assets/screenshots/dark/audit.png?v=4.0.0" alt="Audit Trail tab"></picture> |
| Accounts, roles, quotas, and streaming user links. | Immutable operator, FlowAI, cluster, and auth events with export. |
| **Settings** | **Security & 2FA** |
| <picture><source media="(prefers-color-scheme: light)" srcset="./docs/assets/screenshots/light/settings.png?v=4.0.0"><img src="./docs/assets/screenshots/dark/settings.png?v=4.0.0" alt="Settings tab"></picture> | <picture><source media="(prefers-color-scheme: light)" srcset="./docs/assets/screenshots/light/security.png?v=4.0.0"><img src="./docs/assets/screenshots/dark/security.png?v=4.0.0" alt="Security & 2FA tab"></picture> |
| Localization, base domain, interface preferences, and AI configuration. | TOTP, password, storage quota, and session-family revocation. |
| **Notifications** | **Quotas** |
| <picture><source media="(prefers-color-scheme: light)" srcset="./docs/assets/screenshots/light/notifications.png?v=4.0.0"><img src="./docs/assets/screenshots/dark/notifications.png?v=4.0.0" alt="Notifications tab"></picture> | <picture><source media="(prefers-color-scheme: light)" srcset="./docs/assets/screenshots/light/quotas.png?v=4.0.0"><img src="./docs/assets/screenshots/dark/quotas.png?v=4.0.0" alt="Quotas tab"></picture> |
| Inbox, rules, and delivery channels. | Per-user storage quotas backed by Linux `setquota`. |

</details>

---

## ⬡ Peer Clustering

Peer clustering links **independent** AetherFlow servers. There is no master node: each server stays sovereign and grants its peers exactly the access it chooses.

<img src="./docs/assets/peer-clustering.svg?v=4.0.0" alt="Peer clustering topology: servers paired over the afpeer0 WireGuard mesh with grants, NFS storage federation, and Jellyfin transcode offload" width="100%">

- **Verified pairing.** A single-use pairing string plus matching six-digit codes on both dashboards establishes a dedicated `afpeer0` WireGuard tunnel. Pairing requests are DNS-pinned and SSRF-guarded.
- **Zero access by default.** Grant `None`, `Read-only`, or `Read and write` per area (`services`, `marketplace`, `settings`, `files`, `users`, `network`, `updates`, `transcoding`). Revoking a grant cancels active peer streams within a second.
- **Remote management.** Switch the whole dashboard to a linked peer and operate it within the granted scopes.
- **Storage federation.** Share media folders between peers over NFSv4.2, restricted to the tunnel, with health gating and media-app safeguards.
- **Distributed transcoding.** The `af-transcode` shim sends Jellyfin `ffmpeg` jobs to `af-transcode-worker.service` on a paired GPU host.
- **Diagnostics.** `af cluster diagnose <link>` inspects handshake, grants, exports, mounts, the transcode worker, and the audit trail.

Requirements: Debian 13 on both servers, direct reachability between WireGuard endpoints, and Jellyfin 12.4 for transcode offload. Peer clustering does not provide HA or failover. → **[Peer clustering guide](./docs/peer-clustering.md)** · **[Design spec](./docs/designs/peer-clustering.md)**

---

## 🏗️ Architecture

<img src="./docs/assets/architecture.svg?v=4.0.0" alt="AetherFlow architecture: Leptos WASM SPA, Apache2 ingress, unprivileged aetherflow-api, runner socket, privileged aetherflow-runner, systemd and native apps, peer mesh" width="100%">

The unprivileged API never touches root directly. Every privileged action, including package installs, `systemctl` transitions, WireGuard and Tailscale changes, quotas, plugin units, and self-updates, goes through a strict allowlist on `/run/aetherflow/runner.sock` and is executed by `aetherflow-runner.service`.

<details>
<summary><b>12-crate Rust control plane (<code>backend-rs</code>)</b></summary>
<br>

| Crate | Role |
| :--- | :--- |
| **`af-api`** | Axum HTTP/WebSocket control plane: auth (JWT/TOTP/OIDC/CSRF), WASM asset serving, McBrowser routes, plugins, subdomain proxy, FlowAI, streaming history, and peer clustering endpoints. |
| **`af-runner`** | Root Unix-socket daemon (`aetherflow-api runner`) with allowlisted `systemctl`, locked Bash installers plus 9 opt-in declarative Rust recipes, WireGuard/Tailscale and `afpeer0` peer-storage (NFS) helpers, `DynamicUser` plugin units, and the self-update launcher. |
| **`af-services`** | Marketplace catalog and update watcher, config mutators, the `af-heal` watchdog, and the MediaFlow queue worker. |
| **`af-db`** | Bundled SQLite WAL with a single writer and pooled readers, migrations, session and JWT revocation, and AES-256-GCM secret encryption. |
| **`af-files`** | Capability-scoped `openat2` filesystem confinement for McBrowser. |
| **`af-release`** | Atomic release engine (deploy, rollback, cleanup) with SHA-256 + Sigstore/SLSA verification and crash recovery. |
| **`af-host`** | Versioned backup manifests, WAL-consistent snapshots, staged restore, and host maintenance (`tune`, `sentinel`, `clean-logs`, `showspace`). |
| **`af-cli`** | The `af` administrative CLI and the `af provision` foundation. |
| **`af-hardware`** | Zero-fork `sysinfo` / `/proc` telemetry and dynamic NVML FFI for NVIDIA GPUs. |
| **`af-librespeed`** | Native Rust `speedtest-backend` (replaces upstream Go `speedtest-go`). |
| **`af-transcode`** | Jellyfin `ffmpeg` shim and remote transcode worker for peer clustering. |
| **`af-models`** | Shared `serde` wire contracts, catalog schemas, and runner IPC payloads. |

</details>

<details>
<summary><b>4-crate Leptos WebAssembly dashboard (<code>frontend-rs</code>)</b></summary>
<br>

| Crate | Role |
| :--- | :--- |
| **`af-web-core`** | API and WebSocket client policies, locale catalogs, draft persistence, shared algorithms. |
| **`af-web-worker`** | Dedicated Web Worker modules for search, sorting, hashing, and chunked uploads. |
| **`af-web-ui`** | Accessible Leptos controls, tables, code editor, charts, and topology views. |
| **`af-web-app`** | Application shell, auth and public routes, and the 16 dashboard tabs: Overview, Approval Inbox, Services, Marketplace, McBrowser, File Share, Streaming, MediaFlow, FlowAI, Network, Cluster, Users, Audit Trail, Settings, Notifications, and Quotas. |

</details>

---

## 📦 77-App Native Catalog

Every app installs natively, with no Docker, and is supervised by `systemd`. Marketplace groups them into 9 categories; the full lifecycle contract is in [AetherMarketplace](./docs/marketplace.md).

| Domain | Applications |
| :--- | :--- |
| **Media, IPTV & YouTube (23)** | Plex, Jellyfin, Emby, Dispatcharr, Threadfin, Navidrome, Jellyseerr (Seerr), Overseerr, Maintainerr, Requestrr, Audiobookshelf, Kavita, Calibre-Web, FileBot, Unmanic, Unpackerr, Autoscan, Recyclarr, Tautulli, Ombi, FlareSolverr, Piped *(exp.)*, Invidious *(exp.)* |
| **Arr automation (8)** | Sonarr, Radarr, Lidarr, Readarr *(retired upstream)*, Listenarr, Prowlarr, Bazarr, Jackett |
| **Download clients (12)** | qBittorrent, Qui, Autobrr, Flood, SeedCross, pyLoad, rTorrent, ruTorrent, SABnzbd, NZBGet, Deluge, Transmission |
| **Cloud & storage (8)** | Nextcloud, Syncthing, File Browser, Duplicati, Rclone, MergerFS, Cloudplow, Paperless-ngx |
| **Network, DNS & VPN (8)** | WireGuard, Tailscale, Pi-hole, AdGuard Home, LibreSpeed, The Lounge, ZNC, Quassel |
| **Monitoring & security (7)** | Grafana, Prometheus, Netdata, Uptime Kuma, Scrutiny, Vaultwarden, Fail2ban |
| **Productivity, remote desktop & DevOps (11)** | Palate, n8n, Home Assistant, Gitea, Organizr, Notifiarr, McVNC, KasmVNC, XRDP, noVNC, X2Go |

---

## 🚀 Quick Install

On a clean **Debian 12/13** or **Ubuntu 22.04/24.04 LTS** server:

```bash
sudo apt-get update && sudo apt-get -y upgrade
sudo apt-get -y install git curl
sudo git clone https://github.com/McEveritts/AetherFlow.git /opt/AetherFlow
cd /opt/AetherFlow/setup
sudo bash AetherFlow-Setup
```

Setup prints the onboarding URL (also recorded in `/root/information.info`) and writes the bootstrap token to `/var/lib/aetherflow/.setup-bootstrap-token`. Open the URL to create the first administrator, then install apps from **Marketplace**.

<details>
<summary><b>Unattended provisioning & repair</b></summary>

```bash
# Unattended bootstrap: --username creates the Linux owner account. The onboarding URL and
# bootstrap token path are recorded in /root/information.info. The first web admin is created
# via web onboarding unless AETHERFLOW_WEB_ADMIN_PASSWORD is set.
sudo bash /opt/AetherFlow/setup/AetherFlow-Setup \
  --unattended \
  --username admin \
  --domain node.example.com

# Repair specific step(s) on an existing install while preserving configuration and database
# (--list-steps shows step IDs, e.g. build_modern for the control plane)
sudo bash /opt/AetherFlow/setup/AetherFlow-Setup --repair build_modern
```

Use `setup/AetherFlow-Setup` for first-time host provisioning (APT, Apache2, TLS, initial admin). Use `af provision` for repeatable Rust-native foundation steps and day-2 administration. See the [`af` CLI reference](./docs/rust-admin-cli.md).

</details>

**Already running AetherFlow?** Switch channels and update in place from **Settings → System Updates**, or follow [Upgrading & Rollbacks](./docs/upgrading.md) and [Self-Update Lifecycle](./docs/self-update.md). The updater swaps the API binaries and the matching `web/dist` dashboard together and rolls back automatically if readiness checks fail.

---

## 📚 Documentation

The full index lives in **[docs/README.md](./docs/README.md)**. Start here:

| Getting started | Operating | Subsystems |
| :--- | :--- | :--- |
| [About AetherFlow](./docs/about.md) | [Operations Runbook](./docs/RUNBOOK.md) | [Peer Clustering](./docs/peer-clustering.md) |
| [Quickstart](./docs/quickstart.md) | [Configuration](./docs/configuration.md) | [AetherMarketplace](./docs/marketplace.md) |
| [Architecture](./docs/architecture.md) | [Upgrading & Rollbacks](./docs/upgrading.md) | [McBrowser](./docs/mcbrowser.md) |
| [Deployment Checklist](./docs/deployment_checklist.md) | [Self-Update](./docs/self-update.md) | [Streaming History](./docs/streaming-history-contract.md) |
| [Troubleshooting & FAQ](./docs/troubleshooting.md) | [`af` CLI](./docs/rust-admin-cli.md) | [FlowAI](./docs/flowai.md) |
| [Security & Hardening](./docs/security.md) | [Threat Model](./docs/threat_model.md) | [WireGuard & Tailscale](./docs/network-vpn.md) |
| [REST & WebSocket API](./docs/API.md) | [Testing & Verification](./docs/testing.md) | [Plugins SDK](./plugins/README.md) |

---

## 🛠️ Development

```bash
# Rust control plane: unit and contract tests across all 12 crates
JWT_SECRET="$(openssl rand -hex 32)" \
AES_MASTER_KEY="$(openssl rand -base64 32)" \
ALLOWED_HOSTS="localhost,127.0.0.1" \
AETHERFLOW_DISABLE_BACKGROUND_WORKERS=1 \
cargo test --manifest-path backend-rs/Cargo.toml --workspace --locked -- --test-threads=1

# WASM dashboard and workers
cargo test --manifest-path frontend-rs/Cargo.toml --workspace --locked
bash scripts/install_wasm_build_tools.sh --ensure
bash scripts/build_wasm_frontend.sh --stage

# Release manager, marketplace, and build-tool regression suites
AETHERFLOW_SKIP_ENV_FILES=1 python3 tests/run_parallel_tests.py

# Shell hygiene across installer, setup, and lifecycle scripts
python3 tests/check_shell_hygiene.py

# Package the API, CLI, speedtest-backend, web/dist, and SHA256SUMS
bash scripts/build_gold.sh
```

Browser suites (Playwright against the real WASM bundle) are covered in [e2e/tests/e2e/README.md](./e2e/tests/e2e/README.md). To regenerate the README screenshots, see [scripts/docs/README.md](./scripts/docs/README.md).

### Release channels

| Channel | Branch | Cadence |
| :--- | :--- | :--- |
| **`stable`** | `master` | Promoted releases (`vX.Y.Z`), currently **v4.0.0** |
| **`nightly`** | `nightly` | Continuous prereleases (`v4.0.0-nightly.<run>.<attempt>`) with patch notes in [CHANGELOG.md](./CHANGELOG.md) |

Every release artifact ships with `SHA256SUMS` and Sigstore bundles, and the updater verifies both before it switches binaries.

---

## 📜 License & Security

- **License:** [GNU General Public License v3.0](./LICENSE.md)
- **Security policy:** see [SECURITY.md](./SECURITY.md) for supported release tracks and private vulnerability disclosure.
- **History:** [CHANGELOG.md](./CHANGELOG.md) · [Releases](https://github.com/McEveritts/AetherFlow/releases)

<div align="center">
<sub>Built with 🦀 Rust and 🕸️ WebAssembly for people who own their hardware.</sub>
</div>
