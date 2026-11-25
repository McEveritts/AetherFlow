# AetherFlow Peer Clustering

*   **Author:** Donovan Everitt
*   **Status:** Implemented locally across Phases P0–P9 (`f20a3a99`) plus pre-release hardening Bundles A–D on branch `feat/peer-clustering`. Local build, test, lint, supply-chain, and standalone regression gates pass on Server A; two-server live acceptance is pending Server B provisioning.
*   **Supersedes:** Earlier pre-implementation drafts (`five-phase plan`, `concepts_brief.md`, and `peer_clustering_plan.md`). Original 52 entry IDs are preserved as `[Entry N]` traceability tags across phases.
*   **Date:** 2026-11-22 (updated 2026-11-25 to align with post-hardening Bundles A–D on `feat/peer-clustering`)
*   **Code baselines:** Original line anchors were drafted at `origin/nightly` `702ae0d2` (97 commits ahead of `master` `32f324e1`). Implementation started at `origin/nightly` `447e04fe`, completed P0–P9 at `f20a3a99`, and applied pre-release hardening Bundles A–D on `feat/peer-clustering`. See [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md) for the frozen `702ae0d2 → 447e04fe` citation audit, complete per-phase repository file manifests, and integration log.
*   **Target environment:** Debian 13 (`trixie`) on both servers, with Jellyfin **12.4** (`12.4+deb13`) and matching `jellyfin-ffmpeg` packages (`jellyfin-ffmpeg8` `8.1.3-1-trixie` on Server A). Jellyfin dropped the `10.` prefix after 10.11, so 12.x succeeds 10.11.

--------------------------------------------------------------------------------

## Overview

Peer Clustering lets multiple servers, each running a full copy of AetherFlow, manage each other from the **Cluster** page (`/?tab=cluster`).

Two servers **pair** with each other over an AetherFlow-managed **WireGuard tunnel** (`afpeer0`). Over that encrypted link:

*   A server holding a **grant** manages the other server through that server's own existing API. Grants set `none`, `read-only`, or `read-write` access per area, independently in each direction (one-way or two-way).
*   Media folders are shared via **NFSv4.2 inside the tunnel** with sentinel health gating.
*   Jellyfin transcodes offload to paired GPU workers with matching `jellyfin-ffmpeg` packages through a **Rust-native transcode dispatcher** (`af-transcode`).

Peer Clustering replaces the legacy single-master clustering (`backend-rs/crates/af-services/src/cluster_daemon/` and `cluster_*` tables), which Phase P4 and Migration 26 delete permanently.

### Terminology and system context

*(Route notation: This specification uses OpenAPI `{param}` syntax in prose; the backend pins `axum = "0.7"` and registers routes with `:param` / `*rest` syntax in Rust.)*

| Term / Component | Definition |
| :--- | :--- |
| **`af-api`** (`aetherflow-api.service`) | Unprivileged Rust HTTP/WebSocket control plane serving `/api/v1/*`, backed by single-writer WAL SQLite (`af-db`). See [docs/architecture.md](../architecture.md) and [docs/API.md](../API.md#8-peer-clustering). |
| **`af-runner`** (`aetherflow-runner.service`) | Root-privileged helper daemon receiving validated JSON IPC over `/run/aetherflow/runner.sock` for WireGuard, systemd units/sandboxes, NFS, and apt operations. |
| **`af-cli`** (`af`) | Rust administrative CLI (`backend-rs/crates/af-cli`) providing host/backup/sandbox/cluster operations (including `af sandbox apply <pkg>` and `af cluster diagnose <link>`). See [docs/rust-admin-cli.md](../rust-admin-cli.md). |
| **`af-release` & `scripts/build_gold.sh`** | AetherFlow's release verification crate (`backend-rs/crates/af-release`) and release-tarball build script staging control-plane and companion binaries (`aetherflow-api`, `bin/af`, `bin/speedtest-backend`, `bin/af-transcode`). |
| **`af-web-core` / `af-web-app`** | Rust/WASM frontend workspaces built with Trunk (`frontend-rs/`). `af-web-core` holds Leptos-free HTTP/WS transport (`ApiClient`, `api_url`); `af-web-app` renders the reactive dashboard UI. |
| **Marketplace & apt serialization** | AetherFlow's curated app catalog (`config/package_automation.json`), executing `apt-get` installs/updates under a shared package lifecycle mutex (`reconcile_package_jobs`) and writing package receipts for installed apps. Peer infrastructure package installs reuse apt serialization without creating Marketplace app receipts. |
| **Systemd sandboxing** | AetherFlow hardens managed app units via `10-aetherflow-sandbox.conf` drop-ins (`af-runner/src/sandbox_ops.rs`) driven by `config/package_automation.json` (`sandbox_rw_paths`, where a leading `-` marks an optional path ignored if absent; the `dotnet` profile applies `ProtectSystem=strict` with allowlisted `ReadWritePaths`). `is_exempt_sandbox_unit` excludes host-infrastructure units from app sandboxing; `sudo af sandbox apply <pkg>` regenerates a package's drop-in and reloads systemd. |
| **Reverse proxy, Apache vhosts, & app-launch / plugin tokens** | External HTTPS ingress terminates at host Apache virtual hosts (`app_launch.rs` / `app_subdomain_proxy_middleware` proxy managed third-party app UIs using per-host `__Host-` session cookies minted via **app-launch minting**); `PUBLIC_URL` provides the server's trusted HTTPS origin. **Plugin tokens** are local single-server bearer tokens scoped by plugin manifests (`plugins/manifest.rs`) that cannot access admin routes. |
| **`McBrowser` & `tus`** | AetherFlow's built-in file manager (`af-files`, `tabs/mcbrowser/`) supporting resumable `tus` HTTP uploads with root-relative `Location` headers. |
| **`FileShare`** | Managed file-share module (`tabs/fileshare/`) providing authenticated and public anonymous share links. |
| **`Plugin Sandbox`** | Local-only plugin iframe host (`tabs/marketplace/sandbox.rs`) that is never proxied across peers and closes automatically on server switch. |
| **`MediaFlow`** | Automated media scan and approval queue (`tabs/mediaflow.rs`, `intelligence/scan_cursor.rs`). |
| **`Streaming settings`** | Local Plex, Jellyfin, and Emby server URLs and encrypted API keys stored in SQLite (`streaming_servers`). |
| **`AF_ALLOWED_FS_ROOTS`** | Comma-separated root directories permitted for filesystem browsing and peer NFS exports; when unset or empty, `fs_browser::get_allowed_fs_roots` defaults to `/mnt,/media,/srv,/data,/home` plus `env::temp_dir()` and `env::current_dir()` (unless canonicalized under `/opt/AetherFlow` or `/var/lib/aetherflow`; see [docs/configuration.md](../configuration.md#storage--native-mcbrowser-af-files)). |
| **`AreaFence`** | Per-server, per-area UI busy/mutation guard (`af-web-app/src/tabs/busy.rs`) preventing cross-server action races when switching servers. |
| **Filtered telemetry** | Peer WebSocket `/api/v1/auth/ws` filtering (`ws/telemetry.rs:396-431`) restricting broadcast frames and service diagnostics to areas permitted by the peer's active read grant. |
| **`TrackedRouter`** | Axum `Router` wrapper (`af-api/src/routes/inventory.rs`) recording every registered production `(method, path)` template so CI tests fail if any route lacks a `peers::scopes` classification rule. |
| **Receiving vs. Initiating server** | During pairing, the **receiving server** opens a 10-minute pairing window and approves the six-digit comparison code; the **initiating server** pastes the pairing string and sends the initial HTTPS request. |
| **Inbound vs. Outbound grant** | From a server's perspective, an **inbound grant** (`peer_grants`) defines access this server grants *to* a peer; an **outbound grant** (`peer_received_grants`) records access the peer grants *to* this server. |

## The Problem

Prior to Peer Clustering (pre-P4), AetherFlow could manage only the server it ran on. Its legacy clustering subsystem was a single-master fleet monitor:

*   One fixed role per node (`CLUSTER_MODE=standalone|master|worker`).
*   5-second heartbeats over manually provisioned TLS certificates.
*   A polling command queue limited to start, stop, restart, reload, and ping.

That architecture could not manage another server's settings, Marketplace apps, files, or users; could not stream media between servers or offload transcoding; and had no two-way management.

Multi-server deployments (such as two datacenter hosts on 1 Gbps+ links or a shared private VLAN) require unified management from a single dashboard without building per-tab remote APIs. The solution is peer links with scoped grants, a generic HTTP/WebSocket management proxy, NFSv4.2 media sharing, and Rust-native Jellyfin transcode offload inside one AetherFlow-managed WireGuard tunnel.

## Goals

*   Pair two AetherFlow servers from `/?tab=cluster` by pasting a single-use pairing string and confirming a matching six-digit fingerprint, without manual certificates or env-file edits under default tunnel settings (subnet/port overrides use `/etc/aetherflow/aetherflow.env` before first pairing).
*   Support independent one-way or two-way grants setting **none / read-only / read-write** across eight areas (`services`, `marketplace`, `settings`, `files`, `users`, `network`, `updates`, `transcoding`), with two presets (**Read-only (everything)** and **Read and write (everything)**).
*   Allow a server holding a read-write grant to operate all supported remote dashboard views through the target's existing API without per-tab remote-control code, while keeping authentication, session management, pairing, grant administration, local-operator profile/header avatars, and the Plugin Sandbox local.
*   Enforce fail-closed authorization: a read-only grant never allows state mutations on the target, and unclassified routes return `403 PEER_ROUTE_UNCLASSIFIED`.
*   Share media folders over NFSv4.2 inside the tunnel (read-only by default) so link loss stops mounts and removes empty leaf mountpoints rather than exposing empty library roots to media apps.
*   Offload Jellyfin transcodes to eligible paired workers with matching `jellyfin-ffmpeg` versions and encoders, falling back locally before remote dispatch begins and letting Jellyfin retry locally on mid-job stream loss without duplicate encodes.
*   Allow either side to revoke a link or grant, immediately rejecting credentials locally and canceling active management WebSockets, in-flight non-WebSocket HTTP proxy streams (`<< 1 s`), and active remote transcode jobs (`Signal(Kill)`), with full link revocation also tearing down transcode mounts/exports, peer media NFS mounts/exports, credentials, and owned WireGuard peers.
*   Audit every proxied peer action on the target server with the link, run-as account, origin operator, and request ID (propagated into `PeerError` bodies, Cluster UI banners, and `aetherflow-runner` logs).
*   Keep each server independently operable when peers are unreachable.
*   Implement all new AetherFlow code in Rust.

## Non-Goals

*   High availability, automatic failover, moving services between servers, or general app scheduling. Distributed Jellyfin transcoding is the only cross-server compute in scope.
*   Desired-state configuration management, where one server declares another's configuration.
*   Proxying third-party app UIs (Sonarr, Plex, etc.) through the link; those open directly on the peer's own host URL.
*   NAT traversal and relays; both servers must be directly reachable on their chosen WireGuard endpoints.
*   Multi-server topology maps and combined aggregate dashboards.
*   Remote transcoding for Plex or Emby.
*   In-band WireGuard key rotation (keys rotate by re-pairing).
*   Migrating legacy `cluster_nodes` enrollments (deleted permanently by Migration 26).

## Environment Facts (Debian 13 + Jellyfin 12.4)

Both servers target Jellyfin 12.4 with matching installed `jellyfin` and `jellyfin-ffmpeg` apt versions. Rows below reflect observed Server A Debian 13.7 facts; live two-server Jellyfin 12.4 missing-root scan retention and remote stop-sequence timing remain pending Server B acceptance (see [Open Questions](#open-questions) and [Deferred two-server acceptance](#deferred-two-server-acceptance)).

| Topic | Fact | Design consequence |
| :--- | :--- | :--- |
| **Jellyfin ffmpeg path** | Since 10.9, the ffmpeg path in Jellyfin's dashboard is read-only, and 12.x keeps it that way. Jellyfin reads its ffmpeg path from `JELLYFIN_FFMPEG` or `--ffmpeg`. | `af-runner` writes `/etc/systemd/system/jellyfin.service.d/20-aetherflow-transcode.conf` (separate from `10-aetherflow-sandbox.conf`, `af-runner/src/sandbox_ops.rs`), loading `EnvironmentFile=-/etc/aetherflow/transcode.env` and setting `Environment=JELLYFIN_FFMPEG=/usr/lib/aetherflow/transcode/ffmpeg` without editing `encoding.xml` or the sandbox drop-in. |
| **Jellyfin stop sequence** | Jellyfin stops a transcode by writing `q` to `ffmpeg`'s stdin; on timeout it sends `SIGKILL` to the process tree. | Stdin is relayed (handling `q`). Because `SIGKILL` cannot be caught by the shim, the dispatcher detects the shim Unix socket closing without `Exit` and sends `Signal(Kill)` to the worker; the worker also kills its `ffmpeg` process group on unexpected stream close. |
| **Jellyfin temp folder** | Jellyfin 10.10+ writes auxiliary `ffmpeg` files under `TMPDIR`, which workers must share. | The same drop-in sets `Environment=TMPDIR=/var/cache/jellyfin/af-tmp`, exported alongside the transcode directory. |
| **Jellyfin paths under AetherFlow** | Marketplace installs Jellyfin from apt (`config/package_automation.json:20-40`). Data/config live under `/var/lib/jellyfin` (`/var/lib/jellyfin/config`, `af-runner/src/app_metadata/extractors_media.rs:270-297`), cache under `/var/cache/jellyfin`, and real `ffmpeg` at `/usr/lib/jellyfin-ffmpeg/ffmpeg`. | `InspectJellyfinPaths` reads `<TranscodingTempPath>` from `/var/lib/jellyfin/config/encoding.xml` (default `/var/cache/jellyfin/transcodes`) instead of hardcoding paths. |
| **Jellyfin sandbox** | AetherFlow runs `jellyfin.service` under its `dotnet` sandbox (`ProtectSystem=strict` + allowlisted `ReadWritePaths`, `config/package_automation.json:24-40`). | `config/package_automation.json:35` adds directory `"-/run/aetherflow-transcode"` (broadened from single file `transcode.sock` in Bundle A so `aetherflow-api.service` restarts never strand `jellyfin.service` on an unlinked socket inode). Peer mounts under `/mnt/af-peers` are already permitted by `-/mnt`. Upgraded hosts with a pre-existing `10-aetherflow-sandbox.conf` run `sudo af sandbox apply jellyfin` once. |
| **NFS on Debian 13** | Debian 13 (`trixie`) ships `nfs-utils` 2.8.x supporting `/etc/nfs.conf.d/` drop-ins and `[nfsd] host=`. | Use `/etc/nfs.conf.d/aetherflow-peers.conf`, `/etc/systemd/system/nfs-server.service.d/20-aetherflow-peers.conf` (`After=wg-quick@afpeer0.service`, `Wants=wg-quick@afpeer0.service`), and `/etc/exports.d/` without editing `/etc/nfs.conf`. |
| **WireGuard & NFS packages on Debian 13** | The trixie kernel (6.12) includes WireGuard; `wireguard-tools` provides `wg` and `wg-quick@.service`. | `PeerNetworkRequest::EnsurePackages` (`/v1/peer-network`) is dispatched by `pairing.rs::ensure_local_identity` (`pairing.rs:1176`) before `EnsureIdentity` so fresh Debian 13 hosts automatically install `wireguard-tools` via Marketplace apt serialization (no DKMS, no Marketplace receipt). `PeerStorageRequest::EnsurePackages` (`/v1/peer-storage`) likewise installs `nfs-kernel-server` and `nfs-common` on first export/mount (`peers/storage.rs:1184,1873`) and transcode sync (`peers/transcode.rs:3423,6284`). |
| **AetherFlow installer** | `setup/modules/00-core.sh:95-112` already detects Debian 13 (`trixie`). | No OS-detection changes required. |
| **WebSocket routes** | Defined at `/api/v1/auth/ws`, `/api/v1/auth/ws/ticket`, and `/api/v1/auth/ws/logs` (`af-api/src/routes.rs`). `af-web-core/src/ws.rs` fetches tickets via `ApiClient` and constructs `ws(s)://<window host>...` URLs. | Both ticket requests and WebSocket URLs pass through `api_url()`, rewriting to `/api/v1/peers/{id}/auth/ws*` (`BrowserConnection` + `LogStreamConnection`, Entry 6 & P6). |

## Critical User Journeys (CUJs)

In the journeys below, **Server A** is named **`seedbox-1`** and **Server B** is named **`media-2`**.

### CUJ 1: Pair two servers

*   **Given:** Servers A (`seedbox-1`) and B (`media-2`) run this release, an administrator is signed into both dashboards, B's trusted HTTPS address is reachable from A, and UDP `51821` is reachable between chosen endpoints (VLAN or public IP).
*   **When:**
    1.  On B, the admin opens **Cluster → Allow a server to manage this one**, opens the pairing window, and copies the pairing string.
    2.  On A, the admin opens **Cluster → Pair with a server**, pastes the pairing string, and clicks **Start pairing**.
    3.  On B, the admin compares the six-digit code against A's locally computed code and clicks **Approve & link**.
*   **Then:**
    *   Both Cluster pages list the peer as *Linked, healthy*, showing RTT, software version, and compatibility.
    *   `afpeer0` is up on both servers.
    *   No grant exists yet, so neither server can manage the other.

### CUJ 2: Grant and manage (one-way, read-write)

*   **Given:** A (`seedbox-1`) and B (`media-2`) are linked.
*   **When:** On B, the admin grants A **Read and write (everything)**. On A, the admin switches to B from **Cluster**, restarts a service, changes a setting, and installs a Marketplace app.
*   **Then:**
    *   All three actions succeed.
    *   A colored "Managing **media-2**" identity bar remains visible on every tab.
    *   B's Audit tab records each action under `peer-seedbox-1` with peer audit metadata (`link`, `operator`, `request_id`, e.g., `"via seedbox-1, operator alice"`).

### CUJ 3: Read-only grant

*   **Given:** B grants A **Read-only (everything)**.
*   **When:** A browses every tab of B and attempts to stop a service.
*   **Then:**
    *   Every supported view loads.
    *   Mutation controls are disabled with an explanatory reason.
    *   A forced write request returns `403 PEER_SCOPE_DENIED` and is audited on B.

### CUJ 4: Two-way grants

*   **Given:** B has granted A read-write access.
*   **When:** On A, the admin grants B **Read-only (`services`)**.
*   **Then:**
    *   Each Cluster page shows both inbound and outbound grants in plain language (e.g., *"seedbox-1 can manage media-2 (read-write)"* and *"media-2 can view seedbox-1 services"*).
    *   Revoking one direction leaves the other direction intact.

### CUJ 5: Stream media from a peer

*   **Given:** B (`media-2`) exports parent folder `/srv/media/movies` (containing an existing `library/` subfolder on B) read-only to A (`seedbox-1`), and A mounts that export via **Cluster → Storage** at `/mnt/af-peers/media-2/movies`.
*   **When:** A's Jellyfin library points at the interior subfolder `/mnt/af-peers/media-2/movies/library`, and a 4K remux plays.
*   **Then:**
    *   Playback streams over kernel NFSv4.2 inside `afpeer0`.
    *   If the link is cut, the mount unit stops and `/mnt/af-peers/media-2/movies/library` disappears instead of presenting an empty folder. *(Target acceptance behavior: Jellyfin 12.4 preserves its library items — pending live Server B verification; see [Open Questions](#open-questions).)*
    *   Server A's Cluster page shows the mount as *Stopped: link down* (while Server B shows the link down).

### CUJ 6: Offload a transcode

*   **Given:** A runs Jellyfin with its media library shared between A and B over peer NFS **Storage**. B has a VA-API GPU, matching `jellyfin-ffmpeg`, `jellyfin.service` stopped/disabled, `transcoding: write` granted to A, worker mode enabled, and passing path parity with weight 1.
*   **When:** A client plays a file requiring a VA-API transcode.
*   **Then:**
    *   `ffmpeg` executes on B (reading media via path-parity bind mounts) and writes HLS segments into A's shared transcode directory.
    *   Jellyfin receives progress updates over relayed stdout/stderr, and stopping playback terminates remote `ffmpeg` on B.
    *   An NVENC-only job falls back locally on A.
    *   If B's link is revoked or the dispatcher is stopped, new playback transcodes locally.

### CUJ 7: Revoke a link

*   **Given:** A and B are linked with grants, mounts, and active streams.
*   **When:** On B, the admin revokes the link.
*   **Then:**
    *   B disables local link/grant authorization, tears down transcode mounts/exports before media storage mounts/exports, clears link/grant credentials, and removes A's owned WireGuard peer immediately.
    *   A's open management WebSockets (`<< 1 s`), in-flight non-WebSocket HTTP proxy streams (`<< 1 s`), active remote transcode jobs (`Signal(Kill)`), and NFS mounts terminate (new proxied requests fail immediately).
    *   A displays `"Link revoked by media-2"` when the revoke notice is delivered (or marks the link down if unreachable).
    *   Both audit logs record the revocation.

### CUJ 8: Version mismatch

*   **Given:** A runs a newer release than B, and a capability flag is absent on B.
*   **When:** A opens B in **Cluster**.
*   **Then:**
    *   The link reports **Limited**, and unsupported features are disabled with an upgrade prompt (e.g., *"Update media-2 to use missing capabilities: ..."*, `af-web-core/catalogs/en.json:335-336,2751`).
    *   If B's `peer_protocol` is below A's minimum, the link reports **Incompatible** and remote management pauses.

## Technical Plan (Architecture)

### Components

```text
               Server A (managing; runs Jellyfin)                           Server B (managed; storage + GPU)
 ┌───────────────────────────────────────────────────────┐     ┌───────────────────────────────────────────────────────┐
 │ Browser /?tab=cluster ──► af-api                      │     │ af-api                                                │
 │   ApiClient base-path hook: /api/v1/peers/{id}/...    │     │   peer listener (tunnel IP:9443, SO_BINDTODEVICE) ◄───┼──┐
 │   peers::proxy  (admin-only, 6 HTTP methods, WS) ─────┼──┐  │     1. source IP matches live/pending link IP         │  │
 │   peers::transcode dispatcher (unix socket) ◄── shim ─┼──┤  │     2. X-AF-Link-Token verified (SHA-256 CT eq)       │  │
 │   peers::health loop (15 s: WG, /health, sentinels) ──┼──┤  │     3. path canonicalized & /api/v1/ prefix checked   │  │
 │ af-runner (root)                                      │  │  │     4. X-AF-Grant-Token & ScopeRequirement verified   │  │
 │   afpeer0 (WireGuard, UDP 51821)                      │  │  │     5. PeerPrincipal + run-as AuthUser → af-api router│  │
 │   NFS mounts of B exports (/mnt/af-peers/...)         │  │  │   /peer/v1/{hello,link,revoke-notice,grant-*,exports, │  │
 │   NFS export: Jellyfin transcode/tmp/cache dirs       │  │  │     transcode/mounts,transcode/jobs} + GET /health    │  │
 │ Jellyfin ──JELLYFIN_FFMPEG──► af-transcode shim       │  │  │   worker relay ──► /run/aetherflow-transcode-worker/  │  │
 └───────────────────────────────────────────────────────┘  │  │                    worker.sock                        │  │
                                                            │  │ af-transcode-worker.service (User=jellyfin; GPU)      │  │
        WireGuard afpeer0 (keys pinned; VLAN or public IP)  │  │ af-runner (root)                                      │  │
                                                            └──┴── afpeer0, NFS exports, transcode/bind mounts, units  │  │
                                                               └───────────────────────────────────────────────────────┘  │
                                                                (all tunnel API/WS/health/transcode calls enter :9443) ───┘
```

### Transport: AetherFlow-managed WireGuard

*   **Dedicated interface:** AetherFlow manages `afpeer0` through `wg-quick@afpeer0.service` and `/etc/wireguard/afpeer0.conf` (`0600`), never touching the operator's existing `wg0` WireGuard VPN interface (managed via the **Network** tab and `af-runner/src/network.rs`). `af-runner/src/sandbox_ops.rs` already exempts `wg-quick@*`. Before `EnsureIdentity`, `pairing.rs::ensure_local_identity` (`pairing.rs:1157-1176`) dispatches `PeerNetworkRequest::EnsurePackages` so fresh Debian 13 hosts automatically install `wireguard-tools` through AetherFlow's Marketplace apt lock (without creating a Marketplace receipt).
*   **Addressing & kernel hardening:** Each server picks a random available host IP from `AF_PEER_TUNNEL_CIDR` (default `10.231.0.0/16`, avoiding already-known peer IPs) during first pairing and persists it in `peer_identity.tunnel_ip`; both peers must share the same `AF_PEER_TUNNEL_CIDR` and `AF_PEER_LISTEN_PORT` (if two already-initialized hosts collide on the same IP, pairing returns `409 TUNNEL_IP_CONFLICT`, requiring manual `afpeer0` identity reset on one unlinked host or subnet realignment; see [docs/peer-clustering.md](../peer-clustering.md#common-recovery-runbooks)). Local `afpeer0.conf` configures the interface with the full subnet prefix so `wg syncconf` keeps a connected subnet route, while each peer entry sets `/32` `AllowedIPs` and `PersistentKeepalive = 25`. Before committing peer routes, `af-runner` verifies via `ip -j route get <peer_tunnel_ip>` that the effective kernel route is `unicast` over `dev == "afpeer0"` without `dead`/`linkdown` flags, rolling back disk and live configs on route failure. The default WireGuard UDP port is `AF_PEER_WG_PORT=51821` (configurable per host before first initialization).
*   **Firewall expectations:** Allow UDP `51821` (or `AF_PEER_WG_PORT`) between chosen endpoints, plus TCP `9443` (`AF_PEER_LISTEN_PORT`) and TCP `2049` (NFSv4.2) on `afpeer0` only. Pairing also requires Server A to reach Server B's trusted HTTPS address (strict OS CA TLS; no `danger_accept_invalid_certs`, redirects, or proxy env overrides; SSRF-guarded with DNS IP pinning).
*   **Endpoint selection:** Administrators choose from detected non-loopback interfaces (private VLAN addresses are labeled recommended). Endpoints are stored per link, never fail over silently, and can be updated from **Cluster**.
*   **Internal link ownership state machine (`peer_links.state`):** Encodes both lifecycle (`pending`, `active`, `down`, `revoking`, `revoked`) and affirmative WireGuard peer ownership across 10 internal states (`af-api/src/peers/mod.rs:56-132`):
    *   Newly reserved pending rows start as `pending` (unowned). Only a definitive `PeerNetworkRequest::AddPeer` (`Ok(Mutation)` rather than a pre-existing/unconfirmed peer or uncertain runner outcome) promotes a row to `pending_owned`. Uncertain outcomes or pre-existing WireGuard peers remain unowned so AetherFlow never deletes an unowned WireGuard peer automatically.
    *   **Owned lifecycle:** `pending_owned → active ↔ down → revoking` (initiating revocation/cleanup) or `revoked` (remote-revocation tombstone; admin removal transitions `revoked → revoking`) (`is_wg_peer_owned == true`, authorizing destructive `RemovePeer` during revocation when no other link shares the public key).
    *   **Unowned lifecycle:** `pending → active_unowned ↔ down_unowned → revoking_unowned` or `revoked_unowned` (admin removal transitions `revoked_unowned → revoking_unowned`) (`is_wg_peer_owned == false`, skipping automated `RemovePeer`).
    *   `revoking` / `revoking_unowned` mark in-flight revocation cleanup before the revoking server deletes the `peer_links` row. If runner cleanup fails, the error propagates while retaining `revoking*` with `pending_expires_at = 0`—which signals `pairing::cleanup_expired_pending` (run on every 15 s health tick, `peers/health.rs:176`, `peers/pairing.rs:1923`) to retry cleanup and row deletion (`revoking*` never transitions to `revoked*`). `public_link_state` projects all 10 internal values to 4 public API states (`pending`, `active`, `down`, and `revoked` — projecting `revoking*` to `revoked`).
*   **Why WireGuard:** Both sides pin keys, packets without a valid key draw no response, and source tunnel IPs cryptographically map to peer keys—securing API, NFSv4.2, and transcode traffic inside one tunnel without per-service certificates.

### Peer authentication and authorization (on the managed server)

**Peer listener, `ifindex` recycling, & lazy activation:** `peers::start()` (`af-api/src/peers/mod.rs:1563`) is gated at boot in `af-api/src/main.rs:271-274,331-340` behind `if !disable_workers`, so setting `AETHERFLOW_DISABLE_BACKGROUND_WORKERS`, `AETHERFLOW_DISABLE_WORKERS`, or `AETHERFLOW_E2E_ISOLATED` skips boot-time health probing, transcode auto-start, listener binding, and startup grant cleanup. When enabled, `peers::start()` spawns the 15-second health loop once (which returns early as an idle no-op when no `peer_identity`, links, or open pairing attempts exist, `peers/health.rs:141-177`), runs `start_dispatcher_if_configured` (binding `transcode.sock` if `peer_identity` exists and `jellyfin_dropin_enabled && shim_installed`), and leaves the peer tunnel listener dormant until a `peer_identity` exists. Once `EnsureIdentity` succeeds during first pairing, `PeerRuntime::ensure_listener_started()` (`peers/mod.rs:1306-1398`) dynamically binds the axum peer listener to `<own tunnel IP>:AF_PEER_LISTEN_PORT` (default `9443`) using `SO_BINDTODEVICE("afpeer0")` without an API restart. `ListenerHandle` and `TunnelClientBindingKey` (`peers/mod.rs:562-598`) track the kernel `interface_index` (`libc::if_nametoindex`); whenever `wg-quick@afpeer0.service` restarts with a new `ifindex`, `ensure_listener_started()` clears pooled `tunnel_clients` and `proxy_tunnel_clients` (`clear_tunnel_clients`, `peers/mod.rs:765`) and automatically rebinds the listener. Every 15 s health tick also runs `transcode::reconcile_dispatcher_if_configured` (`peers/health.rs:171`, `peers/transcode.rs:4331`, logging `tracing::warn!` on transient errors) so transient boot-time `InspectJellyfinPaths` failures recover automatically.

1.  **Link check:** Require the tunnel source IP to match a live (`active` or `down` via `is_live_link_state`) link (or, exclusively for `POST /peer/v1/hello` `phase: "bootstrap"`, a pending peer's pinned WireGuard identity and unexpired attempt ID), allowing recovery probes, grant revocations, and `/peer/v1/revoke-notice` to authenticate even while a link is marked `down`.
2.  **Link token:** Live links require `X-AF-Link-Token` to match `peer_links.inbound_token_hash` (SHA-256) via `af_models::constant_time_eq`. Each side mints an independent 256-bit incoming token; the issuer stores only its hash and the caller stores the raw token in a runner-managed file (`PeerCredentialSlot::LinkToken`).
3.  **Peer-internal tunnel routes:** All tunnel routes pass through `tunnel_request_id_middleware` (`peers/listener.rs:283`, normalizing/generating `X-Request-ID`, scoping `af_runner::with_runner_request_id`, and echoing `X-Request-ID` on responses) and require `X-AF-Link-Token` (except `POST /peer/v1/hello` `phase: "bootstrap"`, which uses pending WG IP + attempt ID); transcode routes additionally require `X-AF-Grant-Token` (`transcoding: write`):
    *   `POST /peer/v1/hello` (`phase: "bootstrap"` via pending WG IP + attempt ID; `phase: "acknowledge"` via `X-AF-Link-Token`)
    *   `GET /health` (link-authenticated health, protocol, capabilities, async-refreshed 60 s TTL transcode capability probe including `worker_max_jobs`, and `"inbound_grant_generation"` for offline grant-revocation reconciliation, `peers/listener.rs:410-458`)
    *   `GET /peer/v1/link` (link metadata)
    *   `POST /peer/v1/revoke-notice` (best-effort link revocation delivery)
    *   `POST /peer/v1/grant-offer` (purely informational reciprocal-grant prompt: mutates zero grant tables, emits an in-app `"Access review requested by <peer>"` notification via `emit_notification`, and logs `peer_grant_offer_received`)
    *   `POST /peer/v1/grant-token` & `POST /peer/v1/grant-revoke` (generation-fenced grant credential delivery and revocation)
    *   `GET /peer/v1/exports` (authenticated media-export catalog for P7 mount discovery)
    *   `POST /peer/v1/transcode/mounts` (8 KiB body cap; requires `X-AF-Link-Token` + `X-AF-Grant-Token` with `transcoding: write`; syncs or tears down worker transcode NFS mounts and media bind mounts)
    *   `GET /peer/v1/transcode/jobs` (WebSocket upgrade outside the 8 KiB layer; requires `X-AF-Link-Token` + `X-AF-Grant-Token` with `transcoding: write`; relays `wincode` transcode frames to `af-transcode-worker.service` under `MAX_FRAME_BYTES = 1 MiB`)
    *   Unknown `/peer/v1/*` routes hit the fail-closed fallback and return `403 PEER_ROUTE_UNCLASSIFIED`.
4.  **Management request canonicalization, grant check, in-flight revocation, and route classification (`peers/listener.rs`):**
    1.  Canonicalize the request path (`scopes::canonicalize`) and enforce the `/api/v1/` prefix **before** grant lookup: collapse `//`, percent-decode once, reject `.` / `..`, backslashes, whitespace, control characters, and double-encoded separator ambiguity (non-`/api/v1/` or malformed paths return `403 PEER_ROUTE_UNCLASSIFIED`).
    2.  Look up the active inbound grant and verify `X-AF-Grant-Token` against `peer_grants.token_hash` (SHA-256) before route scope evaluation. Subscribe to `RevocationEvent` via `spawn_listener_revocation_watcher` (`peers/listener.rs:308`) so in-flight non-WS HTTP management requests and streaming response bodies cancel immediately (`<< 1 s`) on link or grant revocation.
    3.  Classify `(&Method, &CanonicalPath) -> RouteDecision` (`Allowed(ScopeRequirement) | Forbidden | Unclassified`, `af-api/src/peers/scopes.rs:1499`) against static `FORBIDDEN_RULES` (`ForbiddenRule` → `403 PEER_SCOPE_DENIED`) and `ALLOWED_RULES` (`AllowedRule`), reusing `crate::plugins::route_pattern_matches` (`scopes.rs:1447-1461`) for static and trailing-`/*` `/api/v1/` patterns and segment matching for `:param` templates. Rules span 8 areas (`services`, `marketplace`, `settings`, `files`, `users`, `network`, `updates`, `transcoding` — full operator mapping in [docs/peer-clustering.md](../peer-clustering.md#grant-access-to-a-linked-peer)) and `ScopeRequirement::{Area(area, mode), All(&[...]), Any(&[...]), AnyReadAccess}`:
        *   **`updates` and `transcoding` scope specifics:** `updates` covers AetherFlow system update checks/status/runs plus updating **`jellyfin` / `jellyfin-ffmpeg*`** via `POST /api/v1/admin/packages/{id}/update` (`is_jellyfin_update_package_id`, enforced in both `peers/scopes.rs:1493-1531` and handler-level guard `routes/marketplace/handlers.rs:188`); updating any other Marketplace package requires `marketplace: write`. `transcoding: read` covers MediaFlow queue reads (`GET /api/v1/admin/mediaflow/queue`), while `transcoding: write` covers MediaFlow mutations plus tunnel transcode jobs and mounts.
        *   `AnyReadAccess` (`scopes.rs:457-505`): permits any grant holding `read` or `write` in at least one area on `GET /api/v1/auth/ready`, `/api/v1/{auth,admin}/system/metrics`, `/api/v1/auth/system/metrics/history`, `/api/v1/auth/system/{hardware,topology}`, and `/api/v1/auth/notifications` (plus filtered `/api/v1/auth/ws` telemetry).
        *   Multi-area `ScopeRequirement::All` rules (`scopes.rs:703,722,1046-1051`): `POST /api/v1/auth/deploy/{appName}` (`marketplace: write` + `services: write` + `network: write`), `POST /api/v1/admin/blueprints/{appName}/sync` (`marketplace: write` + `network: write`), and per-user McBrowser policy `GET`/`PUT /api/v1/auth/mcbrowser/policy/{user_id}` (`files` + `users` at matching mode).
        *   Production route registration uses `TrackedRouter` (`af-api/src/routes/inventory.rs`, recording every registered `(method, path)` template) so CI tests fail if any registered route is unclassified.
    4.  Check the grant's per-area level (`none | read | write`). Read-only grants permit read routes and read WebSocket upgrades, except **five** explicit `GET`/`HEAD` endpoints carrying sensitive payloads or staging side effects that require `Write` (plus Axum implicit `HEAD` inheriting `GET` write rules, `scopes.rs:805,940,1109-1124,1165`):
        *   `GET /api/v1/admin/backup/download/{filename}` (`settings: write`)
        *   `GET /api/v1/admin/streaming/portability/export` (`settings: write`)
        *   `GET /api/v1/auth/mcbrowser/uploads` (`files: write`)
        *   `HEAD /api/v1/auth/mcbrowser/uploads/{id}` (`files: write`)
        *   `GET /api/v1/auth/mcbrowser/archive/{ticket}` (`files: write`)

        `POST /api/v1/admin/packages/{id}/update` accepts `ScopeRequirement::Any(&[(Marketplace, Write), (Updates, Write)])` strictly when `is_jellyfin_update_package_id(id)` holds (`jellyfin` or `jellyfin-ffmpeg*`) and requires `ScopeRequirement::Area(Marketplace, Write)` for all other package IDs (`peers/scopes.rs:1519-1530`, `routes/marketplace/handlers.rs:188`).
    5.  **Fail closed:** Unclassified routes return `403 PEER_ROUTE_UNCLASSIFIED`.
5.  **Never reachable through a grant:** `/api/v1/admin/peers/*` (including `/api/v1/admin/peers/transcode`), `/api/v1/peers/*` (blocks proxy chaining), pairing routes, Plugin Sandbox iframe routes, OIDC client mutations (`POST`/`DELETE`) and `/api/v1/{auth,public}/oidc/*` (reading `GET /api/v1/admin/oidc/clients` is allowed under `settings: read`), plugin token / app-launch minting, and local auth/session/credential mutation routes (`FORBIDDEN_RULES` → `403 PEER_SCOPE_DENIED`).
6.  **Identity injection & target audit:** The listener strips peer credential headers, inserts `PeerPrincipal` (`link_id`, `link_name`, `local_server` [local server display name for errors/audits], `grant_id`, `run_as_user_id`, `run_as_username`, `access`, `origin_operator`, `request_id` — 9 fields in `af-api/src/auth/tokens.rs:71-81`) and the run-as `AuthUser`, records peer audit entries containing the link name, run-as username, `X-AF-Origin-Operator`, and `X-Request-ID` (rendered in the Audit tab and displayed with secrets redacted by `af cluster diagnose`), and forwards into `routes::build_router()`.
    *   **Role:** Both read-only and read-write grants inject `role = "admin"` because existing read endpoints sit behind `admin_only_middleware`; perimeter enforcement in `peers::scopes` prevents mutations under read-only grants.
    *   **Middleware:** `csrf_middleware` and `host_validation_middleware` skip browser-specific checks only when the in-process `PeerPrincipal` extension is present.

**Run-as account:** Creating a grant provisions a dedicated local user `peer-<peer name>` (`account_type = 'peer'`, no password hash, rejected by password and OIDC login, hidden from normal user lists, undeletable from the Users tab, and disabled on grant revocation). `load_active_human_subject` remains human-only; a dedicated `load_active_peer_subject` / `load_active_subject_for_request` (`af-api/src/auth/tokens.rs:133-160`) loads `account_type = 'peer'` only when `PeerPrincipal` is present (returning `403 PEER_SCOPE_DENIED` if the run-as subject is missing or disabled).

**Password re-check routes:** Standard AetherFlow backup downloads use a two-step flow: a `POST` password re-check mints a one-use `af_backup_download` ticket cookie consumed by the subsequent browser `GET` download. For peer calls (`af-api/src/storage/backups.rs:694-759,936-965`), both steps require `PeerPrincipal` (`settings: write`) without forwarding the managing administrator's local password: step 1 (`POST`) discards any request body on the managing proxy (`peers/proxy.rs:123-135,840,1012`) and mints the one-use `af_backup_download` ticket cookie scoped to `/api/v1/peers/{id}/admin/backup/download/`; step 2 (`GET`) forwards that isolated ticket cookie alongside `PeerPrincipal` (or accepts `PeerPrincipal` directly for non-browser API downloads).

### Remote management (on the managing server)

*   **Proxy:** `tracked_proxy_routes_with_runtime` (`af-api/src/peers/mod.rs:1527`) registers six explicit HTTP methods (`GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`) on `/api/v1/peers/{id}/{rest}` behind `admin_only_middleware` (rejecting plugin tokens and peer principals), forwarding via `peers/proxy.rs` to `http://<peer tunnel IP>:<AF_PEER_LISTEN_PORT>/api/v1/{rest}` with the held link and grant tokens.
*   **Transport & in-flight revocation:** Reuses shared `stream_proxy` (`af-api/src/middlewares/subdomain_proxy.rs:468`, re-exported at `middlewares.rs:27`, with options, `GuardedBody::wrap_with_cancel`, and tunnel-bound TCP connect helpers in `middlewares/proxy_helpers.rs:490-648`) shared with `app_subdomain_proxy_middleware` for streaming HTTP bodies and WebSocket upgrades. Both WebSockets and in-flight non-WS HTTP requests/response bodies subscribe to `RevocationEvent` via `spawn_proxy_revocation_watcher` (`peers/proxy.rs:421,878,970-1009`) and `StreamProxyOptions.stream_cancel` (`StreamProxyErrorKind::Cancelled`), canceling active streams and releasing permits within 1 second (`<< 1 s`).
*   **Header, cookie, & body handling:**
    *   Strips `Cookie`, `Authorization`, `X-Forwarded-*`, `Host`, `Origin`, and any client-supplied peer auth or audit headers before setting authoritative peer tokens and `X-AF-Origin-Operator`, with two backup-download carve-outs (`peers/proxy.rs:123-135,832-840,1012`): (a) on `GET /api/v1/admin/backup/download/{filename}`, extracts and forwards an isolated `Cookie: af_backup_download=<ticket>` header (failing closed with `403 INVALID_CURRENT_PASSWORD` on malformed or ambiguous cookies); and (b) on `POST /api/v1/admin/backup/download/{filename}`, discards the request body (`discard_request_body = true`, stripping `Content-Length`/`Content-Type`) so local passwords never traverse the tunnel.
    *   Propagates `X-Request-ID` (bounded to 128 ASCII identifier bytes; local `security_headers_middleware` in `af-api/src/routes.rs:273,301` falls back to a bare Unix nanosecond integer via `Utc::now().timestamp_nanos_opt().unwrap_or(0)`, while `peers/proxy.rs:899` and `peers/listener.rs:232` fall back to UUID v4, and `af_runner::with_runner_request_id` propagates the same ID into `PeerErrorBody.request_id` and `aetherflow-runner` IPC/logs).
    *   Rewrites root-relative `Location` headers (e.g., McBrowser `tus` uploads) under `/api/v1/peers/{id}`. Strips all upstream `Set-Cookie` headers **except** the one-use `af_backup_download` ticket cookie, which is scoped to `/api/v1/peers/{id}/admin/backup/download/` (note trailing slash, `af-api/src/peers/proxy.rs:191-290`).
*   **Targets & limits:** Always dials the stored tunnel IP (never request-supplied hosts). Enforces per-link `AF_PEER_MAX_CONN=64` concurrent HTTP requests and `AF_PEER_MAX_WS=16` WebSockets (configured in `/etc/aetherflow/aetherflow.env`, logging `tracing::warn!` via `parse_peer_env_or_warn` at `peers/mod.rs:1632-1657` on invalid/non-positive values; permits are held until stream drop, and the target peer listener enforces the same per-link `AF_PEER_MAX_WS` pool across both management WebSockets and `/peer/v1/transcode/jobs` streams), 30 s connect timeout, 30 s response-header timeout (started after request body completion), 30 s idle timeout on stalled uploads, and no total duration cap on active streams.
*   **Frontend isolation:**
    *   `af-web-core/src/api.rs` provides thread-local `active_server()` / `api_url(path)` driven by `AppContext.active_server_id: RwSignal<Option<String>>` (`af-web-app/src/state.rs:109`, paired with pure switching/health helpers `PeerArea`, `ServerAccent`, `ActivePeerHealth`, `peer_switch_eligibility` in `af-web-app/src/state/server.rs`), plus `SERVER_EPOCH` / `bump_server_epoch_and_abort` to abort stale in-flight fetches on switch.
    *   `af-web-core/src/ws.rs` manages both `BrowserConnection` (telemetry) and `LogStreamConnection` (live logs) through `api_url`, tagged with `origin_server_epoch`. On the managed server, `websocket_message_for_peer_session` (`ws/telemetry.rs:396-431`) drops `package:progress` without `marketplace: read`, nulls `METRICS_UPDATE.data.services` without `services: read`, runs `sanitize_services_for_viewer` (`ws/telemetry.rs:240-291`, redacting raw `log_line`/`update_error` and detailed `last_job` fields when `services: read` lacks `marketplace: read`), and gates diagnostic messages on `services: read && marketplace: read`.
    *   `af-web-app/src/tabs/busy.rs` provides `AreaFence`, resource caches are keyed by server, local auth/pairing/grant/Plugin Sandbox paths and local-operator header/profile avatars stay local, upstream peer `401`/`403` never clears the local admin session, and the identity bar offers **`Exit to This server`**.
    *   When managing a remote peer (`context.is_remote_untracked()`), third-party app launch buttons bypass local `/api/v1/admin/apps/launch` minting (`tabs/services/launch.rs:19-23`) and navigate directly to the external app URL returned by the peer's service payload (opening against the peer's own host Apache vhost/login).
*   **Compatibility & `/health`:** Both public `GET /health` and tunnel `GET /health` include `peer_protocol: 1` (`PEER_PROTOCOL_VERSION = 1`, `MIN_PEER_PROTOCOL_VERSION = 1`) and `capabilities` (`["links", "grants", "storage", "transcode"]`). `evaluate_compatibility` (`peers/health.rs:51-89`) classifies peers into four `CompatibilityStatus` states: `Unknown` (no `peer_protocol` observed yet), `Incompatible` (`protocol < MIN_PEER_PROTOCOL_VERSION`, which pauses remote management in the UI via `peer_switch_eligibility`), `Compatible` (`protocol == PEER_PROTOCOL_VERSION` and all local `capabilities()` present), and `Limited` (`protocol >= MIN_PEER_PROTOCOL_VERSION` with `protocol != PEER_PROTOCOL_VERSION`—including higher future protocol versions—or any missing local capability). `422 VERSION_INCOMPATIBLE` is returned during pairing (`pairing.rs` when `peer_protocol` is unsupported or missing) and when tunnel peer calls hit `404` or unclassified grant routes (`peers/errors.rs:526`, `peers/grants.rs:469`). Unauthenticated public `GET /health` (`routes/health.rs:34`) unconditionally returns `"transcode": null` without exposing host hardware/FFmpeg inventory or spawning subprocesses. Link-authenticated tunnel `GET /health` (`peers/listener.rs:410-458`) returns cached `transcode` capabilities (including `worker_max_jobs`, refreshed on a 60 s TTL by `reconcile_dispatcher_if_configured` at `peers/transcode.rs:4331`, the 15 s health loop, and `GET /api/v1/admin/peers/transcode`) plus `"inbound_grant_generation"` (`i64 | null`).
*   **Long jobs:** Marketplace jobs execute under the target's `reconcile_package_jobs` and are polled through the proxy, showing done, failed (with reason), or unknown (peer unreachable).

### Pairing protocol

1.  **Open the window (B):** `POST /api/v1/admin/peers/pairing-window` initializes B's peer identity/listener if dormant (auto-installing `wireguard-tools` via `PeerNetworkRequest::EnsurePackages` first), resolves B's trusted `https_url` (from optional explicit bare `https://host[:port]` input, else `PUBLIC_URL`, else `oidc::get_base_url_for_peer(headers, peer_ip)`, `peers/pairing.rs:2220`) and operator-selected reachable WireGuard `endpoint`, opens a 10-minute window, stores only the SHA-256 hash of the single-use code, and returns `afpair1:<base64url(json{https_url, wg_pubkey, endpoint, wg_port, tunnel_ip, code})>`. Unused windows can be closed via `DELETE /api/v1/admin/peers/pairing-window/{id}` or all at once via `DELETE /api/v1/admin/peers/pairing-window`.
2.  **Start pairing (A):** `POST /api/v1/admin/peers/pair { pairing_string, name?, endpoint?, local_name? }` (optional `name` labels the remote peer on A; optional `local_name` overrides A's advertised name sent to B) validates B's `https_url` against SSRF rules (`validate_pairing_url_host`/`validate_pairing_ip` at `peers/pairing.rs:536-685` and DNS-pinned `.no_proxy()` strict-TLS transport in `ProductionPublicPairingTransport` at `peers/mod.rs:209-275`, blocking loopback, link-local/metadata, unspecified, multicast, broadcast/reserved, `afpeer0` CIDR, and RFC1918/ULA/CGNAT unless `AF_PEER_ALLOW_PRIVATE_PAIRING_URLS=true`, with redirects disabled), initializes A's identity/listener (`EnsurePackages` → `EnsureIdentity`), chooses A's tunnel IP, adds B's pinned key and tunnel IP to `afpeer0` as a pending peer, computes the six-digit comparison code locally from A's key and B's `wg_pubkey` in the pairing string, and posts A's public key, endpoint, `wg_port`, tunnel IP, name, version, peer protocol, timestamp, and code (`PublicPairingRequest`) to B's `POST /api/v1/peer-pairing/request` over strict-TLS HTTPS. B enforces a 4 KiB body cap, 5 requests/minute per source IP (`Retry-After: 60`), `CLOCK_SKEW_MAX_SECS = 300` (5 minutes), and atomic single-use consumption.
3.  **Record the attempt:** B stores the attempt and expiry and returns its attempt ID plus the six-digit comparison code derived via `derive_comparison_code(A_pubkey, B_pubkey)` (`af-api/src/peers/pairing.rs:99`): `u32::from_be_bytes(sha256(A_pubkey_utf8 || B_pubkey_utf8)[0..4]) % 1_000_000` formatted as `{num:06}` (initiator A then responder B). Because A computes the code independently from B's pairing-string key, comparing both dashboards detects MITM key substitution. Pending attempts can be canceled via `DELETE /api/v1/admin/peers/pairing/{attempt}`.
4.  **Confirm (B):** After the administrator confirms matching six-digit codes, `POST /api/v1/admin/peers/pairing/{attempt}/confirm` (optional body `{ name? }`) records B's pending link, adds A to B's `afpeer0`, mints B's incoming link token (staging a temporary copy in `PeerCredentialSlot::PendingIssuerToken`), and calls A's `POST /peer/v1/hello` (`phase: "bootstrap"`) over the tunnel (accepted only from the pending peer's pinned WireGuard IP and unexpired attempt ID).
5.  **Complete & retry semantics:** A validates the pending peer and attempt, saves B's issued incoming token (`PeerCredentialSlot::LinkToken`), mints and stages A's own temporary incoming token in root-only `/etc/aetherflow/peers/pending/link-<link_id>.token` (or `link-<sha256-48hex>.token` if `link_id.len() > 59 || !is_valid_credential_id(link_id)`, derived strictly from the local `peer_links.id` — never keyed by a remote attempt ID, `peers/pairing.rs:307`), and returns it. B saves A's incoming token (`PeerCredentialSlot::LinkToken`, `peers/pairing.rs:5090`), sends an authenticated acknowledgment (`phase: "acknowledge"`, `HelloPhase::Acknowledge`, `peers/pairing.rs:1081,5181`) to `POST /peer/v1/hello` using that token, commits link activation in SQLite, and **after** activation deletes B's staged `PendingIssuerToken` (`peers/pairing.rs:5426`) so confirm retries remain idempotent across transient tunnel failures. A activates the link and clears its temporary file; authenticated retries for the same acknowledged attempt reuse the same credentials until expiry, and cancellation/failure/expiry cleans up pending peers and files.
6.  **Typed errors (22 `PeerError` codes in `af-api/src/peers/errors.rs:88-165`):** Every peer endpoint (including standardized `Bytes`/`Json` extractor rejections via `bytes_rejection_to_peer_error`, `json_rejection_to_peer_error`, `parse_optional_json_bytes`, and `parse_required_json_bytes` at `errors.rs:625-707`) returns `{code, server, step, message, action, request_id?}` (`PeerErrorBody` at `errors.rs:76-84`, populated from `af_runner::current_runner_request_id()` at `L200`) with secret redaction:
    *   `410 GONE`: `CODE_EXPIRED`, `WINDOW_CLOSED`
    *   `409 CONFLICT`: `CODE_USED`, `KEY_MISMATCH`, `TUNNEL_IP_CONFLICT`, `PEER_CONFLICT`
    *   `502 BAD_GATEWAY`: `ENDPOINT_UNREACHABLE`, `LINK_DOWN`
    *   `504 GATEWAY_TIMEOUT`: `HANDSHAKE_TIMEOUT`
    *   `422 UNPROCESSABLE_ENTITY`: `VERSION_INCOMPATIBLE`
    *   `400 BAD_REQUEST`: `CLOCK_SKEW`, `INVALID_REQUEST`
    *   `413 PAYLOAD_TOO_LARGE`: `PAYLOAD_TOO_LARGE`
    *   `415 UNSUPPORTED_MEDIA_TYPE`: `UNSUPPORTED_MEDIA_TYPE`
    *   `403 FORBIDDEN`: `PEER_SCOPE_DENIED`, `PEER_ROUTE_UNCLASSIFIED`, `LINK_REVOKED`
    *   `429 TOO_MANY_REQUESTS`: `RATE_LIMITED`
    *   `401 UNAUTHORIZED`: `PEER_UNAUTHORIZED`
    *   `404 NOT_FOUND`: `PEER_NOT_FOUND`
    *   `503 SERVICE_UNAVAILABLE`: `PEER_BUSY`
    *   `500 INTERNAL_SERVER_ERROR`: `PEER_INTERNAL_ERROR`
7.  **Two-way grants (P5):** Each direction is created solely on the granting server. `POST /api/v1/admin/peers/{id}/grant-offer` (accepting empty body or `{}`) forwards a purely informational `/peer/v1/grant-offer` notification (emitting an in-app notification on the remote server inviting that admin to open **Cluster → Grants**; no grant state changes). Grant creation/rotation (`PUT /api/v1/admin/peers/{id}/grant`) fails closed without activating the grant locally if `POST /peer/v1/grant-token` delivery fails or omits matching `{ accepted: true, grant_id, generation }` (`peers/grants.rs:625-825`). Both `/peer/v1/grant-token` and `/peer/v1/grant-revoke` are ordered by `peer_grant_epochs.issuer_generation`: receivers reject stale/out-of-order `grant-token` payloads (`incoming_gen <= existing.generation`) with `409 PEER_CONFLICT` (`peers/grants.rs:2027`) and ignore stale `grant-revoke` payloads (`generation < existing.generation`, returning `200 OK` without disturbing newer grants, `peers/grants.rs:2421`).

### Revocation

*   **Grant:** Clears `peer_grants.token_hash`, disables `peer-<name>`, invalidates its sessions, notifies `/peer/v1/grant-revoke` (best effort), and broadcasts `RevocationEvent::GrantRevoked` (canceling open management WebSockets and in-flight non-WS HTTP proxy streams on both managing and target sides within `<< 1 s`, and sending `Signal(Kill)` to active `/peer/v1/transcode/jobs` streams for that grant). On workers, revoking an inbound grant or downgrading `transcoding` below `write` automatically invokes `transcode::cleanup_worker_transcode_mounts_for_link` (`peers/grants.rs:1015,1133,1918,2339,2565`) to tear down that link's `transcode_bind` and `transcode` NFS mounts. If the best-effort `/peer/v1/grant-revoke` notice is missed during a tunnel outage, the grantor immediately rejects management and transcode requests with `403 PEER_SCOPE_DENIED` (`401 PEER_UNAUTHORIZED` when a newer active grant exists and a stale token fails digest match), and once connectivity recovers, the 15 s health loop inspects `"inbound_grant_generation": null` from tunnel `GET /health` and runs `grants::reconcile_missing_remote_grant` (`peers/health.rs:318`, `peers/grants.rs:1803-1930`) to delete the stale `peer_received_grants` row, queue credential cleanup, broadcast `RevocationEvent::GrantRevoked`, and clean up any worker transcode mounts. Preserves link health and peer media NFS mounts.
*   **Link (`peers/links.rs:609-675`):** Runs in three phases:
    *   **Phase A (SQLite `IMMEDIATE` tx under `link_lock`):** Disables local link and grant authorization immediately (`inbound_token_hash = NULL`, transitions live/revoked states to `revoking`/`revoking_unowned`, revokes grants, marks mounts stopped), publishes `RevocationEvent` (canceling active management WebSockets and in-flight non-WS HTTP proxy streams within `<< 1 s`, and sending `Signal(Kill)` to active `/peer/v1/transcode/jobs` streams), and writes the audit entry.
    *   **Phase B (lock-free, avoiding mutual-revocation deadlock):** Sends a best-effort authenticated `POST /peer/v1/revoke-notice` using the held link token.
    *   **Phase C (re-acquiring `link_lock`, `cleanup_revoked_link_resources_locked` at `peers/links.rs:649-675`):** Tears down transcode mounts/exports **first** via `transcode::cleanup_revoked_link_transcode_locked` (`L657`, so `transcode_bind` mounts sitting atop `/mnt/af-peers/*` unmount cleanly BEFORE media mounts), runs peer media storage cleanup (`cleanup_revoked_link_storage_locked`, `L658`), deletes staged grant, link, and pending-issuer credentials, removes the WireGuard peer (when `is_wg_peer_owned`), propagates **both** `transcode_res?` and `storage_res?` (`L673-674`), and deletes the local `peer_links` row once cleanup completes (retaining `revoking`/`revoking_unowned` with `pending_expires_at = 0` for retry or health-sweep recovery if transcode, storage, or WireGuard runner cleanup fails).
    *   **Remote-peer behavior:** Delivered notices (`apply_remote_revocation`, `peers/links.rs:685`) immediately disable incoming authorization, publish `RevocationEvent`, clean up transcode, storage, credentials, and owned WireGuard peers, and keep the tombstoned link row in `revoked`/`revoked_unowned` state displaying `"Link revoked by {name}"` until manually removed. Because normal Phase C deletion removes the initiating server's `peer_links` row, an unreachable peer receives `401 PEER_UNAUTHORIZED` (`peers/listener.rs:117`) and stays `down` until manually revoked (auto-transitioning to `revoked` via `LINK_REVOKED` at `peers/listener.rs:126`, `peers/health.rs:333` occurs only while the remote still retains a `revoking*` or `revoked*` row).

### Media sharing: NFSv4.2 inside the tunnel

Media export discovery (`GET /peer/v1/exports`) and mounting require only an active link (no `files` management grant). On the first export or mount, `PeerStorageRequest::EnsurePackages` automatically installs `nfs-kernel-server` and `nfs-common` via Marketplace apt serialization.

*   **Server side (B):**
    *   `af-runner` writes `/etc/exports.d/aetherflow-peer-<link_id>.exports` (keyed by `peer_links.id`), restricting every export to the peer's tunnel IP, and runs `exportfs -ra`. (Transcode exports use a separate `/etc/exports.d/aetherflow-peer-<link_id>-transcode.exports` file.)
    *   `af-api/src/peers/storage.rs` enforces `AF_ALLOWED_FS_ROOTS` (when unset/empty, `/mnt,/media,/srv,/data,/home` plus `env::temp_dir()` and `env::current_dir()` unless canonicalized under `/opt/AetherFlow` or `/var/lib/aetherflow`), real non-symlink directories, 18 `FORBIDDEN_EXPORT_PREFIXES` (`/bin`, `/boot`, `/dev`, `/etc`, `/lib`, `/lib32`, `/lib64`, `/libx32`, `/mnt/af-peers`, `/opt/AetherFlow`, `/proc`, `/root`, `/run`, `/sbin`, `/sys`, `/usr`, `/var/lib/aetherflow`, `/var/run`), and `FORBIDDEN_EXACT_EXPORT_ROOTS` (`/`, `/tmp`, `/var/tmp`, `/var`, `/home`).
    *   Every export (read-only or writable) runs `EnsureSentinel` to create `.af-peer-sentinel` (`0644`) inside the exported directory on Server B and return its authoritative on-disk `(owner_uid, owner_gid)`. Read-only exports use `ro,root_squash,secure,no_subtree_check`. Opt-in writable exports reject root-owned directories (`uid == 0 || gid == 0` via `EnsureSentinel { require_non_root_owner: true }`) and use `rw,all_squash,anonuid=<uid>,anongid=<gid>,secure,no_subtree_check` derived from that folder's on-disk owner (persisted in `peer_exports.squash_uid`/`squash_gid`).
    *   `ConfigureNfsd` (`peer_storage.rs:2712-2790`) writes `/etc/nfs.conf.d/aetherflow-peers.conf` (`[nfsd]\nhost=<tunnel IP>\n`) and managed `/etc/systemd/system/nfs-server.service.d/20-aetherflow-peers.conf` (`After=wg-quick@afpeer0.service`, `Wants=wg-quick@afpeer0.service`), runs `systemctl daemon-reload`, logs a warning if pre-existing active unmanaged lines exist in `/etc/exports`, and enables/restarts `nfs-server.service` (restricting `nfs-server.service` host-wide to `afpeer0` — see [Risks & Mitigations](#risks--mitigations) for LAN-NFS exclusivity).
    *   `sec=sys` relies on WireGuard host authentication plus `secure` privileged source ports.
*   **Client side (A):**
    *   `derive_unique_mount_path_for_export` (`peers/storage.rs:650`) derives `/mnt/af-peers/<link_segment>/<export_segment>` using `peer_links.name` verbatim when `validate_peer_mount_segment(&link.name).is_ok()` (otherwise falling back to `sanitize_mount_segment(&link.id, "peer", &link.id)`) and the exported folder's basename (appending `-<export_id_prefix>` or `export-<uuid>` on basename collisions). `af-runner` derives mount unit names in-process via Rust's `systemd_escape_path` (matching `systemd-escape --path`, tagged with `PEER_MANAGED_HEADER` to protect unmanaged host files) with `[Mount]` directives `Type=nfs4`, `Options=vers=4.2,soft,timeo=100,retrans=2,{ro|rw},nosuid,nodev,_netdev,x-systemd.requires=wg-quick@afpeer0.service`, `DirectoryMode=0755`, `TimeoutSec=30`, and `ForceUnmount=yes`.
    *   Media apps point at an interior user subfolder inside the mount (e.g., `/mnt/af-peers/<link_segment>/<export_segment>/library`; MediaFlow enforces the same interior-subfolder rule via `validate_media_library_path` in `intelligence/scan_cursor.rs:49`, rejecting bare mount roots). This provides defense-in-depth alongside leaf-mountpoint removal: whenever the mount is unmounted (including before mount start on reboot or if leaf cleanup fails), the interior subfolder is absent instead of an empty directory, and `StopMount` additionally removes the empty leaf mountpoint directory.
    *   Adding or removing a P7 media export or mount triggers a best-effort mount resync for active enabled transcode workers on that link (`transcode::resync_worker_transcode_mounts_if_active_best_effort`, `peers/storage.rs:1507,2030,2225`).
*   **Health gating:** Every 15 s, the health loop checks WireGuard peer liveness (`afpeer0` handshake age `> 180 s` or explicit peer removal stops `purpose == "media"` mounts on the first tick) and probes `<mount>/.af-peer-sentinel` (`ProbeSentinel`, default `5000 ms`, range `100..=15000 ms`; two consecutive failures stop the mount). Inside `af-runner`, `SentinelProbeCoordinator` (`peer_storage.rs:70,1154-1265`) enforces per-mount single-flight deduplication and a global concurrency cap (`MAX_CONCURRENT_SENTINEL_PROBES = 4`) on dedicated OS threads off Tokio's `spawn_blocking` pool so D-state NFS hangs cannot starve unrelated runner IPC. Once WireGuard is live/fresh and tunnel `GET /health` returns `200 OK`, `reconcile_mounts_for_healthy_link` (`peers/storage.rs:2467`) automatically restores `stopped` media mounts on the next tick via `StartMount` followed by an immediate `<mount>/.af-peer-sentinel` check (stopping again if the probe fails; mounts in `error` state must complete a verified stop before recovery). (Worker `transcode` and `transcode_bind` mounts are not gated by this loop.)
*   **Media-app safety:**
    *   **Jellyfin 12.4:** Relies on the missing interior library root (verification pending Server B acceptance; see [Open Questions](#open-questions)).
    *   **Plex:** `apply_plex_peer_mount_safety_best_effort` (`af-api/src/peers/storage.rs:3168`) and `apply_plex_safety_on_streaming_save_if_peer_mounts_exist` (`peers/storage.rs:3228`, wired in `routes/streaming.rs:153-155`) issue a best-effort `PUT /:/prefs?autoEmptyTrash=0` on mount creation and Plex saves whenever a Plex library already points under `/mnt/af-peers`, backed by operator verification guidance.
    *   **Emby and `*arr` apps (Sonarr/Radarr/Lidarr):** Cluster UI reminds admins to disable automatic removal of missing items.
*   **High-latency warning:** Cluster warns when link RTT exceeds `AF_PEER_RTT_WARN_MS` (default `25 ms`).

### Rust-native transcode dispatcher

**Crate:** `backend-rs/crates/af-transcode` builds one binary (`bin/af-transcode`, staged into server release bundles) with three modes:

| Mode | Invoked as | Runs where | Role |
| :--- | :--- | :--- | :--- |
| **shim** | `/usr/lib/aetherflow/transcode/ffmpeg <args...>` | Jellyfin server, as `jellyfin` | Replaces `ffmpeg` for Jellyfin via `JELLYFIN_FFMPEG`. |
| **worker** | `af-transcode worker` (`af-transcode-worker.service`, `User=jellyfin`, `Group=jellyfin`, `SupplementaryGroups=render video`, hardened with `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, `ProtectSystem=strict`, `ProtectHome=read-only`, `WorkingDirectory=/run/aetherflow-transcode-worker`, `DevicePolicy=closed` + DRM/NVIDIA `DeviceAllow=`, dynamic `30-aetherflow-transcode-paths.conf`) | Worker server | Listens on `/run/aetherflow-transcode-worker/worker.sock` (`0660` in `0750` runtime dir), enforces local-only protocol whitelist & clamped `cwd`, and spawns real `ffmpeg`. |
| **probe** | `af-transcode capabilities` | Any server | Prints real `ffmpeg` package version, encoders, `/dev/dri/renderD*` nodes (via `af-hardware::detect_render_nodes()`), and `worker_max_jobs` as JSON. |

The shim folder symlinks `ffprobe` to real `ffprobe`. Dedicated secret-free **`/etc/aetherflow/transcode.env`** (`0640 root:jellyfin`, `DEFAULT_TRANSCODE_ENV_FILE`, `af-transcode/src/config.rs:23`, `peer_transcode.rs:71,1087,2600`) is created idempotently by `af-runner` and loaded via `EnvironmentFile=-/etc/aetherflow/transcode.env` by all four consuming units (`af-transcode-worker.service`, `jellyfin.service.d/20-aetherflow-transcode.conf`, `aetherflow-api.service.d/20-aetherflow-transcode.conf`, and `aetherflow-runner.service.d/20-aetherflow-transcode.conf`) — `af-transcode-worker.service` **never** loads `/etc/aetherflow/aetherflow.env`. Real binary path defaults to `AF_TRANSCODE_REAL_FFMPEG=/usr/lib/jellyfin-ffmpeg/ffmpeg`. Additional runtime knobs live in `af-transcode/src/config.rs`, `af-runner/src/peer_transcode.rs`, and `af-api/src/peers/mod.rs`: `AETHERFLOW_TRANSCODE_BIN` (binary lookup override), `AF_SERVER_NAME` (host identity override), `AF_TRANSCODE_DISPATCHER_SOCK`, `AF_TRANSCODE_WORKER_SOCK`, `AF_TRANSCODE_WORKER_MAX_JOBS` (default `8`, clamp `1..=64`; configured in `/etc/aetherflow/transcode.env`, advertised on tunnel `GET /health` via `TranscodeCapabilities.worker_max_jobs` at `capabilities.rs:66`, and auto-clamped on controllers via `effective_worker_max_jobs` at `peers/transcode.rs:4104`), `AF_TRANSCODE_WORKER_SOCKET_MODE` (default `0660`, fail-closed on invalid/world-accessible/`<0600`), `AF_TRANSCODE_HANDSHAKE_TIMEOUT_MS` (default `2000`, valid `50..=30_000`), and `AF_TRANSCODE_SHIM_ACTIVE` (anti-recursion guard exiting `1`).

#### Job flow

1.  **Probe calls, recursion guard, & non-UTF-8 argv:** Before `exec`'ing local `ffmpeg`, the shim sets `AF_TRANSCODE_SHIM_ACTIVE`; if it is already set on entry, the shim refuses execution with exit code `1` to prevent fork-bombs. Probe invocations (`is_probe`, checking `STANDALONE_PROBE_FLAGS` in `af-transcode/src/argv.rs:168`—such as `-version`, `-encoders`, `-decoders`, `-hwaccels`, `-filters`, `-h`, `-buildconf`—or calls with no `-i` input) and invocations containing non-UTF-8 Unix arguments `exec` local `ffmpeg` directly.
2.  **Real jobs ask the dispatcher:** The shim connects to `/run/aetherflow-transcode/transcode.sock` (`0660 aetherflow:jellyfin` inside `0750` `/run/aetherflow-transcode` provisioned via `/etc/tmpfiles.d/aetherflow-transcode.conf`) within a 2,000 ms handshake deadline (`RECOMMENDED_DISPATCHER_REMOTE_START_TIMEOUT = 1,500 ms`). It sends `Start { args, cwd, env_subset }`, where `env_subset` is filtered to `ALLOWED_ENV_KEYS` (`TMPDIR`, `TZ`, `LANG`, `LC_ALL`, `LC_CTYPE`, `FONTCONFIG_FILE`, `FONTCONFIG_PATH`); the worker preserves only its own `WORKER_BASELINE_ENV_KEYS` (`PATH`, `HOME`, `USER`, `LOGNAME`, `XDG_RUNTIME_DIR`, `LIBVA_DRIVER_NAME`, `LIBVA_DRIVERS_PATH`, `MESA_SHADER_CACHE_DIR`).
3.  **Dispatcher target selection & network-input bypass (`af-api/src/peers/transcode.rs`):**
    1.  If `argv::has_network_input(&args)` (`argv.rs:1373`) or `argv::has_disallowed_protocol_whitelist(&args)` is true, the dispatcher immediately returns `Frame::RunLocal` (`peers/transcode.rs:4554`) without contacting any remote worker so `PrivateNetwork=yes` workers never handle network streams.
    2.  `argv::required_capability(args)` returns `Capability { hwaccel, required_hwaccels, encoder, filters, render_nodes }` (5 fields, `af-transcode/src/argv.rs:52-63`; primary `HwAccel` rank order for mixed pipelines is `Qsv > Cuda > Vaapi > Vulkan > OpenCl > Drm`, `argv.rs:9-42`).
    3.  Eligible workers have an active link with `"transcode"` capability, held `transcoding: write` grant, healthy status outside 60 s cooldown, `parity_ok = true`, identical `jellyfin-ffmpeg` package version, required encoder/hwaccel/compatible vendor DRM render node (for hardware jobs), and `active_jobs < effective_worker_max_jobs(worker.max_jobs, remote_caps)` (`min(worker.max_jobs, cap.worker_max_jobs)`, `peers/transcode.rs:448-454,4104`).
    4.  Weighted random selection without replacement picks a worker, or replies `RunLocal` if none is eligible.
4.  **Remote run & worker-side confinement:** The dispatcher opens a custom RFC 6455 WebSocket to `/peer/v1/transcode/jobs` on the worker's tunnel listener with link + grant tokens, and relays frames between the shim socket and the WebSocket. The worker's `af-api` (granted socket access via `/etc/systemd/system/aetherflow-api.service.d/20-aetherflow-transcode.conf` adding `EnvironmentFile=-/etc/aetherflow/transcode.env`, `SupplementaryGroups=jellyfin`, and `ReadWritePaths=-/run/aetherflow-transcode -/run/aetherflow-transcode-worker`) relays to `worker.sock`. `af-transcode worker` independently validates arguments via `argv::validate_worker_args` (`worker.rs:588`, rejecting network inputs or widened whitelists), injects `-protocol_whitelist file,pipe,fd,crypto,data,subfile` (`WORKER_LOCAL_PROTOCOL_WHITELIST`, `argv.rs:88`, `worker.rs:684`), clamps child `cwd` via `config::resolve_worker_child_cwd` (`config.rs:658`), selects the target render node on multi-GPU workers via `capabilities::select_render_node` (vendor-aware in `af_hardware::detect_render_nodes()` order: QSV prefers Intel, VA-API prefers Intel/AMD excluding NVIDIA, CUDA prefers NVIDIA, `capabilities.rs:117`), and spawns real `ffmpeg` with only `/dev/dri/renderD*` remapped to that node.
5.  **Stream protocol (`af-transcode::protocol`):**
    *   Length-prefixed (4-byte BE length, `MAX_FRAME_BYTES = 1 MiB` enforced before deserialization) **`wincode = "0.6.3"`** frames (bincode v1 LE fixed-int layout, chosen because `cargo deny` rejects unmaintained `bincode` under `RUSTSEC-2025-0141`; rejects trailing bytes and enforces `MAX_START_ARGS = 512`, `MAX_START_ARG_BYTES = 64 KiB`):
        *   `0: Start(StartRequest)`, `1: RunLocal`, `2: Started`, `3: Stdin(Vec<u8>)`, `4: StdinEof`, `5: Stdout(Vec<u8>)`, `6: Stderr(Vec<u8>)`, `7: Signal(SignalKind)`, `8: Exit(i32)`, `9: Error { kind: ErrorKind, message: String }`.
    *   **No-duplicate-encode boundary:** On the shim→dispatcher Unix socket (`shim.rs:273-278,356-389`), local fallback runs on errors before all bytes of `Frame::Start` are written. On the dispatcher→worker WebSocket (`peers/transcode.rs:1728-1826`), failures before the **first byte** of `Start` is written (`WsWriteError::BeforeAnyBytesSent`) mark the worker unhealthy for 60 s and retry another worker or return `RunLocal`; once the first byte of `Start` is sent, a lost acknowledgment or dropped stream exits non-zero without starting a duplicate local encode so Jellyfin's retry path handles recovery.
    *   **Backpressure, EOF, signals, and hard kills:** Bounded 64-frame channels provide backpressure. `StdinEof` closes remote stdin; `SIGTERM`/`SIGINT` forward as `Signal`. If Jellyfin `SIGKILL`s the shim, the dispatcher detects socket closure without `Exit` and sends `Signal(Kill)`, and the worker kills its `ffmpeg` process group on unexpected stream close.
6.  **Path parity orchestration (transcode dirs + input media `BindMedia`):**
    *   **Transcode & cache directories:** When an enabled worker is saved (`PUT /api/v1/admin/peers/transcode`), Server A inspects local Jellyfin paths (`InspectJellyfinPaths`), exports `<TranscodingTempPath>` (default `/var/cache/jellyfin/transcodes`), `/var/cache/jellyfin/af-tmp`, and `/var/cache/jellyfin` via `/etc/exports.d/aetherflow-peer-<link_id>-transcode.exports` (`ExportTranscodeDirs`, options `rw,all_squash,anonuid=<jellyfin_uid>,anongid=<jellyfin_gid>,secure,no_subtree_check`) with `st_dev`-guarded pruning of nested `/var/cache/jellyfin` child exports sharing the same filesystem (`prune_same_device_descendant_exports`, `peer_transcode.rs:713,4352-4378`, preserving separate-filesystem `<TranscodingTempPath>` exports), and calls Server B's `POST /peer/v1/transcode/mounts` (`sync`, `TRANSCODE_MOUNT_SYNC_TIMEOUT = 180 s > 150 s` runner timeout, `peers/transcode.rs:118`). Server B enforces an explicit worker Jellyfin cache/transcode allowlist in both `af-api` (`peers/transcode.rs:2718-2755`) and `af-runner` before mounting via `MountTranscodeDirs` (`purpose = "transcode"`).
    *   **Input-media path parity (`BindMedia`) & calling-link confinement:** Because `af-transcode worker` passes Jellyfin's input file paths verbatim to remote `ffmpeg`, the two hosts coordinate media bind aliases across both storage directions (`peers/transcode.rs:2916-3640`, `peer_transcode.rs:4865-5020`), using per-unit runner locks (releasing the short config lock before `systemctl` calls) and dynamically syncing `af-transcode-worker.service.d/30-aetherflow-transcode-paths.conf` (`peer_transcode.rs:2832`):
        *   **B-holds-media direction (requested by A):** Server A inspects its own `peer_mounts` (`purpose == "media"`) and sends `media_binds` entries (`TranscodeMediaBindSpec { from, to, writable? }`, `#[serde(deny_unknown_fields)]`, `peers/transcode.rs:2532-2545`) in `POST /peer/v1/transcode/mounts`; Server B validates each requested bind against B's own `peer_exports` rows and passes `BindMedia.calling_link_segment` (`peer_transcode.rs:187,4865-4907`) enforcing exact `/mnt/af-peers/<calling-link-segment>/` component confinement (rejecting prefix overlaps and cross-link shadowing) before bind-mounting `<B's local export path>` → `/mnt/af-peers/<B>/<export>` (`purpose = "transcode_bind"`).
        *   **A-holds-media direction (auto-added locally by B):** Server B inspects its own `peer_mounts` (`purpose == "media"`) on that link and appends local bind aliases `/mnt/af-peers/<A>/<export>` → `<A's local export path>` (`purpose = "transcode_bind"`), enforcing the worker media-root allowlist (`validate_bind_media_target_allowlist`, `peer_transcode.rs:2933-2970`), refusing non-empty local target directories (`dir_has_entries`, `peer_transcode.rs:2972,4958-4995`), and attaching conditional `BindsTo=`/`After=` on the backing `/mnt/af-peers/*` NFS `.mount` unit (`peer_transcode.rs:1278,4919`) so media-mount stops automatically stop the bind unit.
        *   **Atomic rollback & Storage auto-resync:** Both `MountTranscodeDirs` (`peer_transcode.rs:4513`) and `handle_tunnel_transcode_mounts_inner` roll back newly applied transcode/bind mounts on partial failure and wrap `peer_mounts` DB replacement in a SQLite transaction. Adding or removing P7 Storage exports/mounts automatically triggers a best-effort resync (`AUTO_RESYNC_MOUNT_TIMEOUT = 15 s`, `peers/transcode.rs:119`). If Jellyfin plays a local file whose parent folder was never shared via **Storage**, remote `ffmpeg` cannot open that input path and exits non-zero.
    *   **Parity test:** Saving an enabled worker whose prior parity test has not passed triggers automatic path parity (deduplicated so it runs once—not twice—if the same request also explicitly sets `run_parity_test_link_id` for that link, `peers/transcode.rs:6876-6879`), and clicking **Run parity test** triggers it explicitly. The worker encodes a 1-second (10-frame) software `libx264` clip within a **5-second** timeout (`DEFAULT_PARITY_TEST_TIMEOUT`, `peers/transcode.rs:115`) into `<TranscodingTempPath>`; in production, root `af-runner`'s `PeerTranscodeRequest::CleanupParityFile` performs both the 64-byte local read verification and unlink of `.af-parity-<32hex>.ts` (`peer_transcode.rs:5350`) before setting `parity_ok = true`. (It validates transcode path/socket parity, not GPU hardware encoding or media bind mounts.)
7.  **Failure handling:**

    | Failure | Behavior |
    | :--- | :--- |
    | Network-protocol input or non-local `-protocol_whitelist` | Dispatcher immediately returns `Frame::RunLocal` (`peers/transcode.rs:4554`); worker independently rejects network inputs (`worker.rs:588`). |
    | Worker unreachable before first byte of `Start` | Mark worker unhealthy for 60 s; try another eligible worker or return `RunLocal`. |
    | Timeout / stream drop / `Frame::Error` after first byte of `Start` | Shim exits non-zero (no duplicate local encode); mark worker unhealthy for 60 s; Jellyfin retries. |
    | Remote `ffmpeg` exits non-zero (`Frame::Exit(non_zero)`, e.g. unshared local input path) | Shim exits with that non-zero code (no duplicate local encode); worker is **not** marked unhealthy (`mark_unhealthy = false`, `peers/transcode.rs:4793,5059`). |
    | Link or grant revoked | Active streams terminate (`Signal(Kill)`); subsequent jobs run locally. |
    | Dispatcher down | Shim falls back to local `ffmpeg`. |
    | Jellyfin hard-kills shim (`SIGKILL`) | Dispatcher detects socket close without `Exit` and sends `Signal(Kill)`; worker kills `ffmpeg` process group. |

8.  **Recording:** Each job writes a row to `transcode_jobs` (`id`, `link_id`, `started_at`, `ended_at`, `exit_code`, `request_id`, `ran_locally`), pruned automatically after 7 days in `af-api/src/main.rs:317`'s 15-minute maintenance loop.

#### Keeping `jellyfin-ffmpeg` aligned (no apt version pinning)

All servers remain on the same Debian apt state for `jellyfin` and `jellyfin-ffmpeg`:

*   **Reporting:** `capabilities` reads installed package versions via `dpkg-query -W -f=${Status}\t${Package}\t${Version}\n jellyfin-ffmpeg*` (`af-transcode/src/capabilities.rs:82,220`, filtering `install ok installed`) alongside `ffmpeg -version` and `worker_max_jobs`. Tunnel `GET /health` and the 15-second peer health loop (when checkable links exist) refresh capabilities on a 60 s TTL (and startup/health-tick reconciliation refreshes on Jellyfin controllers where `dropin_enabled && shim_installed`). Local Marketplace updates to `jellyfin`/`jellyfin-ffmpeg` invalidate the cache (`af-api/src/routes/marketplace/job_runner.rs:967-971`).
*   **When versions differ:** During the 15-second peer health loop, `handle_remote_health_transcode_caps` (`af-api/src/peers/transcode.rs:967-1017`) caches the peer's capabilities, compares metadata against the existing `transcode_workers` row to skip no-op SQLite upserts, and upserts only on changes (worker eligibility is computed dynamically on dispatch/UI read, so mismatched workers become ineligible and jobs run locally), displays e.g. *"jellyfin-ffmpeg differs: seedbox-1 8.1.3-1-trixie vs media-2 8.1.2-1-trixie"* in **Cluster**, and emits a deduplicated in-app notification when `worker_enabled == true`.
*   **Align button:** **Update to match** invokes `POST /api/v1/admin/packages/jellyfin/update` (local or proxied to the older server), updating Jellyfin there. Both `has_updates_write_grant` (`peers/transcode.rs:5812`) / Cluster UI (`tabs/cluster/transcode.rs:395`) and backend scope checks (`peers/scopes.rs:1493-1531`, `routes/marketplace/handlers.rs:188`) accept `updates: write` or `marketplace: write` for `jellyfin`/`jellyfin-ffmpeg*` (while non-Jellyfin packages require `marketplace: write`).

#### Enabling and disabling distributed transcoding

**Enabling a transcode worker (Server B):** Install matching Jellyfin 12.4 and `jellyfin-ffmpeg` packages so the `jellyfin` Linux user/group exists, stop and disable `jellyfin.service` (`sudo systemctl disable --now jellyfin.service`), grant Server A `transcoding: write`, and toggle `worker_service_enabled: true` via `PUT /api/v1/admin/peers/transcode`. `af-runner` runs `InstallWorkerUnit` (provisioning `/etc/aetherflow/transcode.env`, writing hardened `/etc/systemd/system/af-transcode-worker.service`, `/etc/systemd/system/aetherflow-api.service.d/20-aetherflow-transcode.conf`, and `/etc/systemd/system/aetherflow-runner.service.d/20-aetherflow-transcode.conf`) and dispatches deterministic debounced `ScheduleApiRestart` (`systemd-run --unit=aetherflow-transcode-api-restart --on-active=1s`, `peer_transcode.rs:77,5215`, returning `api_restart_scheduled: true`) if the API drop-in was newly written **or** `!process_has_gid(paths.jellyfin_gid)` (`peers/transcode.rs:6788`). Operators must wait a few seconds for that 1-second API restart to finish before saving workers or running parity so `aetherflow-api` picks up `SupplementaryGroups=jellyfin` and `ReadWritePaths`.

**Enabling transcoding on the Jellyfin server (Server A):** On upgraded hosts whose `10-aetherflow-sandbox.conf` predates directory-level `-/run/aetherflow-transcode`, run `sudo af sandbox apply jellyfin` once first (otherwise `ProtectSystem=strict` blocks `jellyfin` on `transcode.sock` or pins it to an unlinked inode across API restarts). Then `PUT /api/v1/admin/peers/transcode` (`enabled: true`) runs `af-runner`:

1.  `EnsureDispatcherDir`: provisions `/etc/aetherflow/transcode.env` (`0640 root:jellyfin`), `/run/aetherflow-transcode`, `/etc/tmpfiles.d/aetherflow-transcode.conf`, `/etc/systemd/system/aetherflow-api.service.d/20-aetherflow-transcode.conf`, and `/etc/systemd/system/aetherflow-runner.service.d/20-aetherflow-transcode.conf`.
2.  `InstallShim`: installs `/usr/lib/aetherflow/transcode/ffmpeg` and symlinks `ffprobe` to `/usr/lib/jellyfin-ffmpeg/ffprobe`. (Subsequent AetherFlow self-updates in `af-release/src/health.rs:97,840,983` and `deploy/release-manager.sh:2044-2107` automatically refresh an existing shim atomically—dormant if absent, refusing symlinks—and restart `af-transcode-worker.service` only if active.)
3.  `EnableJellyfin`: creates `/var/cache/jellyfin/af-tmp` (`jellyfin:jellyfin`), writes `/etc/systemd/system/jellyfin.service.d/20-aetherflow-transcode.conf` (`EnvironmentFile=-/etc/aetherflow/transcode.env`, `JELLYFIN_FFMPEG`, and `TMPDIR`), runs `daemon-reload`, and restarts `jellyfin.service` without editing `10-aetherflow-sandbox.conf`.
4.  If Jellyfin is configured in `streaming_servers`, performs one immediate probe against `/System/Configuration/encoding` and `/System/Info` (`EncoderAppPathDisplay`, `EncoderAppPath`, `EncoderPath`, `FfmpegPath`, plus camelCase fallbacks), retrying up to 5 times at 1-second intervals (up to 6 attempts total) only while Jellyfin is not yet reachable (`NotConfiguredOrUnreachable`). Rolls back (`DisableJellyfin`) on both path mismatch (`Reported`) and `ReachableMissingPath`; if still `NotConfiguredOrUnreachable` after ~5 s (unconfigured or slow cold startup), skips automated rollback silently.
5.  If `aetherflow-api.service.d/20-aetherflow-transcode.conf` was newly written, live `ProtectSystem=strict` blocks socket binding, **or** `!process_has_gid(paths.jellyfin_gid)` (`peers/transcode.rs:6560`), dispatches deterministic debounced `ScheduleApiRestart` (`systemd-run --unit=aetherflow-transcode-api-restart --on-active=1s`) **before** returning the HTTP response (setting `api_restart_scheduled: true` and `resp.enabled = true` when `jellyfin_dropin_enabled` is true even though `dispatcher_active` stays `false` until restart completes, `L6979`). Wait a few seconds for the 1-second restart to complete.
6.  **Share media & save enabled workers:** Ensure shared media libraries are exported and mounted via **Cluster → Storage** first so `BindMedia` establishes input-media path parity, then save each enabled worker (`PUT /api/v1/admin/peers/transcode { workers: [...] }`). Saving an enabled worker runs `PeerStorageRequest::EnsurePackages` on both hosts if NFS packages are not yet installed, exports transcode directories (`st_dev`-pruned), calls `POST /peer/v1/transcode/mounts`, and triggers the initial path-parity test (`parity_ok = true`).

**Disabling distributed transcoding & reboot recovery:** Toggling `enabled: false` on Server A (`peers/transcode.rs:6603-6725`) stops the dispatcher, runs `DisableJellyfin` (removing `jellyfin.service.d/20-aetherflow-transcode.conf`, reloading systemd, and restarting Jellyfin back onto `/usr/lib/jellyfin-ffmpeg/ffmpeg`), removes controller transcode NFS exports (`RemoveTranscodeExports`) for all configured workers, sends best-effort `TunnelTranscodeMountRequest::Teardown` to enabled workers, and marks those worker rows disabled. Toggling `worker_service_enabled: false` on Server B (`peers/transcode.rs:6729-6765`) tears down all local `transcode_bind` and `transcode` mounts (`cleanup_worker_transcode_mounts_for_link`) **before** calling `RemoveWorkerUnit`. Individual worker disable (`enabled: false` per worker) and link revocation (`peers/links.rs:657`) also tear down transcode exports and mounts cleanly. Because controller-holds-media `BindMedia` units attach `BindsTo=`/`After=` on their backing `/mnt/af-peers/*` NFS `.mount` unit (`peer_transcode.rs:1278,4919`), systemd automatically stops the bind unit whenever the backing media mount stops; after a worker reboot or media-mount outage, operators wait for `/mnt/af-peers/*` media mounts to auto-recover and re-save the worker on Server A.

### Data model (migrations 25–27 in `af-db`)

#### Migration 25: "Peer clustering" (Phase P0)

```sql
CREATE TABLE IF NOT EXISTS peer_identity (id INTEGER PRIMARY KEY CHECK (id = 1), wg_pubkey TEXT NOT NULL,
  tunnel_ip TEXT NOT NULL, wg_port INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS peer_links (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, wg_pubkey TEXT NOT NULL UNIQUE,
  tunnel_ip TEXT NOT NULL UNIQUE, endpoint TEXT NOT NULL, wg_port INTEGER NOT NULL, state TEXT NOT NULL,
  peer_version TEXT, peer_protocol INTEGER, capabilities TEXT, rtt_ms REAL, last_ok_at TEXT,
  last_error TEXT, consecutive_failures INTEGER NOT NULL DEFAULT 0, inbound_token_hash TEXT,
  pending_attempt_id TEXT, pending_expires_at INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS peer_grants (id TEXT PRIMARY KEY, link_id TEXT NOT NULL REFERENCES peer_links(id) ON DELETE CASCADE,
  run_as_user_id INTEGER NOT NULL, access TEXT NOT NULL /* JSON {area: "none"|"read"|"write"} */,
  token_hash TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE IF NOT EXISTS peer_pairing_windows (id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL,
  consumed_at INTEGER);
CREATE TABLE IF NOT EXISTS peer_pairing_attempts (id TEXT PRIMARY KEY, window_id TEXT, remote_name TEXT, remote_pubkey TEXT,
  remote_tunnel_ip TEXT, remote_endpoint TEXT, source_ip TEXT, status TEXT NOT NULL, error_code TEXT,
  expires_at INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS peer_exports (id TEXT PRIMARY KEY, link_id TEXT NOT NULL REFERENCES peer_links(id) ON DELETE CASCADE,
  path TEXT NOT NULL, writable INTEGER NOT NULL DEFAULT 0, squash_uid INTEGER, squash_gid INTEGER, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS peer_mounts (id TEXT PRIMARY KEY, link_id TEXT NOT NULL REFERENCES peer_links(id) ON DELETE CASCADE,
  remote_path TEXT NOT NULL, mount_path TEXT NOT NULL UNIQUE, unit_name TEXT NOT NULL, writable INTEGER NOT NULL DEFAULT 0,
  purpose TEXT NOT NULL /* 'media' | 'transcode' | 'transcode_bind' */, state TEXT NOT NULL, last_error TEXT);
CREATE TABLE IF NOT EXISTS transcode_workers (link_id TEXT PRIMARY KEY REFERENCES peer_links(id) ON DELETE CASCADE,
  enabled INTEGER NOT NULL DEFAULT 0, weight INTEGER NOT NULL DEFAULT 1, max_jobs INTEGER NOT NULL DEFAULT 2,
  ffmpeg_version TEXT, encoders TEXT, render_node TEXT, parity_ok INTEGER NOT NULL DEFAULT 0, parity_error TEXT);
CREATE TABLE IF NOT EXISTS transcode_jobs (id TEXT PRIMARY KEY, link_id TEXT, started_at TEXT NOT NULL, ended_at TEXT,
  exit_code INTEGER, request_id TEXT, ran_locally INTEGER NOT NULL);
ALTER TABLE users ADD COLUMN account_type TEXT NOT NULL DEFAULT 'human';
```

*(Note: `transcode_workers.render_node` stores the primary selected DRM render node persisted in SQLite, while runtime health capabilities carry the full `render_nodes` list. Host-level transcode flags `enabled` and `worker_service_enabled` are **not** stored in SQLite; `GET /api/v1/admin/peers/transcode` derives them dynamically from live host/systemd state via `InspectJellyfinPaths` and `dispatcher_active`, `peers/transcode.rs:5738`.)*

#### Migration 26: "Remove legacy master/worker clustering" (Phase P4)

```sql
DROP TABLE IF EXISTS cluster_commands;
DROP TABLE IF EXISTS cluster_enrollment_tokens;
DROP TABLE IF EXISTS cluster_nodes;
```

#### Migration 27: "Peer grant direction metadata" (Phase P5)

Implemented in `af-db/src/lib.rs:797-811,816`, with SQL constant `PEER_GRANT_METADATA_MIGRATION_27_SQL` (`af-db/src/peers.rs:106-132`) and runtime repair helper `ensure_peer_grant_schema_invariants` (`af-db/src/peers.rs:136-163`):

```sql
CREATE TABLE IF NOT EXISTS peer_received_grants (
  link_id TEXT PRIMARY KEY REFERENCES peer_links(id) ON DELETE CASCADE,
  grant_id TEXT NOT NULL,
  run_as_user_id INTEGER NOT NULL,
  access TEXT NOT NULL,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL,
  generation INTEGER NOT NULL DEFAULT 0,
  revoked_at TEXT,
  credential_id TEXT,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS peer_received_grant_cleanups (
  link_id TEXT NOT NULL REFERENCES peer_links(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL,
  generation INTEGER NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (link_id, credential_id)
);
CREATE TABLE IF NOT EXISTS peer_grant_epochs (
  link_id TEXT PRIMARY KEY REFERENCES peer_links(id) ON DELETE CASCADE,
  issuer_generation INTEGER NOT NULL DEFAULT 0,
  active_op_id TEXT,
  updated_at TEXT NOT NULL
);
```

*(Note: `peer_grant_epochs.active_op_id` serializes concurrent in-flight grant rotations/revocations per link.)*

At startup, `init_db()` runs `peers::ensure_peer_grant_schema_invariants(&conn)` (guaranteeing additive `credential_id` and `peer_received_grant_cleanups` on pre-release test DBs) and `peers::start()` runs `grants::cleanup_pending_received_grant_credentials` to sweep any superseded credential files left after an interrupted rotation.

#### Runner-managed secret files

Raw secrets live in runner-managed files (staged atomically via root-only `/etc/aetherflow/peers/.staging`):

*   WireGuard private key: `/etc/aetherflow/peers/afpeer0.key` (`0600`)
*   Held link token: `/etc/aetherflow/peers/tokens/<link_id>.token` (`0640`, group `aetherflow`)
*   Held grant tokens: `/etc/aetherflow/peers/tokens/<credential_id>.grant.token` (`0640`, group `aetherflow`); legacy rows without `credential_id` fall back to `<link_id>`.
*   Pending issuer tokens for handshake retries: `/etc/aetherflow/peers/pending/link-<link_id>.token` (or `link-<sha256-48hex>.token` if `link_id.len() > 59 || !is_valid_credential_id(link_id)`; `0600`, root-only), deleted after link activation/acknowledgment, cancellation, or expiry.

### Wire and IPC contract summary

Admin and public OpenAPI routes live in [config/openapi-v1.yaml](../../config/openapi-v1.yaml) and [docs/API.md](../API.md#8-peer-clustering) (`/peer/v1/*` tunnel endpoints are internal and omitted from OpenAPI). `deny_unknown_fields` is enforced on admin request DTOs, `PublicPairingRequest`/`PublicPairingResponse`, `HelloRequest`, `TunnelTranscodeMountRequest`, and `TranscodeMediaBindSpec`; tunnel grant payloads (`GrantTokenDeliveryPayload` / `GrantRevokePayload` / `GrantOfferPayload`) ignore unknown fields, and `POST /peer/v1/revoke-notice` does not parse a typed request body. All peer endpoints standardize `Bytes`/`Json` extractor rejections into `PeerError` JSON (`{code, server, step, message, action, request_id?}`, `peers/errors.rs:76-84,625-707`):

*   **Admin & public pairing/link routes (`/api/v1/admin/peers*`, `/api/v1/peer-pairing/request`):**
    *   `GET /api/v1/admin/peers` → `200` `{ identity: { wg_pubkey, tunnel_ip, wg_port, listen_port, created_at } | null, peer_protocol, capabilities, rtt_warn_ms, peers: PeerLinkView[], pairing_windows, pairing_attempts: [{ id, window_id, remote_name, remote_pubkey, remote_tunnel_ip, remote_endpoint, source_ip, status, error_code, comparison_code, expires_at, created_at }], detected_endpoints: [{ interface, address, family, recommended }] }` (`PeerLinkView` includes `grants: { inbound, outbound }`, `exports`, `mounts` [all `peer_mounts` rows including `transcode`/`transcode_bind`], `transcode_worker`, `compatibility`, `missing_capabilities`, `high_latency`).
    *   `POST /pairing-window` `{ endpoint?, https_url?, wg_port? }` → `201` window + `afpair1:...` string; `DELETE /pairing-window` → `200 { "closed": <usize> }`; `DELETE /pairing-window/{id}` → `200 { "closed": true, "window_id": "<id>" }` (or `404 PEER_NOT_FOUND`).
    *   `POST /pair` `{ pairing_string, name?, endpoint?, local_name? }` → `201` pending attempt + 6-digit code; `POST /pairing/{attempt}/confirm` (optional `{ name? }`, `ConfirmPairingReq`) → `200 { "link_id", "name", "state", "attempt_id", "confirmed": true, "rtt_ms"? }`; `DELETE /pairing/{attempt}` → `200 { "cancelled": true, "attempt_id": "<id>" }` (note British spelling `cancelled`, `peers/pairing.rs:5652`).
    *   `POST /api/v1/peer-pairing/request` (`4 KiB` cap, `PublicPairingRequest { code, name, wg_pubkey, endpoint, wg_port, tunnel_ip, version, peer_protocol?, timestamp }`) → `200` `PublicPairingResponse { attempt_id, comparison_code, expires_at, server_name, version, peer_protocol }`.
    *   `PUT /{id}/endpoint` `{ endpoint, wg_port? }` → `200`; `DELETE /{id}` → `200 { revoked, link_id, name, notice_delivered }`.
*   **Admin grants, storage, & transcode routes:**
    *   `GET/PUT/DELETE /{id}/grant` (`8 KiB` body cap; `PUT` body `{ access: AccessMap }`, rejecting all-`none` → `200` `LinkGrantsView { inbound, outbound }`); `POST /{id}/grant-offer` (`8 KiB` body cap; accepts empty body or `{}` only — rejects non-empty objects with `400 INVALID_REQUEST` → `200 { "sent": true }`).
    *   `GET/POST/DELETE /{id}/exports` (`8 KiB` body cap; `POST` `{ path, writable? }` → `201 Created { export }`, `DELETE` `{ export_id }` → `204 No Content`) & `/{id}/mounts` (`8 KiB` body cap; `POST` `{ export_id, writable? }` → `201 Created { mount }`, `DELETE` `{ mount_id }` → `204 No Content`; `GET` returns `purpose == "media"` mounts + `available_exports` / `exports_error`).
    *   `GET/PUT /api/v1/admin/peers/transcode` (`32 KiB` body cap; `PUT` `UpdateTranscodeConfigReq { enabled?, worker_service_enabled?, workers?: [{ link_id, enabled, weight, max_jobs }], run_parity_test_link_id? }` → `200` `TranscodeConfigResponse { enabled, worker_service_enabled, worker_service_active, dispatcher_active, dispatcher_socket, shim_installed, shim_path, jellyfin_dropin_enabled, jellyfin_reported_ffmpeg, api_restart_scheduled, local, workers, recent_jobs, parity_result? }`; each worker entry exposes `worker_max_jobs?`, `effective_max_jobs`, and `has_updates_write_grant` [true for `updates: write || marketplace: write`], `peers/transcode.rs:5601-5609,5812`).
*   **Tunnel routes:**
    *   **`internal_routes` (`8 KiB` `DefaultBodyLimit` layer, `peers/listener.rs:1044-1075`):**
        *   `GET /health` → `{ status, version, peer_protocol, capabilities, transcode, inbound_grant_generation }` (`peers/listener.rs:410-458`; `transcode` includes `worker_max_jobs?`, while public `GET /health` unconditionally returns `"transcode": null`) & `GET /peer/v1/link` → `{ link_id, name, state, version, peer_protocol, capabilities }`.
        *   `POST /peer/v1/hello` (`HelloRequest { phase: "bootstrap" | "acknowledge", attempt_id, wg_pubkey, tunnel_ip?, version, peer_protocol, capabilities, link_token? }` → `HelloResponse { phase, attempt_id, acknowledged, state, wg_pubkey, version, peer_protocol, capabilities, link_token? }`, `peers/pairing.rs:1088-1135`) & `POST /peer/v1/revoke-notice` (sender body `{ reason, server }` → `{ acknowledged: true, state: "revoked", message }`, `peers/links.rs:1393-1433`).
        *   `POST /peer/v1/grant-token` (`GrantTokenDeliveryPayload { grant_id, run_as_user_id, access, created_by, created_at, generation, token }` → `GrantTokenDeliveryAck { accepted, grant_id, generation }`), `POST /peer/v1/grant-revoke` (`{ generation }` → `{ revoked: bool, generation: i64 }`, `peers/grants.rs:2412`), & `POST /peer/v1/grant-offer` (`{ from_server?, requested_by? }`, server-constructed → `GrantOfferAck { received: true }`, `peers/grants.rs:105`).
        *   `GET /peer/v1/exports` (`{ exports }`) & `POST /peer/v1/transcode/mounts` (`#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]`: `sync { transcode_paths, media_binds?: TranscodeMediaBindSpec[] }` where `TranscodeMediaBindSpec { from, to, writable? }` → `{ status: "synced", transcode_paths, media_binds }` | `teardown` → `{ status: "removed", removed_transcode_mounts, removed_media_binds }`, `MAX_TUNNEL_TRANSCODE_PATHS = 32`, `peers/transcode.rs:2532-2545,3025,3639`).
    *   **Transcode WebSocket (`transcode_ws_routes`, mounted outside the 8 KiB layer, `peers/listener.rs:1077-1091`):** `GET /peer/v1/transcode/jobs` (WS relaying `wincode` frames bounded by `MAX_FRAME_BYTES = 1 MiB`).
*   **Runner IPC endpoints (`/v1/peer-network`, `/v1/peer-storage`, `/v1/peer-transcode`):** Requests use tagged JSON (`#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]`) and propagate `X-Request-ID` over `/run/aetherflow/runner.sock` via `af_runner::with_runner_request_id` (`af-runner/src/lib.rs:462-480`, echoed on runner responses and emitted in runner logs). All three HTTP responses return the `af_models::RunnerResponse { success: bool, output: String, error: String }` envelope (`af-runner/src/runner_client.rs:993,1105,1221`) with typed JSON serialized inside `RunnerResponse.output` and typed error codes in the `x-af-peer-error-code` response header (`invalid_input`, `busy`, `not_found`, `conflict`, `runtime`, plus `peer_not_found`/`peer_already_exists`/`tunnel_ip_conflict` on `/v1/peer-network` and `unmanaged_file` on `/v1/peer-transcode`). **Only** `PeerTranscodeResponse` (`peer_transcode.rs:246`, with untagged fallback) uses `#[serde(tag = "kind", rename_all = "snake_case")]`; `PeerNetworkResponse` (`peer_network.rs:508`) and `PeerStorageResponse` (`peer_storage.rs:304`) serialize raw untagged inner structs into `RunnerResponse.output` and decode by originating request variant. Per-endpoint action field names differ under `deny_unknown_fields`:
    *   `/v1/peer-network` (`peer_network.rs:215-259`): `ensure_identity { tunnel_ip?, avoid_tunnel_ips?, wg_port?, tunnel_cidr? }` → `PeerIdentityResponse`; `add_peer { pubkey, endpoint, port, tunnel_ip }` / `remove_peer { pubkey }` / `set_endpoint { pubkey, endpoint, port? }` → `PeerMutationResponse`; `status {}` → `PeerStatusResponse`; `ensure_packages {}` → `PeerEnsurePackagesResponse`; `write_credential { slot, id, value }` / `read_credential { slot, id }` / `delete_credential { slot, id }` / `delete_link_credentials { link_id }` → credential responses.
    *   `/v1/peer-storage` (`peer_storage.rs:163-218`): `ensure_packages {}` → `PeerStorageEnsurePackagesResponse`; `configure_nfsd { tunnel_ip }` / `write_exports { link, tunnel_ip, entries }` / `remove_exports { link }` → `PeerStorageMutationResponse`; `ensure_sentinel { path, require_non_root_owner? }` → `PeerSentinelInfo`; `probe_sentinel { mount_path, timeout_ms? }` → `PeerSentinelProbeResponse`; `write_mount { link, tunnel_ip, remote_path, mount_path, writable? }` / `write_bind_mount { link, source_path, mount_path, writable? }` / `remove_mount { mount_path }` / `start_mount { mount_path }` / `stop_mount { mount_path }` / `mount_status { mount_path }` → `PeerMountStateResponse`.
    *   `/v1/peer-transcode` (`peer_transcode.rs:154-203,246`): `inspect_jellyfin_paths {}` → `JellyfinTranscodePaths`; `ensure_dispatcher_dir {}` / `install_shim {}` / `enable_jellyfin {}` / `disable_jellyfin {}` / `install_worker_unit {}` / `remove_worker_unit {}` / `export_transcode_dirs { link_id, tunnel_ip, uid, gid, paths }` / `remove_transcode_exports { link_id }` / `mount_transcode_dirs { link_id, tunnel_ip, paths }` / `remove_transcode_mounts { link_id, paths }` / `bind_media { from, to, writable?, calling_link_segment? }` / `remove_bind_media { to }` / `schedule_api_restart {}` → `TranscodeMutationReport`; `cleanup_parity_file { dir, file_name }` → `ParityFileCleanupReport`.

## Alternatives Considered

### Alternative A: Separate dashboards plus single sign-on and a server switcher

*   **Pros:** Lowest implementation cost; avoids cross-server proxy trust paths.
*   **Cons:** Requires separate browser sessions, fragments audit and monitoring workflows across browser tabs, and provides no unified management surface or cross-server storage/transcoding coordination from `/?tab=cluster`.
*   **Technical Reason Not Chosen:** Fails the single-dashboard management goal and leaves media sharing and transcode orchestration unaddressed.

### Alternative B: Extend the legacy master/worker cluster

*   **Pros:** Reused pre-existing `cluster_daemon` tables and heartbeat scaffolding.
*   **Cons:** Single-master topology prevents symmetric two-way management; polling command queues cannot carry interactive forms, streaming uploads, or WebSockets; requires manual TLS certificate provisioning; and created `cluster_commands`/`cluster_enrollment_tokens` lazily outside versioned `af-db` migrations (only `cluster_nodes` lived in base DDL + Migration 5).
*   **Technical Reason Not Chosen:** Retrofitting symmetric auth, streaming HTTP/WS, and versioned migrations onto `cluster_daemon` adds more complexity than replacing it with Peer Clustering.

### Alternative C: Dedicated pinned mTLS peer listener on public or VLAN interfaces

*   **Pros:** Removes the WireGuard package and interface dependency.
*   **Cons:** Requires custom certificate generation, pinning, and `rustls` verifier maintenance; exposes a public TLS handshake surface; and leaves NFSv4.2 and transcode traffic requiring separate transport encryption and firewall rules.
*   **Technical Reason Not Chosen:** WireGuard provides silent unauthenticated packet drop, mutual key pinning, and one shared encrypted kernel tunnel for API, NFSv4.2, and transcode traffic.

### Alternative D: Embed Server B's frontend bundle inside Server A

*   **Pros:** Server B's UI always matches Server B's API version without capability gating.
*   **Cons:** Executing B's WASM/JS inside A's origin lets a compromised B hijack A's admin session; compiled `/api/v1/*` paths would target A; and A's `X-Frame-Options: DENY` security header (`routes.rs`) blocks cross-origin framing.
*   **Technical Reason Not Chosen:** Violates same-origin isolation and introduces cross-server XSS and session-takeover exposure.

### Alternative E: `rclone` WebDAV or SFTP mounts for peer media

*   **Pros:** Handles higher-latency WAN links via local VFS caching, and `rclone` is already in Marketplace.
*   **Cons:** FUSE + HTTP/SSH adds per-stream CPU overhead and slows library scans; VFS write caching breaks immediate HLS/DASH transcode segment visibility; and AetherFlow's sandboxed `rclone.service` cannot mount FUSE (`af-runner/src/package_executor/declarative_recipes/catalog.rs:1192-1201`).
*   **Technical Reason Not Chosen:** Kernel NFSv4.2 over `afpeer0` avoids userspace FUSE/HTTP copies and VFS write-caching delays, delivering lower latency and immediate write visibility required by distributed transcoding on 1 Gbps+ datacenter links.

### Alternative F: Package `rffmpeg` for distributed transcoding

*   **Pros:** Existing community wrapper for Jellyfin `ffmpeg` offloading.
*   **Cons:** Introduces Python and per-worker SSH keys plus a separate SQLite host database; lacks native encoder/render-node awareness (requiring wrapper flag rewrites); and bypasses AetherFlow link revocation, grant enforcement, and audit logging.
*   **Technical Reason Not Chosen:** Conflicts with the Rust-only goal and does not integrate with WireGuard link revocation, grant scopes, or per-job audit trails.

### Alternative G: Reuse plugin scopes and tokens as peer grants

*   **Pros:** Reuses existing plugin token verification code.
*   **Cons:** Plugin manifests (`plugins/manifest.rs:10-85`) hard-deny `/api/v1/admin`, `/api/v1/ingress`, `/api/v1/plugins`, and 9 sensitive `/api/v1/auth/*` subpaths (`session`, `sessions`, `refresh`, `logout`, `ws`, `profile`, `user/2fa`, `oidc`, `plugins`), restrict non-`GET`/`HEAD` writes on `/api/v1/auth/{packages,services,system/update,deploy}`, `admin_only_middleware` rejects plugin tokens, and tokens are signed with local single-server secrets (only narrow `/api/v1/auth/*` scopes like metrics/hardware/services/packages/notifications are exposed via `permission_route_prefixes`).
*   **Technical Reason Not Chosen:** Admin management requires a dedicated `PeerPrincipal` + `TrackedRouter`-verified `ForbiddenRule`/`AllowedRule` table that covers every admin route while failing closed on unclassified paths.

### Alternative H: Per-feature typed remote clients, or direct browser-to-peer calls

*   **Pros:** Eliminates a generic streaming proxy.
*   **Cons:** Per-feature remote clients multiply maintenance cost on every new tab or API route; direct browser calls break same-origin `__Host-` session cookies, require CORS exposure on peer listeners, and force logins on every server.
*   **Technical Reason Not Chosen:** A single `api_url` prefix + `stream_proxy` routes classified `/api/v1/*` dashboard endpoints without per-tab proxy clients while keeping the browser same-origin.

### Alternative I: Reuse existing `wg0` or Tailscale instead of dedicated `afpeer0`

*   **Pros:** Avoids adding a second WireGuard interface.
*   **Cons:** `wg0` is operator-managed via the **Network** tab for arbitrary VPN topologies (risking conflicting `AllowedIPs`, key rotation, or accidental peer deletion); Tailscale relies on an external coordination plane and optional third-party login.
*   **Technical Reason Not Chosen:** Dedicated `afpeer0` isolates peer WireGuard state in `afpeer0.conf` with deterministic tunnel IPs and key pinning without modifying `wg0` or depending on external coordination servers.

### Alternative J: Link-only bearer token vs. separate revocable `X-AF-Grant-Token`

*   **Pros:** Single token per link eliminates Migration 27's received-grant rotation tables.
*   **Cons:** Coupling management authorization to the link credential prevents revoking or rotating remote management access independently of link health, NFS transport, and pairing state.
*   **Technical Reason Not Chosen:** Independent link and grant credentials allow revoking or downgrading grants while preserving authenticated link health and reciprocal grants.

### Alternative K: Dedicated read-only synthetic role vs. perimeter `role = "admin"` injection

*   **Pros:** Splitting `admin_only_middleware` into read-only vs. read-write middleware would provide defense-in-depth inside route handlers if a route-table rule were ever misclassified.
*   **Cons:** Existing AetherFlow read handlers sit uniformly behind `admin_only_middleware` across dozens of route modules, so introducing a second admin role requires auditing and re-gating every existing admin route registration.
*   **Technical Reason Not Chosen:** Enforcing `TrackedRouter` completeness in CI (`peers/scopes.rs`) keeps existing admin handlers untouched while failing builds on any unclassified route; the single-layer perimeter trade-off is tracked explicitly in [Risks & Mitigations](#risks--mitigations).

### Alternative L: Worker argv path-rewriting / per-link mount namespaces vs. host-global `/var/cache/jellyfin*` mounts

*   **Pros:** Mounting controller transcode directories under `/mnt/af-peers/<link>/transcode` and either rewriting `ffmpeg` arguments or running per-link mount namespaces (`af-transcode-worker@<link>.service`) would allow a GPU worker to serve multiple controllers and coexist with local Jellyfin.
*   **Cons:** Rewriting arbitrary `ffmpeg` path arguments (including filtergraphs, concat lists, and HLS playlist references) risks breaking edge-case Jellyfin invocations, while templated per-link systemd mount namespaces add unit lifecycle and mount-propagation complexity.
*   **Technical Reason Not Chosen:** Initial implementation prioritizes exact path parity on dedicated workers and defers per-link mount namespaces to [Future Improvements](#future-improvements).

### Alternative M: `tokio-tungstenite` vs. custom RFC 6455 transcode client (and tunnel-only transcode capabilities)

*   **Pros:** Restricting cached `transcode` metadata solely to link-authenticated tunnel `GET /health` eliminates unauthenticated public hardware/package disclosure without diverging the nullable schema, and reusing `tokio-tungstenite` (already compiled via `axum`) avoids maintaining a bespoke RFC 6455 client inside `peers/transcode.rs`.
*   **Cons:** Omitting `transcode` on public `GET /health` prevents unauthenticated local probe scripts from reading cached FFmpeg/GPU status (authenticated operators use `GET /api/v1/admin/peers/transcode` or `af cluster diagnose`, while paired peers use tunnel `GET /health`); wrapping `tokio-tungstenite` over a `SO_BINDTODEVICE` tunnel stream requires custom write-boundary instrumentation for `WsWriteError::BeforeAnyBytesSent`.
*   **Decision & Technical Reason:** Bundle B(d) adopted tunnel-only transcode capabilities—unauthenticated public `GET /health` (`routes/health.rs:34`) now unconditionally returns `"transcode": null`, while link-authenticated tunnel `GET /health` (`peers/listener.rs:410-458`) serves cached `transcode` capabilities (including `worker_max_jobs`) and `"inbound_grant_generation"`. Replacing the self-contained bound-socket RFC 6455 WS client with `tokio-tungstenite` remains deferred to [Future Improvements](#future-improvements) and [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md#post-release-architectural-simplification-backlog).

--------------------------------------------------------------------------------

## Non-Functional Requirements

*   **Security & Privacy:**
    *   Read-write grants in administrative areas (`services`, `marketplace`, `settings`, `users`, `network`, `files`, `updates`, `transcoding`) carry host-level blast radius, and two-way write grants expose both servers if either host is compromised. `updates: write` is narrowed on `POST /api/v1/admin/packages/{id}/update` strictly to `jellyfin` and `jellyfin-ffmpeg*` (`marketplace: write` is required for other packages).
    *   Mitigations: per-area access with read-only defaults, fail-closed `TrackedRouter` route classification, proxy-chaining denial, dual source-IP + `X-AF-Link-Token` + `X-AF-Grant-Token` validation, immediate local token rejection with bounded async teardown (`<< 1 s` for both WebSockets and in-flight non-WS HTTP proxy streams on managing and target sides; `Signal(Kill)` for transcode jobs), worker-side systemd/protocol/`cwd`/allowlist confinement, full target-side auditing, and root/`aetherflow`-only credential storage (with secret-free `/etc/aetherflow/transcode.env` `0640 root:jellyfin` isolated from `/etc/aetherflow/aetherflow.env`).
    *   The management proxy never accepts a target host from client requests; `X-AF-Origin-Operator` is audit metadata only. During initial pairing, `POST /api/v1/admin/peers/pair` posts `PublicPairingRequest` to the `https_url` decoded from the operator-pasted `afpair1:` string, enforcing `https://`, bare origin, strict OS CA TLS, no redirects, `.no_proxy()`, DNS IP pinning (`resolve_to_addrs`), and SSRF blocking of loopback, link-local/metadata, unspecified, multicast, broadcast/reserved, `afpeer0` CIDR, and private RFC1918/ULA/CGNAT ranges (unless `AF_PEER_ALLOW_PRIVATE_PAIRING_URLS=true`).
    *   NFS exports use `secure` (privileged source ports) restricted to each peer's tunnel IP.
*   **Performance, Scale, & Latency:**
    *   Compile-time caps enforce `MAX_PEERS = 256`, `MAX_EXPORTS_PER_LINK = 64`, and `MAX_TUNNEL_TRANSCODE_PATHS = 32` per sync (note that links with 33–64 media mounts exceed `MAX_TUNNEL_TRANSCODE_PATHS`—and large bind lists can exceed the `8 KiB` `/peer/v1/transcode/mounts` body limit—until reconciled); the proxy streams HTTP bodies and WebSockets without full-body buffering under configurable per-link defaults (`AF_PEER_MAX_CONN = 64`, `AF_PEER_MAX_WS = 16`). Because the current 15 s health loop probes sequentially on single-writer SQLite, the practical operational envelope is small clusters (≤ 16 peers) until parallelized.
    *   Raw 1 Gbps+ datacenter links provide theoretical wire-rate headroom for multiple 4K remux streams (~70–80 Mbps/stream before WireGuard crypto CPU and disk I/O overhead; actual concurrent stream capacity remains unmeasured pending live Server B benchmarking); transcode stdio/signal frames remain bounded by `MAX_FRAME_BYTES = 1 MiB` while media segments travel over NFS.
    *   Single-writer SQLite writes per 15 s health tick are minimized to `commit_link_healthy` (plus `transcode_workers` capability upserts only when metadata changes—`handle_remote_health_transcode_caps` at `peers/transcode.rs:967-1017` skips no-op writes—and `prune_old_transcode_jobs` now runs in `af-api/src/main.rs:317`'s 15-minute maintenance loop), alongside synchronous per-proxied-request `admin_audit_log` writes (currently unbounded retention) and per-job `transcode_jobs` records (7-day retention).
*   **Rollout & Rollback:**
    *   Phases ship incrementally. Migrations 25 and 27 are additive; **Migration 26 (Phase P4) irreversibly drops `cluster_nodes`, `cluster_enrollment_tokens`, and `cluster_commands`**, so rolling back across Migration 26 requires restoring a pre-upgrade WAL-safe SQLite backup. *(Note: `perform_system_backup()` in `storage/backups.rs:773-839` snapshots `aetherflow.sqlite` including `peer_*` tables without `/etc/wireguard/afpeer0.conf` or `/etc/aetherflow/peers/`, so post-pairing backup restores require manual peer reconciliation or re-pairing — see [Risks & Mitigations](#risks--mitigations).)*
    *   Mixed-version peers degrade via `peer_protocol` and `capabilities` (`Compatible`, `Limited`, `Incompatible`): malformed, non-`/api/v1/`, or unknown `/peer/v1/*` routes return **`403 PEER_ROUTE_UNCLASSIFIED`**, revoked/revoking links return **`403 LINK_REVOKED`** (`peers/listener.rs:126`), missing/inactive grants or forbidden/insufficient scopes return **`403 PEER_SCOPE_DENIED`** (`peers/listener.rs:548-708`), and unknown tunnel source IPs or invalid link/grant tokens return **`401 PEER_UNAUTHORIZED`** (`peers/listener.rs:97-158`).
    *   With transcoding disabled before first enable, Jellyfin is untouched. Toggling global offloading off (`enabled: false`) removes `jellyfin.service.d/20-aetherflow-transcode.conf`, restores local Jellyfin, tears down controller transcode exports, and sends best-effort teardown to enabled workers; toggling `worker_service_enabled: false` tears down all local worker transcode/bind mounts before `RemoveWorkerUnit`.

## Risks & Mitigations

| Risk / Limit | Impact | Current Mitigation / Operational Constraint |
| :--- | :--- | :--- |
| **Host-global `/var/cache/jellyfin*` worker mounts & dedicated-worker constraint** | Mounting controller Jellyfin cache/transcode paths globally shadows local Jellyfin and limits each worker to **one Jellyfin controller at a time** (neither media nor worker `.mount` units are `systemctl enable`d at boot, requiring post-reboot worker re-save after `/mnt/af-peers/*` recovers). | **Hardened in Bundles A–B:** `MountTranscodeDirs` enforces an explicit Jellyfin cache/transcode allowlist in both `af-api` and `af-runner`; `BindMedia` enforces calling-link `/mnt/af-peers/<segment>/` confinement, controller-holds-media media-root allowlist + empty-directory check, and conditional `BindsTo=`/`After=` on backing `/mnt/af-peers/*` NFS `.mount` units; `ExportTranscodeDirs` applies `st_dev`-guarded nested export pruning; partial sync failures roll back atomically (with SQLite transaction wrapping `peer_mounts`); `links.rs:649-675` tears down transcode before media storage on revocation and propagates errors; and `enabled: false`, `worker_service_enabled: false`, and inbound `transcoding: write` revocation/downgrade tear down exports/mounts automatically. Per-link mount namespaces remain a post-release enhancement in [Future Improvements](#future-improvements). |
| **Host-wide `[nfsd] host=<tunnel_ip>` lock-in** | `/etc/nfs.conf.d/aetherflow-peers.conf` binds `nfs-server.service` globally to the tunnel IP, making a peer-exporting host incompatible with unrelated LAN NFS clients until peer exports and drop-ins are removed. | **Boot-ordered & guarded in Bundle A:** `ConfigureNfsd` (`peer_storage.rs:2712-2790`) installs managed `/etc/systemd/system/nfs-server.service.d/20-aetherflow-peers.conf` (`After=wg-quick@afpeer0.service`, `Wants=wg-quick@afpeer0.service`), runs `daemon-reload`, and logs a warning if pre-existing unmanaged `/etc/exports` lines exist. Host-exclusivity and LAN NFS restoration steps are documented in [docs/peer-clustering.md](../peer-clustering.md#operational-limits-and-safeguards). |
| **Worker concurrency cap & shared `AF_PEER_MAX_WS`** | Worker inbound transcode jobs share `AF_PEER_MAX_WS = 16` with management WebSockets; hitting `AF_PEER_MAX_WS` fails pre-`Start` (`503 PEER_BUSY`, triggering fallback + 60 s cooldown). | **Hardened in Bundle B(b):** Dedicated secret-free `/etc/aetherflow/transcode.env` (`0640 root:jellyfin`, never `aetherflow.env`) configures `AF_TRANSCODE_WORKER_MAX_JOBS` (default `8`) and `AF_TRANSCODE_REAL_FFMPEG` across all 4 consuming units. Workers advertise `worker_max_jobs` over tunnel `GET /health`, and controllers auto-clamp dispatch to `effective_max_jobs = min(worker.max_jobs, worker_max_jobs)`. |
| **Hardware-eligibility matching limitations** | `af-transcode capabilities` lists compile-time `ffmpeg -encoders` identically across hosts and detects only `/dev/dri/renderD*` nodes—permanently disqualifying headless NVIDIA workers exposing only `/dev/nvidia*`, letting cold-cache DB fallback (`vendor_id: None`, `peers/transcode.rs:4096`) wildcard across QSV/VA-API/CUDA, and not distinguishing same-vendor GPU codec generations (e.g., `av1_vaapi` on older GPUs). | Pair workers with verified matching GPU encoder capabilities; headless NVIDIA detection, persisted `vendor_id`, and runtime hardware probing are tracked in [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md#post-release-architectural-simplification-backlog). |
| **Unverified Jellyfin 12.4 missing-root retention** | If Jellyfin 12.4 purges items when `/mnt/af-peers/<link>/<export>/library` disappears, link outages could wipe library metadata. | Explicitly gated in Server B P7 acceptance (with conditional Jellyfin ScheduledTasks contingency trigger in [Open Questions](#open-questions)). |
| **Privilege boundaries (`role = "admin"`, `SupplementaryGroups=jellyfin`, GPU/cache blast radius)** | Read-only grants rely on perimeter `peers::scopes` classification; `aetherflow-api` joins group `jellyfin`; and `transcoding: write` grants GPU access plus read-write access to shared Jellyfin cache/transcode directories. | **Hardened in Bundles A–B:** `TrackedRouter` CI test fails on unclassified routes; `jellyfin` is never added to group `aetherflow`; `updates: write` is narrowed strictly to `jellyfin`/`jellyfin-ffmpeg*` (`marketplace: write` required for other packages); `af-transcode-worker.service` runs with `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, `ProtectSystem=strict`, `ProtectHome=read-only`, `WorkingDirectory=/run/aetherflow-transcode-worker`, `DevicePolicy=closed` + DRM/NVIDIA `DeviceAllow=`, dynamic `30-aetherflow-transcode-paths.conf`, local-only `WORKER_LOCAL_PROTOCOL_WHITELIST`, and clamped `cwd` (with dispatcher `RunLocal` bypass for network inputs); in-flight non-WS HTTP proxy streams cancel on `RevocationEvent` (`<< 1 s`) on both sides; pairing enforces SSRF + DNS IP pinning; and public `GET /health` unconditionally returns `"transcode": null`. |
| **SQLite audit/write amplification, sequential health probing, & `MAX_EXPORTS_PER_LINK` vs. `MAX_TUNNEL_TRANSCODE_PATHS`** | High-rate proxied requests write synchronous per-request audit rows (`admin_audit_log`, unbounded retention) through the single SQLite writer; unthrottled `POST /peer/v1/grant-offer` can amplify writes; sequential 15 s health probing limits practical cluster size (≤ 16 peers); and links with 33–64 media mounts exceed `MAX_TUNNEL_TRANSCODE_PATHS = 32` per sync. | **Partially hardened in Bundles A & C:** `ProbeSentinel` runs with per-mount single-flight deduplication and a global cap (`MAX_CONCURRENT_SENTINEL_PROBES = 4`) on dedicated OS threads off Tokio's `spawn_blocking` pool; `handle_remote_health_transcode_caps` skips no-op SQLite upserts; and `prune_old_transcode_jobs` runs in `main.rs:317`'s 15-minute loop. Parallel health probing, `grant-offer` rate-limiting, read-audit batching, retention pruning, and `64` vs. `32` reconciliation remain tracked in [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md#post-release-architectural-simplification-backlog). |
| **SQLite backup/restore split-brain & revoked-grant resurrection** | `perform_system_backup()` (`storage/backups.rs:773-839`) snapshots `peer_*` SQLite tables without `/etc/wireguard/afpeer0.conf` or `/etc/aetherflow/peers/`, so restoring an older backup can resurrect revoked links/grants, rewind `peer_grant_epochs`, or mismatch host WireGuard identity. | Re-verify and revoke/re-pair links after any SQLite backup restore; explicit backup/restore quarantine/reconciliation is tracked in [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md#post-release-architectural-simplification-backlog). |
| **Slow >5 s Jellyfin cold start, `GET` probe latency, upgraded-host sandbox, & initial 1 s API restart** | Upgraded hosts still run `sudo af sandbox apply jellyfin` once to migrate `10-aetherflow-sandbox.conf`; first-time transcode enable runs a debounced 1 s `aetherflow-api.service` restart interrupting active transfers; Jellyfin cold starts >5 s skip automatic shim rollback; and `GET /api/v1/admin/peers/transcode` runs a live Jellyfin HTTP probe (up to ~6 s latency when Jellyfin is stopped). | **Hardened in Bundle A:** `config/package_automation.json:35` now mounts directory `"-/run/aetherflow-transcode"` (so API restarts no longer strand Jellyfin on an unlinked socket inode); `af-release` and `deploy/release-manager.sh` atomically refresh existing `/usr/lib/aetherflow/transcode/ffmpeg` shims and restart active `af-transcode-worker.service` on self-updates; `ensure_listener_started()` auto-recovers on `afpeer0` `ifindex` changes; `reconcile_dispatcher_if_configured` auto-recovers in `run_health_tick`; and `ScheduleApiRestart` debounces deterministically via `--unit=aetherflow-transcode-api-restart`. |

## Open Questions

*   **Jellyfin 12.4 missing-root retention (conditional contingency trigger — pending Server B acceptance):** Jellyfin has no Plex-style "empty trash" toggle, so the design relies on the interior library subfolder (`/mnt/af-peers/<link>/<export>/library`) disappearing when a mount stops. Two-server acceptance (P7) tests a live scan while the mount is stopped. If Jellyfin 12.4 purges items when the library root is missing, a dedicated follow-up mini-spec will be authored before coding covering four bounded areas:
    1.  Shared `streaming_servers` credential lookup (reusing `af-api/src/streaming_ext/config.rs:28-75` instead of `peers/transcode.rs:230-260`).
    2.  Migration 28 DDL persisting pause state and original Jellyfin `Triggers` JSON (idempotent across multiple stopped mounts).
    3.  Jellyfin ScheduledTasks API calls (`GET /ScheduledTasks` matching `Key == "RefreshLibrary"`, `DELETE /ScheduledTasks/Running/{taskId}`, and `POST /ScheduledTasks/{taskId}/Triggers` suspend/restore) in `af-api/src/peers/{storage.rs,health.rs,mod.rs}` with startup and health-tick recovery.
    4.  Mock-Jellyfin regression tests.
*   **Pre-release escalation queue status:** All pre-release security, runtime reliability, design-decision `(a)`–`(d)`, CLI/protocol/observability, and documentation items (Bundles A–D) have been **resolved on `feat/peer-clustering`** (detailed in [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md#tracked-pre-release-escalation-queue)). Remaining open gates are live two-server acceptance on Server A + Server B and the post-release architectural simplification backlog.

--------------------------------------------------------------------------------

## Detailed Implementation Plan

Phases landed sequentially as local commits `a80f123b` through `f20a3a99` on `feat/peer-clustering`. Complete per-phase repository file manifests (including all test, catalog, Cargo, and E2E files) are cataloged in [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md#phase-file-boundary-expansion).

### Before you start

*   [x] Base `feat/peer-clustering` on fetched `origin/nightly` (`447e04fe`) and audit baseline references in [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md).
*   [x] Run workspace release builds and tests on unmodified nightly and land prerequisite parallel-test isolation fixes (`2c9f7032`, `f88aaeb0`).
*   [x] Confirm Rust, `wasm32-unknown-unknown`, Trunk, and `wasm-bindgen` on Server A.
*   [ ] Complete two-server acceptance on Server A + Server B (Debian 13 + matching Jellyfin 12.4 / `jellyfin-ffmpeg` apt state, SSH destination, private VLAN addresses, UDP `51821` reachability, release artifact delivery, test media library, and GPU worker).

### Roadmap

| Phase | Entry IDs and follow-up wiring | Local commit | Local exit gate |
| :--- | :--- | :--- | :--- |
| **P0 Backend groundwork** | Entries 1–4 (+ `routes/health.rs`, `af-db/src/tests.rs`, `backup_tests.rs`, `security_and_account.rs`) | `a80f123b` | Fresh and legacy Migration 25 pass (`max_ver == 25`). `/health` advertises protocol 1 with `[]`. Bounded `X-Request-ID` appears in JSON logs. |
| **P1 Browser transport groundwork** | Entries 5–7 (+ `mcbrowser/{editor,mod}.rs`, `marketplace/sandbox.rs`, `settings/security.rs`) | `4e1255cb` | Local URLs, CSRF, and telemetry work; peer paths rewrite once; malformed paths rejected; auth and profile avatars stay local. |
| **P2 Privileged peer networking** | Entries 20–22 (+ `network.rs`, `runner_client.rs`) | `e8ebe461` | Fake-runner tests pass for config, `syncconf`, status, route rollback, `PeerCredentialSlot` files, and `wg0` preservation. Unlinked startup stays dormant. |
| **P3 Tunnel pairing and lifecycle** | Entries 12–18, 30 (link slice) (+ `peers/tests.rs`, `routes/health.rs`) | `1848be91` | Pairing, expiry, retry, revocation, 10-state ownership projection, and lazy listener startup pass over staged listener and fake runner. `/health` advertises `["links"]`. |
| **P4 Cluster UI and legacy retirement** | Entries 8–11, 17–18 (cleanup), 19, 23–27 (+ `wasm.cluster.spec.ts`, `.env.example`, `tests/e2e/*`) | `f2c2c85f` | Fresh and upgraded Migration 26 pass (`max_ver == 26`). Legacy `cluster_daemon/`, `intelligence/cluster.rs`, routes, and tables removed. `/?tab=cluster` uses peer API. |
| **P5 Grants and scope enforcement** | Migration 27, Entries 28–30 (scoped), 32–33 (authz), 36 (+ `TrackedRouter` route files, `grant_lifecycle_tests.rs`) | `8e9ec370` | Migration 27 (`max_ver == 27`), `TrackedRouter` route-classification parity, token/source validation, per-area access, and audit assertions pass. Grant revocation preserves link health. `/health` adds `"grants"`. |
| **P6 Management proxy and server switching** | Entries 31, 32 (proxy), 34–35 (+ `state/server.rs`, `state/tests.rs`, `tabs/busy.rs`, `tabs/settings/updates.rs`, `mcbrowser/transfers/upload.rs`, `wasm.peer-switching.spec.ts`) | `6dc2dbee` | 6-method proxy, header/cookie scoping, streaming permits, WebSocket revocation (≤ 1 s), `SERVER_EPOCH`/`AreaFence`, and `wasm.peer-switching` E2E pass. |
| **P7 Media over NFS** | Entries 22 (storage), 37–40 (+ `sandbox_ops.rs`, `routes/{fs_browser,streaming}.rs`, `scan_cursor.rs`) | `86a81951` | Fake `exportfs`/mount/sentinel fixtures pass; `PeerStorageRequest` runner-derived options, non-root writable checks, stale WG handshake / peer removal stop, and Plex safety hook verified. `/health` adds `"storage"`. |
| **P8 Local transcode foundation** | Entries 41–47 (+ `af-transcode/src/config.rs`, `tests/integration.rs`) | `03940e70` | `wincode 0.6.3` 10-frame codec, 5-field `Capability`, shim probe/local fallback, worker streaming/signal/hard-kill fixtures, and `detect_render_nodes()` pass. |
| **P9 Remote transcoding and standalone regression** | Entries 22 (transcode), 48–52 (+ `af-api/Cargo.toml`, `af-cli/Cargo.toml`, `af-cli/src/{cli/*,client.rs,commands.rs,commands/cluster.rs,tests/*}`, `af-release/src/{artifact/archive.rs,tests/config_artifact_tests.rs}`, release/setup scripts) | `f20a3a99` | Dispatcher selection, `POST /peer/v1/transcode/mounts`, parity test, drop-ins/`ScheduleApiRestart`, `af cluster diagnose`, release bundle checks, and standalone E2E pass. `/health` adds `"transcode"`. |

### Phase execution discipline

*   Each phase integrates intra-phase file boundaries into a single `feat(peers): P<n> <title>` commit after passing the workspace build, test, `cargo fmt`, `cargo clippy` (`--manifest-path backend-rs/Cargo.toml` and `frontend-rs/Cargo.toml`, including the `wasm32-unknown-unknown` pass), and supply-chain checks in [Common local gate for every phase](#common-local-gate-for-every-phase), alongside diff verification covering file boundaries, authorization branches, command construction, and secret redaction.
*   Any deviation from the original `702ae0d2` anchor or contract is recorded in [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md). Production isolation seams (`PeerDb::Isolated`, `TunnelTransportBinding::LoopbackFixture`, `PublicPairingTransport`, `PeerRuntime` and `TranscodeRuntimeState` `#[cfg(test)]` hooks, `JellyfinFfmpegProbe`, `PeerRunner`/`PeerStorageRunner`/`PeerTranscodeRunner`, injectable runner managers) and shared crate test harnesses (`isolated_p6_subprocess`, fake `wg`/`exportfs`/`ffmpeg` fixtures, CLI transports) are cataloged in [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md#dependency-environment-variable-and-test-coverage-ledger).

### Phase P0: Backend groundwork

Adds SQLite Migration 25 peer tables (`af-db`), bounded `X-Request-ID` tracing correlation, `/health` peer protocol metadata, and optional JSON tracing output.

#### P0.1 [Entry 1]: `backend-rs/crates/af-db/src/lib.rs` (Modify) & `backend-rs/crates/af-db/src/tests.rs` (Modify)

*   **Implemented Changes:** Added `migrate(&conn, 25, "Peer clustering", &[...])` with the Migration 25 SQL after the existing v23 check in `init_db()` (`af-db/src/lib.rs:746-779`; v24 `streaming::migrate_history` runs earlier at `L707`), preserved `record_audit` `tracing::error!` logging in `af-db/src/audit.rs`, declared `pub mod peers;`, and updated schema max-version assertions in `af-db/src/tests.rs:215` and `af-api/src/storage/backup_tests.rs:356` (progressing `25 → 26 → 27`).
*   **Rationale:** Peer tables require versioned migrations while keeping existing audit-failure visibility intact.

#### P0.2 [Entry 2]: `backend-rs/crates/af-db/src/peers.rs` (Create)

*   **Implemented Changes:** Typed structs and CRUD helpers taking `&Connection` for every peer table (`PeerIdentity`, `PeerLink`, `PeerGrant`, `PairingWindow`, `PairingAttempt`, `PeerExport`, `PeerMount`, `TranscodeWorker`, `TranscodeJob`, plus P5 received-grant/epoch tables), JSON serialization for `AccessMap`, and in-memory SQLite unit tests.
*   **Rationale:** Keeps SQL queries encapsulated out of HTTP handlers.

#### P0.3 [Entry 3]: `backend-rs/crates/af-api/src/routes.rs` (Modify) & `backend-rs/crates/af-api/src/routes/health.rs` (Modify)

*   **Implemented Changes:** Updated `security_headers_middleware` (`routes.rs:259-301`) to validate inbound `X-Request-ID` headers (≤ 128 bytes of `[A-Za-z0-9._:-]`), fall back to a bare Unix nanosecond integer (`routes.rs:273`) on missing/invalid input, record `request_id` on the `TraceLayer` span, scope `af_runner::with_runner_request_id` (`routes.rs:301`, Bundle C), and propagate the same ID to responses. Updated `routes/health.rs` (`/health` mounted at `routes.rs:479`) to return `peer_protocol: 1`, `capabilities` (starting at `[]` in P0 and wired to `crate::peers::capabilities()` from P3 onward, returning `["links", "grants", "storage", "transcode"]`), and `"transcode": null` unconditionally on public `/health` (`routes/health.rs:34`, Bundle B(d)), tested in `routes/tests/security_and_account.rs`.
*   **Rationale:** Enables cross-server request correlation (across API, UI error banners, and `aetherflow-runner`) and mixed-version capability negotiation without disclosing host hardware inventory publicly.

#### P0.4 [Entry 4]: `backend-rs/crates/af-api/src/main.rs` (Modify)

*   **Implemented Changes:** Enabled `tracing_subscriber` JSON output in `init_tracing()` (`main.rs:233-252`, reading `AF_LOG_FORMAT=json` at `L244`) using workspace JSON features.
*   **Rationale:** Produces machine-parseable logs for cross-server `request_id` triage.

### Phase P1: Browser transport groundwork

Introduces Leptos-free peer URL rewriting (`api_url`) and CSRF prefix handling in `af-web-core`, audits all direct browser URL call sites in `af-web-app`, and locks down local-only auth/avatar/Plugin Sandbox boundaries.

#### P1.1 [Entry 5]: `frontend-rs/crates/af-web-core/src/api.rs` (Modify)

*   **Implemented Changes:** Added thread-local `RefCell<Option<String>>` active-server state (`set_active_server`, `active_server`) driven by `AppContext.active_server_id` in P6, `api_url(path)` rewriting `/api/v1/{rest}` to `/api/v1/peers/{id}/{rest}` once while preserving query strings, keeping auth/admin-peer paths local, and rejecting malformed paths. Routed `ApiClient` builders (`impl ApiClient`, `api.rs:1081+`, calling `prepare_api_request_path` defined at `L320-325` from `L1163` and `L1391`) through `api_url`, and updated `should_attach_csrf` (`api.rs:359-392`) to match both local (`/api/v1/...`) and peer-prefixed (`/api/v1/peers/{id}/...`) mutation paths while exempting only the local refresh endpoint.
*   **Rationale:** A single transport hook routes classified dashboard tabs remotely without per-tab proxy clients.

#### P1.2 [Entry 6]: `frontend-rs/crates/af-web-core/src/ws.rs` (Modify)

*   **Implemented Changes:** Routed telemetry ticket fetches and WebSocket URL construction (`ws.rs:37-43,399-426`) through `api_url("/api/v1/auth/ws")` while preserving the current window host and `ws(s)` scheme, with unit tests covering `/api/v1/auth/ws/logs` (wired with `LogStreamConnection` in P6).
*   **Rationale:** Enables live telemetry and log streaming across peer links through the existing browser WebSocket clients.

#### P1.3 [Entry 7]: Direct browser URL sites (Modify)

*   **Files:**
    *   `frontend-rs/crates/af-web-app/src/tabs/mediaflow.rs` (Modify)
    *   `frontend-rs/crates/af-web-app/src/tabs/fileshare/local_storage.rs` (Modify)
    *   `frontend-rs/crates/af-web-app/src/tabs/mcbrowser/{editor.rs,helpers.rs,mod.rs}` (Modify)
    *   `frontend-rs/crates/af-web-app/src/tabs/streaming/live.rs` (Modify)
    *   `frontend-rs/crates/af-web-app/src/tabs/settings/backups_oidc.rs` (Modify)
    *   `frontend-rs/crates/af-web-app/src/shell.rs` (Modify)
    *   `frontend-rs/crates/af-web-app/src/tabs/settings/security.rs` (Modify)
    *   `frontend-rs/crates/af-web-app/src/tabs/marketplace/sandbox.rs` (Modify)
*   **Implemented Changes:** Routed authenticated direct browser URLs (`href`, `fetch`, `EventSource`) through `api_url(...)` while verifying that auth, pairing, header/profile avatars, public anonymous shares, and the Plugin Sandbox remain local.
*   **Rationale:** Prevents hardcoded `/api/v1/...` call sites from bypassing `ApiClient` while preserving local-only security boundaries.

### Phase P2: Privileged peer networking

Adds the root-privileged `/v1/peer-network` runner endpoint for managing `afpeer0` WireGuard interfaces, effective route verification, and runner-owned token credential slots without touching `wg0`.

#### P2.1 [Entry 20]: `backend-rs/crates/af-runner/src/peer_network.rs` (Create)

*   **Implemented Changes:** Implemented `PeerNetworkRequest` over `/v1/peer-network` (`EnsureIdentity`, `AddPeer`, `RemovePeer`, `SetEndpoint`, `Status`, `EnsurePackages`, `WriteCredential`, `ReadCredential`, `DeleteCredential`, `DeleteLinkCredentials` over `PeerCredentialSlot::{LinkToken, GrantToken, PendingIssuerToken}`). Writes `/etc/wireguard/afpeer0.conf` (`0600`), `/etc/aetherflow/peers/afpeer0.key`, `/etc/aetherflow/peers/tokens/*.token` (`0640`), `/etc/aetherflow/peers/pending/link-*.token` (`0600`), and root-only `.staging`. Runs `wg-quick strip afpeer0` and `wg syncconf afpeer0` via argv, verifies kernel routes with rollback on failure, enables `wg-quick@afpeer0.service`, distinguishes `present_live` vs. `persistent` peers in `Status`, installs `wireguard-tools` via Marketplace apt serialization (no receipt), and reuses the shared dump parser in `af-runner/src/network.rs` without modifying `wg0`.
*   **Rationale:** Root-only WireGuard and secret-file changes belong in `af-runner`.

#### P2.2 [Entry 21]: `backend-rs/crates/af-runner/src/peer_network/tests.rs` (Create)

*   **Implemented Changes:** Added tests using a fake `wg` binary and injectable `PeerNetworkManager`: config generation, `syncconf`, add/remove, route-failure rollback, credential slot permissions/redaction, and a regression assertion that `wg0.conf` is untouched.
*   **Rationale:** Verifies privileged WireGuard and credential operations deterministically without mutating host networking.

#### P2.3 [Entry 22]: `backend-rs/crates/af-runner/src/lib.rs` (Modify), `backend-rs/crates/af-runner/src/network.rs` (Modify), `backend-rs/crates/af-runner/src/runner_client.rs` (Modify), & `backend-rs/crates/af-runner/src/sandbox_ops.rs` (Modify)

*   **Implemented Changes:** Shared `parse_wg_dump` in `network.rs` (P2); declared `pub mod peer_network;` (P2), `pub mod peer_storage;` (P7), and `pub mod peer_transcode;` (P9) with crate-root wire re-exports (`af-runner/src/lib.rs:62,70,85`) and registered `/v1/peer-network`, `/v1/peer-storage`, and `/v1/peer-transcode` in `build_runner_router()` (`af-runner/src/lib.rs:491-512`); added `dispatch_peer_network`, `dispatch_peer_storage`, and `dispatch_peer_transcode` in `runner_client.rs` (`L993,1105,1221`, with `with_runner_request_id` `X-Request-ID` propagation in Bundle C); extended `is_exempt_sandbox_unit` in `sandbox_ops.rs` for `nfs-server.service`, `mnt-af\x2dpeers-` mount units (P7), and `af-transcode-worker.service` (P9).
*   **Rationale:** Provides runner IPC dispatch, request-ID propagation, and systemd unit-policy plumbing across P2, P7, P9, and Bundle C.

### Phase P3: Tunnel pairing and lifecycle

Implements the `af-api/src/peers/` subsystem: pairing protocol, typed `PeerError` responses, 15-second health loop, link lifecycle/revocation, and the `SO_BINDTODEVICE("afpeer0")` tunnel listener (entries 12–18 and the link-only slice of entry 30, alongside `peers/tests.rs`).

#### P3.1 [Entry 12]: `backend-rs/crates/af-api/src/peers/mod.rs` (Create) & `backend-rs/crates/af-api/src/peers/tests.rs` (Create)

*   **Implemented Changes:** Declared submodules (`errors`, `health`, `links`, `listener`, `pairing`, plus P5 `grants`/`scopes`, P6 `proxy`, P7 `storage`, P9 `transcode`), exposed `tracked_admin_routes()`, `tracked_public_routes()`, and `tracked_proxy_routes()` (plus `#[allow(dead_code)]` `Router` wrappers), `capabilities()` (`["links"]` → `["links", "grants"]` → `["links", "grants", "storage"]` → `["links", "grants", "storage", "transcode"]`), zero-argument `peers::start()` (spawning the idle health loop once and keeping the listener dormant until `PeerRuntime::ensure_listener_started()` runs after `EnsureIdentity`, with `ifindex` tracking and client-pool clearing added in Bundle A), 10-state `peer_links.state` ownership helpers + `public_link_state`, `broadcast<RevocationEvent>`, and `PeerRunner` test infrastructure in `peers/tests.rs`.
*   **Rationale:** Centralizes peer lifecycle, router integration, and state-machine projection.

#### P3.2 [Entry 13]: `backend-rs/crates/af-api/src/peers/pairing.rs` (Create)

*   **Implemented Changes:** Implemented pairing window open/close (`POST /api/v1/admin/peers/pairing-window`, `DELETE /api/v1/admin/peers/pairing-window`, `DELETE /api/v1/admin/peers/pairing-window/{id}`), `afpair1:` base64url JSON encode/decode, SHA-256 code hashing, atomic single-use consumption, 10-minute expiry, per-IP rate limiting (5/min, `Retry-After: 60`), `CLOCK_SKEW_MAX_SECS = 300`, public request handler, `derive_comparison_code`, confirmation (`POST /api/v1/admin/peers/pairing/{attempt}/confirm`), cancellation (`DELETE /api/v1/admin/peers/pairing/{attempt}`), strict-TLS `reqwest` client (hardened with SSRF IP validation, DNS pinning, `.no_proxy()`, and `PeerNetworkRequest::EnsurePackages` auto-install in Bundle A), `pending_issuer_credential_id(link_id)` staging, idempotent `POST /peer/v1/hello` bootstrap/ack retries, and pending peer/file cleanup.
*   **Rationale:** Implements mutual key-pinned pairing without manual certificates.

#### P3.3 [Entry 14]: `backend-rs/crates/af-api/src/peers/errors.rs` (Create)

*   **Implemented Changes:** Implemented `enum PeerError` with all 22 typed codes, explicit HTTP status mapping (`400`–`504`), `is_terminal_for_confirm` retry rules (treating `HandshakeTimeout`, `EndpointUnreachable`, `Busy`, `RateLimited`, and `LinkDown` as retryable and all other codes as terminal), secret redaction, `{code, server, step, message, action, request_id?}` `IntoResponse` (`request_id` and standardized `Bytes`/`Json` extractor helpers added in Bundle C).
*   **Rationale:** Gives dashboards and operators structured, secret-free recovery actions with end-to-end request correlation.

#### P3.4 [Entry 15]: `backend-rs/crates/af-api/src/peers/health.rs` (Create)

*   **Implemented Changes:** Implemented the 15 s per-link loop sweeping expired pending attempts and failed `revoking*` cleanup rows (`pairing::cleanup_expired_pending`, `pending_expires_at = 0`), reconciling the transcode dispatcher on transient boot errors (`reconcile_dispatcher_if_configured`, Bundle A), checking WireGuard handshake age (`> 180 s` or removed peer stops media mounts on tick 1), calling link-authenticated tunnel `GET /health` with RTT, `CompatibilityStatus::{Compatible, Limited, Incompatible, Unknown}`, and offline grant-revocation reconciliation (`"inbound_grant_generation": null`, Bundle C), running P7 `ProbeSentinel` checks (`5000 ms` timeout) and `reconcile_mounts_for_healthy_link` media-mount recovery, refreshing P9 transcode capabilities (60 s TTL when links exist), updating DB health columns, and emitting notifications on state or `jellyfin-ffmpeg` version changes.
*   **Rationale:** Provides unified link health, version compatibility, grant reconciliation, and media-mount protection.

#### P3.5 [Entry 16]: `backend-rs/crates/af-api/src/peers/links.rs` (Create)

*   **Implemented Changes:** Implemented `GET /api/v1/admin/peers`, `DELETE /api/v1/admin/peers/{id}`, `PUT /api/v1/admin/peers/{id}/endpoint`, and tunnel handlers `GET /peer/v1/link` and `POST /peer/v1/revoke-notice` (Bundle A fixed revocation order to tear down transcode mounts/exports via `cleanup_revoked_link_transcode_locked` before media storage and propagate errors).
*   **Rationale:** Handles link inspection, endpoint updates, and fail-closed revocation teardown.

#### P3.6 [Entry 17]: `backend-rs/crates/af-api/src/routes.rs` (Modify)

*   **Implemented Changes:** Mounted `peers::tracked_admin_routes()` under `/api/v1/admin/peers` behind `admin_only_middleware`, `peers::tracked_public_routes()` outside auth with a 4 KiB body limit (P3), removed legacy cluster imports and routes (P4), and mounted `peers::tracked_proxy_routes()` under `/api/v1/peers` (P6) (`routes.rs:849,878-879`).
*   **Rationale:** Wires all peer routers through `TrackedRouter` for CI route-classification coverage and removes legacy cluster routes.

#### P3.7 [Entry 18]: `backend-rs/crates/af-api/src/main.rs` (Modify)

*   **Implemented Changes:** Started `peers::start()` at boot inside `if !disable_workers` (`main.rs:271-274,331-340`, skipped when `AETHERFLOW_DISABLE_BACKGROUND_WORKERS`, `AETHERFLOW_DISABLE_WORKERS`, or `AETHERFLOW_E2E_ISOLATED` is enabled) in P3, removed legacy cluster daemon startup in P4, and moved `prune_old_transcode_jobs` into the 15-minute maintenance loop (`main.rs:317`, Bundle C).
*   **Rationale:** Integrates dormant-by-default peer startup and periodic maintenance into the API entrypoint.

#### P3.8 [Entry 30]: `backend-rs/crates/af-api/src/peers/listener.rs` (Create)

*   **Implemented Changes:** Bound `<tunnel_ip>:AF_PEER_LISTEN_PORT` with `SO_BINDTODEVICE("afpeer0")` and `ConnectInfo`, serving `/peer/v1/hello`, tunnel `/health`, `/peer/v1/link`, and `/peer/v1/revoke-notice` (P3); added `/peer/v1/grant-{offer,token,revoke}` and scoped management dispatch (`canonicalize` & `/api/v1/` check → `X-AF-Grant-Token` → `peers::scopes::classify` → `PeerPrincipal` + run-as `AuthUser` injection → `routes::build_router()`, auditing allowed/denied calls, P5); added `GET /peer/v1/exports` (P7); added `POST /peer/v1/transcode/mounts` and `GET /peer/v1/transcode/jobs` (P9); enforces per-link concurrency caps, rejects proxy chaining, and fails closed with `403 PEER_ROUTE_UNCLASSIFIED`.
*   **Rationale:** Provides a single tunnel-bound entry point for all peer traffic.

### Phase P4: Cluster UI and legacy retirement

Deletes the legacy single-master cluster backend/UI/tables (Migration 26), rebuilds `/?tab=cluster` on the P3 link API (later extended with grant controls in P5, remote management entry in P6, storage in P7, and transcoding in P9), updates localization catalogs and E2E tests (`wasm.cluster.spec.ts`), and updates reference/operator documentation.

#### P4.1 [Entry 8]: `backend-rs/crates/af-services/src/cluster_daemon.rs` & 11 child modules in `cluster_daemon/` (Delete)

*   **Implemented Changes:** Deleted `cluster_daemon.rs` and all 11 child modules under `backend-rs/crates/af-services/src/cluster_daemon/` (`auth.rs`, `commands.rs`, `grpc.rs`, `master.rs`, `membership.rs`, `receipts.rs`, `receipts/tests.rs`, `tests.rs`, `transport.rs`, `types.rs`, `worker.rs`, cataloged in [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md#phase-file-boundary-expansion)) after P3 ported single-use code issuance/consumption into Entry 13.
*   **Rationale:** Permanently removes the replaced legacy single-master cluster daemon.

#### P4.2 [Entry 9]: `backend-rs/crates/af-services/src/lib.rs` (Modify)

*   **Implemented Changes:** Removed `pub mod cluster_daemon;` and re-exports serving only the legacy cluster daemon.
*   **Rationale:** Keeps `af-services` building after Entry 8 deletion.

#### P4.3 [Entry 10]: `backend-rs/crates/af-api/src/intelligence/cluster.rs` (Delete) & `backend-rs/crates/af-api/src/intelligence.rs`, `backend-rs/crates/af-api/src/intelligence/bandwidth_tests.rs`, `backend-rs/crates/af-api/src/intelligence/media_cluster_tests.rs` (Modify)

*   **Implemented Changes:** Deleted `intelligence/cluster.rs` (`get_cluster_nodes`, `enroll_worker`, `remove_worker`, `dispatch_worker_command`, `list_worker_commands`, `get_worker_metrics`) and its re-exports in `intelligence.rs`; removed legacy cluster tests from `media_cluster_tests.rs` while preserving non-cluster media/bandwidth coverage.
*   **Rationale:** Removes legacy single-master HTTP handlers and tests without regressing unrelated intelligence coverage.

#### P4.4 [Entry 11]: `backend-rs/crates/af-api/src/oidc/keys.rs` (Modify) & `backend-rs/crates/af-api/src/oidc/token_endpoint.rs` (Modify)

*   **Implemented Changes:** Replaced `af_services::cluster_daemon::constant_time_eq` calls in `oidc/keys.rs` and `oidc/token_endpoint.rs` with `af_models::constant_time_eq`.
*   **Rationale:** Decouples OIDC constant-time comparisons from the deleted `cluster_daemon` module.

#### P4.5 [Entry 19]: `backend-rs/crates/af-db/src/lib.rs` (Modify) & `backend-rs/crates/af-db/src/tests.rs` (Modify)

*   **Implemented Changes:** Removed the base `cluster_nodes` DDL and its Migration 5 index (`af-db/src/lib.rs`, see [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md#frozen-preflight-line-citations-702ae0d2--447e04fe)) so fresh databases never create the dropped table or orphan index, added `migrate(&conn, 26, "Remove legacy master/worker clustering", &[...])` dropping `cluster_commands`, `cluster_enrollment_tokens`, and `cluster_nodes` on upgraded databases, and updated the schema version test to `26`.
*   **Rationale:** Removes legacy clustering tables on both fresh and upgraded databases.

#### P4.6 [Entry 23]: `frontend-rs/crates/af-web-app/src/tabs/cluster.rs` (Delete)

*   **Implemented Changes:** Deleted the legacy single-file Cluster tab while leaving `TabId::Cluster` and key `"cluster"` (`af-web-app/src/state/tabs.rs:4-61`, re-exported in `state.rs:43`) intact so `/?tab=cluster` routing stays unchanged.
*   **Rationale:** Clears the way for the modular `tabs/cluster/` implementation in Entry 24.

#### P4.7 [Entry 24]: `frontend-rs/crates/af-web-app/src/tabs/cluster/{mod.rs,peers.rs,pairing.rs}` (Create)

*   **Implemented Changes:** Created the modular Cluster UI (`mod.rs`, `peers.rs`, `pairing.rs`) rendering the peer list (name, plain-language grant directions, health, RTT, version, compatibility), **Allow a server to manage this one** (window copy box + countdown), **Pair with a server** (pairing string + endpoint picker + **Start pairing**), pending confirmation card with 6-digit comparison code (**Approve & link** / **Cancel request** / **Cancel pairing**), revoke/remove and endpoint-edit dialogs listing consequences, and typed `PeerError` action banners.
*   **Rationale:** Delivers the rebuilt `/?tab=cluster` operator UI over the P3 link/pairing API.

#### P4.8 [Entry 25]: `frontend-rs/crates/af-web-app/src/tabs/{mod.rs,l10n.rs}` (Modify) & `frontend-rs/crates/af-web-core/catalogs/{en,de,dk,es,fr,zh}.json` (Modify)

*   **Implemented Changes:** Pointed the `cluster` module at `tabs/cluster/`, added localized Cluster, grant, storage, and transcode translation keys across all six locale catalogs (`en`, `de`, `dk`, `es`, `fr`, `zh`), removed legacy coordinator/worker copy, and updated `e2e/tests/e2e/wasm.cluster.spec.ts`.
*   **Rationale:** Keeps all six UI locales and browser E2E specs aligned with the new Cluster tab.

#### P4.9 [Entry 26]: Documentation, OpenAPI, `.env.example`, & Changelog (Modify)

*   **Implemented Changes:** Updated [docs/API.md](../API.md#8-peer-clustering) (§8 versioned peer routes across P4–P9), [docs/configuration.md](../configuration.md#peer-clustering-and-api-logs) (replaced `CLUSTER_MODE`/`CLUSTER_PSK` with peer env vars), [docs/architecture.md](../architecture.md), [config/openapi-v1.yaml](../../config/openapi-v1.yaml) (peer route parity across P4–P9), [.env.example](../../.env.example) (`AF_PEER_*`), and [CHANGELOG.md](../../CHANGELOG.md) (breaking removal of `CLUSTER_*`). Remaining companion-doc drift is tracked in [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md#deferred-verification--integration-risks).
*   **Rationale:** Keeps API, configuration, and changelog references synchronized with peer-clustering changes.

#### P4.10 [Entry 27]: `docs/peer-clustering.md` (Create)

*   **Implemented Changes:** Created the operator guide ([docs/peer-clustering.md](../peer-clustering.md)) covering prerequisites, pairing, grants and presets, remote management, NFSv4.2 media sharing, distributed Jellyfin transcoding, operational limits/safeguards, link revocation, `af cluster diagnose`, and troubleshooting for all 22 `PeerError` codes.
*   **Rationale:** Gives operators a standalone runbook for configuring and troubleshooting peer clusters.

### Phase P5: Grants and scope enforcement

Adds Migration 27 grant-direction/rotation tables, extends Entry 30 (`peers/listener.rs`) with scoped management dispatch and grant delivery, promotes `tower` to production dependencies (`af-api/Cargo.toml`) and converts backend route registrations across ~35 route/handler files into `TrackedRouter` (exact manifest in [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md#phase-file-boundary-expansion)), adds `PeerPrincipal` middleware integration, and adds the Cluster grant editor.

#### P5.1 [Migration 27]: `backend-rs/crates/af-db/src/{lib.rs,peers.rs,tests.rs}` (Modify) & `backend-rs/crates/af-api/src/storage/backup_tests.rs` (Modify)

*   **Implemented Changes:** Added Migration 27 (`"Peer grant direction metadata"`, `af-db/src/lib.rs:797-811,816`; `PEER_GRANT_METADATA_MIGRATION_27_SQL` at `af-db/src/peers.rs:106-132`) creating `peer_received_grants`, `peer_received_grant_cleanups`, and `peer_grant_epochs`, added `ensure_peer_grant_schema_invariants` (`peers.rs:136-163`), and updated schema max-version tests to `27`.
*   **Rationale:** Separates inbound and outbound grant storage and enables restart-safe generation-fenced credential rotation.

#### P5.2 [Entry 28]: `backend-rs/crates/af-api/src/peers/scopes.rs` (Create) & `backend-rs/crates/af-api/src/routes/inventory.rs` (Create)

*   **Implemented Changes:** Implemented `Area` (8 areas), `Mode`, `ScopeRequirement`, `RouteDecision`, static `FORBIDDEN_RULES` (`ForbiddenRule`) and `ALLOWED_RULES` (`AllowedRule`) tables covering every `TrackedRouter` route (including all 5 explicit write-requiring `GET`/`HEAD` routes and `POST /api/v1/admin/packages/{id}/update`, narrowed in Bundle B(c) so `updates: write` applies strictly to `jellyfin`/`jellyfin-ffmpeg*` via `is_jellyfin_update_package_id` in `scopes.rs:1493-1531` and `routes/marketplace/handlers.rs:188`), `canonicalize`, `classify(&Method, &CanonicalPath) -> RouteDecision` (reusing `crate::plugins::route_pattern_matches` for static/trailing-`/*` `/api/v1/` patterns), `TrackedRouter` in `routes/inventory.rs`, and CI completeness tests walking every production route.
*   **Rationale:** Enforces fail-closed authorization and fails CI tests if any `TrackedRouter` route lacks a scope rule.

#### P5.3 [Entry 29]: `backend-rs/crates/af-api/src/peers/grants.rs` (Create) & `backend-rs/crates/af-api/src/peers/grant_lifecycle_tests.rs` (Create)

*   **Implemented Changes:** Implemented `GET`/`PUT`/`DELETE /api/v1/admin/peers/{id}/grant` (`PUT` rejecting all-`none`), `POST /api/v1/admin/peers/{id}/grant-offer`, presets, `peer-<name>` run-as user provisioning/disabling, 256-bit grant token minting, monotonic `peer_grant_epochs.issuer_generation` fencing, copy-on-write credential staging + `peer_received_grant_cleanups`, tunnel `/peer/v1/grant-{offer,token,revoke}` handlers, `RevocationEvent::GrantRevoked` broadcast, worker-side transcode mount teardown on inbound `transcoding: write` revocation/downgrade (Bundle B(a)), health-loop offline revocation reconciliation via `reconcile_missing_remote_grant` (Bundle C), and lifecycle tests wired via `peers/tests.rs`.
*   **Rationale:** Provides bidirectional grant lifecycle management with restart-safe credential rotation and offline revocation convergence.

#### P5.4 [Entry 32]: `backend-rs/crates/af-api/src/middlewares.rs` (Modify) & `backend-rs/crates/af-api/src/middlewares/{proxy_helpers.rs,subdomain_proxy.rs,host_validation.rs}` (Modify)

*   **Implemented Changes:**
    *   **P5:** Updated `host_validation_middleware` (`middlewares/host_validation.rs`) to skip browser `Host` checks only when `PeerPrincipal` is present.
    *   **P6 & Bundle B(c):** Shared `stream_proxy` (`middlewares/subdomain_proxy.rs:468`, re-exported at `middlewares.rs:27`) and extracted `StreamProxyOptions` (with `stream_cancel` & `StreamProxyErrorKind::Cancelled`), `GuardedBody::wrap_with_cancel`, and `connect_upstream_tcp` helpers in `middlewares/proxy_helpers.rs` for reuse by both `app_subdomain_proxy_middleware` and `peers/proxy.rs`.
*   **Rationale:** Reuses the shared `stream_proxy` transport, authenticates tunnel requests via `PeerPrincipal`, and cancels in-flight HTTP/WS streams on revocation.

#### P5.5 [Entry 33]: `backend-rs/crates/af-api/src/auth.rs` (Modify), `backend-rs/crates/af-api/src/auth/{tokens.rs,middleware.rs,setup_login.rs}` (Modify), & `backend-rs/crates/af-api/src/storage/backups.rs` (Modify)

*   **Implemented Changes:** Defined 9-field `PeerPrincipal` (`auth/tokens.rs:71-81`), exempted `PeerPrincipal` from browser CSRF in `csrf_middleware`, kept `load_active_human_subject` human-only while adding `load_active_peer_subject` / `load_active_subject_for_request` (`auth/tokens.rs:133-160`), blocked `account_type = 'peer'` from password/OIDC login, and updated `storage/backups.rs:694-759,936-965` to accept `PeerPrincipal` (`settings: write`) or the scoped `af_backup_download` cookie.
*   **Rationale:** Reuses existing admin handlers for peer principals without weakening human authentication paths.

#### P5.6 [Entry 36]: `frontend-rs/crates/af-web-app/src/tabs/cluster/grants.rs` (Create)

*   **Implemented Changes:** Built the bidirectional grant editor with per-area **None** / **Read-only** / **Read and write** selectors across all 8 areas, both presets, capability gating, plain-language inbound/outbound direction display, **Save grant**, **Revoke inbound grant** → **Confirm revoke**, and **Send access offer**.
*   **Rationale:** Exposes least-privilege grant controls directly in `/?tab=cluster`.

### Phase P6: Management proxy and server switching

Applies the P6 streaming transport slice of Entry 32, wires the 6-method HTTP/WebSocket management proxy and `<< 1 s` HTTP/WebSocket revocation teardown, and adds reactive browser server switching with `SERVER_EPOCH` and `AreaFence` isolation across all dashboard tabs.

#### P6.1 [Entry 31]: `backend-rs/crates/af-api/src/peers/proxy.rs` (Create) & `backend-rs/crates/af-api/src/peers/proxy_tests.rs` (Create)

*   **Implemented Changes:** Implemented `handle_peer_proxy` (mounted via `tracked_proxy_routes_with_runtime` in `peers/mod.rs:1527` for `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE` on `/api/v1/peers/{id}/{rest}` behind `admin_only_middleware`), validating active link state, dialing the stored tunnel IP, stripping/setting peer auth and `X-AF-Origin-Operator` headers, calling shared `stream_proxy` with `stream_cancel` revocation watching (Bundle B(c)), rewriting root-relative `Location` headers, stripping all `Set-Cookie` except peer-scoped `af_backup_download` (`/api/v1/peers/{id}/admin/backup/download/`), and holding `AF_PEER_MAX_CONN` / `AF_PEER_MAX_WS` permits until stream drop.
*   **Rationale:** Implements the managing-server proxy for remote administration with bounded revocation cancellation.

#### P6.2 [Entry 34]: `backend-rs/crates/af-api/src/ws.rs` (Modify) & `backend-rs/crates/af-api/src/ws/{tickets.rs,telemetry.rs,logs.rs,lifecycle_tests.rs}` (Modify)

*   **Implemented Changes:** Issued WebSocket tickets for peer principals, accepted peer-listener origin/host checks, enforced `AnyReadAccess` (filtered telemetry) and `Services:Read` (live logs), and closed active sockets within 1 s of `RevocationEvent`.
*   **Rationale:** Enables live telemetry and log streaming through the proxy with bounded revocation teardown.

#### P6.3 [Entry 35]: `frontend-rs/crates/af-web-app/src/state/server.rs` (Create), `frontend-rs/crates/af-web-app/src/{state.rs,state/{resources.rs,session.rs,tests.rs},shell.rs,tabs/busy.rs}` (Modify), `frontend-rs/crates/af-web-core/src/{api.rs,ws.rs}` (Modify), & `e2e/tests/e2e/wasm.peer-switching.spec.ts` (Create)

*   **Implemented Changes:** Added `AppContext.active_server_id: RwSignal<Option<String>>` (`state.rs:109`) and pure switching/health predicates (`PeerArea`, `ServerAccent`, `ActivePeerHealth`, `peer_switch_eligibility`, `ServerStateSnapshot` in `state/server.rs`) wired to `af_web_core::api::set_active_server` and `SERVER_EPOCH` / `bump_server_epoch_and_abort`. Added `LogStreamConnection` alongside `BrowserConnection` (both `origin_server_epoch`-fenced), keyed resource caches by server, closed Plugin Sandbox on switch, and preserved local admin sessions on upstream peer `401`/`403` (`af-web-core/src/api.rs` + `state/session.rs`). Wired `AreaFence` (`tabs/busy.rs`) across area-fenced tab views (complete file list in [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md#phase-file-boundary-expansion)) and rendered the colored identity bar with **`Exit to This server`** (`shell.rs`). Added peer-prefixed tus `Location` headers (`mcbrowser/{helpers.rs,transfers.rs,transfers/upload.rs}`), scoped backup downloads (`settings/backups_oidc.rs`), remote update readiness polling via `/api/v1/auth/ready` (`settings/updates.rs`), and Playwright tests (`wasm.peer-switching.spec.ts`).
*   **Rationale:** Mitigates cross-server UI races via `SERVER_EPOCH` response fencing and `AreaFence` action serialization.

### Phase P7: Media over NFS

Applies the P7 storage slice of Entry 22, implements runner-managed NFSv4.2 exports/mounts and sentinel probes, wires `AF_ALLOWED_FS_ROOTS` and Plex safety hooks into existing API routes, and adds Cluster Storage UI controls.

#### P7.1 [Entry 37]: `backend-rs/crates/af-runner/src/peer_storage.rs` (Create)

*   **Implemented Changes:** Implemented all 12 `PeerStorageRequest` actions over `/v1/peer-storage` (`EnsurePackages`, `ConfigureNfsd`, `WriteExports`, `RemoveExports`, `EnsureSentinel`, `ProbeSentinel`, `WriteMount`, `WriteBindMount`, `RemoveMount`, `StartMount`, `StopMount`, `MountStatus`). Derives mount unit names in-process via `systemd_escape_path`, generates `Type=nfs4` + `Options=vers=4.2,soft,timeo=100,retrans=2,{ro|rw},nosuid,nodev,_netdev,x-systemd.requires=wg-quick@afpeer0.service` + `ForceUnmount=yes`, emits `secure,no_subtree_check` on all exports (plus `rw,all_squash,anonuid=<uid>,anongid=<gid>` for non-root writable exports), and guards managed files with `PEER_MANAGED_HEADER`. Bundle A added managed `nfs-server.service.d/20-aetherflow-peers.conf` + unmanaged `/etc/exports` warning in `ConfigureNfsd`, and single-flight + `MAX_CONCURRENT_SENTINEL_PROBES = 4` dedicated OS threads in `ProbeSentinel`.
*   **Rationale:** Keeps privileged NFS and mount-unit synthesis inside `af-runner` without blocking unrelated runner IPC.

#### P7.2 [Entry 38]: `backend-rs/crates/af-runner/src/peer_storage/tests.rs` (Create)

*   **Implemented Changes:** Added unit tests using isolated `PeerStorageManager` fixtures covering export line options, unit escaping, `nfsd` host config and boot drop-in, non-root writable checks, `PEER_MANAGED_HEADER` protection, `SentinelProbeCoordinator` concurrency isolation, and write-boundary isolation.
*   **Rationale:** Verifies privileged NFS export and systemd unit generation safely without host mutations.

#### P7.3 [Entry 39]: `backend-rs/crates/af-api/src/peers/{storage.rs,storage_tests.rs}` (Create) & `backend-rs/crates/af-api/src/{routes/{fs_browser.rs,streaming.rs},intelligence/scan_cursor.rs}` (Modify)

*   **Implemented Changes:** Implemented admin `GET`/`POST`/`DELETE /api/v1/admin/peers/{id}/exports` and `/mounts` (`available_exports` + `exports_error`) and tunnel `GET /peer/v1/exports`. Re-exported `get_allowed_fs_roots` / `is_fs_path_allowed` from `routes/fs_browser.rs`, added interior-subfolder validation for MediaFlow in `intelligence/scan_cursor.rs:49`, wired the Plex safety hook (`peers/storage.rs:3168-3228`) into `routes/streaming.rs:153-155`, wired health-loop media-mount gating (`PeerStorageRunner`), and added automatic best-effort transcode worker mount resync on export/mount changes (Bundle A).
*   **Rationale:** Provides peer media sharing with automatic sentinel mount protection, Plex/MediaFlow safety integration, and transcode mount synchronization.

#### P7.4 [Entry 40]: `frontend-rs/crates/af-web-app/src/tabs/cluster/storage.rs` (Create)

*   **Implemented Changes:** Built the Cluster Storage UI with folder export picker (**Export folder**), read-only/writable toggle and warning, remote export mount list (**Mount folder**), mount state/last error display, interior library-subfolder guidance, and RTT warning banner.
*   **Rationale:** Gives operators direct NFS export/mount controls and latency visibility per link.

### Phase P8: Local transcode foundation

Adds the standalone `af-transcode` Rust crate (`wincode 0.6.3` wire protocol, Jellyfin argv parser, shim/worker/capabilities CLI modes) and extracts `af_hardware::detect_render_nodes()` with local integration tests.

#### P8.1 [Entry 41]: `backend-rs/Cargo.toml` (Modify) & `backend-rs/Cargo.lock` (Modify)

*   **Implemented Changes:** Added `"crates/af-transcode"` to workspace members plus `af-transcode`, `wincode = { version = "0.6.3", features = ["derive"] }`, and `nix = { version = "0.31.3", default-features = false, features = ["signal", "process"] }`.
*   **Rationale:** Integrates `af-transcode` and supply-chain-compliant dependencies into the locked backend workspace.

#### P8.2 [Entry 42]: `backend-rs/crates/af-transcode/{Cargo.toml,src/lib.rs,src/main.rs,src/config.rs}` (Create)

*   **Implemented Changes:** Configured crate dependencies (`af-hardware`, `af-models`, `anyhow`, `libc`, `nix`, `serde`, `serde_json`, `thiserror`, `tokio`, `tracing`, `tracing-subscriber`, `wincode`), defined socket paths, env var names/bounds (`DEFAULT_TRANSCODE_ENV_FILE`, `ALLOWED_ENV_KEYS`, `WORKER_BASELINE_ENV_KEYS`, `DEFAULT_WORKER_MAX_JOBS = 8`, `MAX_WORKER_MAX_JOBS = 64`, `DEFAULT_HANDSHAKE_TIMEOUT = 2 s`, `RECOMMENDED_DISPATCHER_REMOTE_START_TIMEOUT = 1,500 ms`, `resolve_worker_child_cwd`), and implemented `main.rs` mode dispatch (`argv[0] == "ffmpeg"` shim, `worker`, `capabilities`).
*   **Rationale:** Shares configuration and binary entrypoints across shim, worker, and probe modes.

#### P8.3 [Entry 43]: `backend-rs/crates/af-transcode/src/protocol.rs` (Create)

*   **Implemented Changes:** Implemented the 10-variant `Frame` enum (`0..=9` including `StdinEof` and structured `Error { kind, message }`), `wincode` bincode-v1 framing with 4-byte BE length prefix, 1 MiB `MAX_FRAME_BYTES` pre-deserialization bound, trailing-byte rejection, structural caps (`MAX_START_ARGS = 512`, `MAX_START_ARG_BYTES = 64 KiB`), and bounded channel helpers.
*   **Rationale:** Provides bounded, deterministic binary framing across Unix sockets and WebSockets.

#### P8.4 [Entry 44]: `backend-rs/crates/af-transcode/src/argv.rs` (Create)

*   **Implemented Changes:** Implemented `is_probe(args)`, `required_capability(args) -> Capability { hwaccel, required_hwaccels, encoder, filters, render_nodes }`, `rewrite_render_node(args, from, to)`, `WORKER_LOCAL_PROTOCOL_WHITELIST` / `has_network_input` / `validate_worker_args` / `inject_local_protocol_whitelist` (Bundle B(d)), and table-driven tests from real Jellyfin VA-API, QSV, NVENC, software, subtitle burn-in, network-input, and probe command lines.
*   **Rationale:** Classifies Jellyfin `ffmpeg` hardware requirements, remaps worker render nodes, and enforces local-only protocol confinement on isolated workers.

#### P8.5 [Entry 45]: `backend-rs/crates/af-transcode/src/shim.rs` (Create)

*   **Implemented Changes:** Sets `AF_TRANSCODE_SHIM_ACTIVE` before local `exec` and refuses recursive invocation with exit code `1` (`shim.rs:108-114`); executes local `ffmpeg` on probes (`is_probe`), non-UTF-8 Unix argv, explicit `RunLocal`, or definite failure/timeout before all bytes of `Frame::Start` are written to `transcode.sock` (`shim.rs:273-278,356-389`); enforces the 2-second handshake budget; pumps `Stdin`/`StdinEof`/`Stdout`/`Stderr`/`Signal` and exits non-zero on post-`Start` stream drop without duplicate local execution.
*   **Rationale:** Preserves local Jellyfin reliability and prevents fork-bombs or duplicate encodes.

#### P8.6 [Entry 46]: `backend-rs/crates/af-transcode/src/{worker.rs,capabilities.rs}` (Create) & `backend-rs/crates/af-transcode/tests/integration.rs` (Create)

*   **Implemented Changes:** Implemented `worker.rs` listening on `/run/aetherflow-transcode-worker/worker.sock` (`0660`), enforcing `AF_TRANSCODE_WORKER_MAX_JOBS`, `WORKER_LOCAL_PROTOCOL_WHITELIST`, and `resolve_worker_child_cwd`, remapping `/dev/dri/renderD*`, isolating env to `WORKER_BASELINE_ENV_KEYS` + validated `ALLOWED_ENV_KEYS`, forwarding signals, and killing its `ffmpeg` process group on unexpected disconnect; implemented `capabilities.rs` querying `dpkg-query -W -f=${Status}\t${Package}\t${Version}\n jellyfin-ffmpeg*`, `ffmpeg -version`/`-encoders`, `af_hardware::detect_render_nodes()`, and `worker_max_jobs`; added end-to-end local integration tests.
*   **Rationale:** Executes remote `ffmpeg` jobs under bounded concurrency and local-only protocol/cwd confinement while reporting authoritative worker hardware/package capabilities.

#### P8.7 [Entry 47]: `backend-rs/crates/af-hardware/src/lib.rs` (Modify)

*   **Implemented Changes:** Extracted `pub fn detect_render_nodes() -> Vec<RenderNode>` from `get_gpu_transcode_flags`, consumed by `af-transcode/src/capabilities.rs` while preserving legacy GPU selection ordering.
*   **Rationale:** Reuses existing DRM render-node detection logic without duplicating hardware probing.

### Phase P9: Remote transcoding and standalone regression

Applies the P9 transcode slice of Entry 22, wires the API dispatcher/worker relay and runner transcode operations, adds the Cluster transcoding UI and `af cluster diagnose` CLI, updates Jellyfin's sandbox profile, stages `bin/af-transcode` in release bundles, and verifies standalone regression suites.

#### P9.1 [Entry 48]: `backend-rs/crates/af-api/src/peers/{transcode.rs,transcode_tests.rs}` (Create) & `backend-rs/crates/af-api/{Cargo.toml,src/routes/{health.rs,marketplace/job_runner.rs}}` (Modify)

*   **Implemented Changes:** Added `af-transcode` to `af-api/Cargo.toml` (using workspace `sha1` for the custom RFC 6455 tunnel WS client with `WsWriteError::BeforeAnyBytesSent`). Implemented the Unix-socket dispatcher (`/run/aetherflow-transcode/transcode.sock`, `0660 aetherflow:jellyfin` via `fchownat`), weighted random worker selection with `effective_worker_max_jobs` clamping and `RunLocal` bypass for network inputs, 7-day job pruning (moved to `main.rs:317` in Bundle C), tunnel `GET /peer/v1/transcode/jobs` & `POST /peer/v1/transcode/mounts` (allowlist + calling-link confinement + atomic rollback + SQLite tx in Bundle A), and admin `GET`/`PUT /api/v1/admin/peers/transcode` (global switch with automatic teardown on `enabled: false` and `worker_service_enabled: false`, worker toggle, `weight`/`max_jobs`, 5 s parity test via `CleanupParityFile`, `api_restart_scheduled`). Added `"transcode"` to `peers::capabilities()`, public `/health` `"transcode": null` + tunnel `/health` cached capabilities, and cache invalidation on `jellyfin`/`jellyfin-ffmpeg` updates in `routes/marketplace/job_runner.rs:967-971`.
*   **Rationale:** Implements the control plane, capability lifecycle, and tunnel relay for distributed Jellyfin transcoding.

#### P9.2 [Entry 49]: `backend-rs/crates/af-runner/src/{peer_transcode.rs,peer_transcode/tests.rs}` (Create)

*   **Implemented Changes:** Implemented all 15 `PeerTranscodeRequest` actions over `/v1/peer-transcode` (`InspectJellyfinPaths`, `EnsureDispatcherDir`, `InstallShim`, `EnableJellyfin`, `DisableJellyfin`, `InstallWorkerUnit`, `RemoveWorkerUnit`, `ExportTranscodeDirs` [`st_dev`-pruned], `RemoveTranscodeExports`, `MountTranscodeDirs` [allowlist + atomic rollback], `RemoveTranscodeMounts`, `BindMedia` [`calling_link_segment`, allowlist + empty-dir check + conditional `BindsTo=`/`After=`], `RemoveBindMedia`, `ScheduleApiRestart` [debounced `--unit=aetherflow-transcode-api-restart`], `CleanupParityFile`; details in [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md#phase-p9-remote-transcoding-and-standalone-regression-plus-bundles-ad-hardening)), managing `/etc/aetherflow/transcode.env`, `/etc/exports.d/aetherflow-peer-<link_id>-transcode.exports`, `/etc/tmpfiles.d/aetherflow-transcode.conf`, `aetherflow-api.service.d/20-aetherflow-transcode.conf`, `aetherflow-runner.service.d/20-aetherflow-transcode.conf`, `jellyfin.service.d/20-aetherflow-transcode.conf`, hardened `af-transcode-worker.service`, and dynamic `af-transcode-worker.service.d/30-aetherflow-transcode-paths.conf` while keeping `jellyfin` outside group `aetherflow`.
*   **Rationale:** Isolates privileged systemd, NFS, shim, and temp-file cleanup actions inside `af-runner`.

#### P9.3 [Entry 50]: `frontend-rs/crates/af-web-app/src/tabs/cluster/transcode.rs` (Create)

*   **Implemented Changes:** Built the inline **Jellyfin transcoding** section in **Cluster** with **Use paired servers for Jellyfin transcoding**, **Run this server as a transcode worker**, `jellyfin-ffmpeg` version-alignment table + **Update to match** (`POST /api/v1/admin/packages/jellyfin/update`, accepting `updates: write || marketplace: write` via `resolve_align_action_for_peer`), per-worker **Enable worker** / **Weight (1–100)** / **Max jobs (1–64)** controls (**Save worker**, **Run parity test**), and recent job history.
*   **Rationale:** Exposes transcoding enablement, alignment, and diagnostics directly inside `/?tab=cluster`.

#### P9.4 [Entry 51]: `backend-rs/crates/af-cli/src/commands/cluster.rs` (Create), `backend-rs/crates/af-cli/src/tests/cluster_tests.rs` (Create), `backend-rs/crates/af-cli/{Cargo.toml,src/{lib.rs,cli.rs,cli/parse.rs,cli/help.rs,client.rs,commands.rs,tests.rs}}` (Modify), & Release/Packaging Scripts (Modify)

*   **Implemented Changes:**
    *   **CLI diagnostics:** Added `af-db`/`rusqlite` to `af-cli/Cargo.toml`, parsed `cluster diagnose <link> [--db <path>]` in `cli/parse.rs` alongside global `--json`, `--socket`, `--root`, and `--dry-run` flags, added help text in `cli/help.rs` and runner client helpers in `client.rs`, and implemented read-only SQLite + runner inspection (redacting secrets, capping at 10 recent jobs and 20 audit rows) in `commands/cluster.rs` with tests in `tests/cluster_tests.rs`. Bundle C aligned JSON keys and labels to canonical `inbound`/`outbound`, added canonical `state` alongside `internal_state` and `wg_peer_owned`, restricted live `MountStatus`/`ProbeSentinel` probes to `purpose == "media"` (`probe: null` + `probe_skipped_reason` for `transcode`/`transcode_bind`), and migrated DB path resolution to shared `af_models` helpers with `--root` confinement.
    *   **Release packaging & self-update refresh:** Staged `bin/af-transcode` (`0755`) across `scripts/build_gold.sh`, `.github/workflows/release.yml`, `af-release/src/artifact/archive.rs` (`config_artifact_tests.rs`), `deploy/release-manager.sh`, `setup/modules/{modern_stack.sh,05-finalize.sh}`, VM matrix helpers, and Python release contract suites (exact file list in [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md#phase-file-boundary-expansion)), guarding each script with `[[ -f ... && ! -L ... ]]` so older bundles without `bin/af-transcode` remain installable. Bundle A added atomic refresh of existing `/usr/lib/aetherflow/transcode/ffmpeg` shims (dormant if absent, refusing symlinks) and conditional restart of active `af-transcode-worker.service` in both `af-release/src/health.rs` and `deploy/release-manager.sh`.
*   **Rationale:** Delivers read-only incident diagnostics and backward-compatible distribution and upgrade refresh of `bin/af-transcode` across build, CI, and installer pipelines.

#### P9.5 [Entry 52]: `config/package_automation.json` (Modify)

*   **Implemented Changes:** Added `"-/run/aetherflow-transcode"` (broadened in Bundle A from single socket file `transcode.sock` in P9) to Jellyfin's `sandbox_rw_paths` (`config/package_automation.json:35` in `25-36`); the leading `-` keeps the path optional when transcoding is disabled.
*   **Rationale:** Allows sandboxed Jellyfin (`dotnet` profile) to connect to the dispatcher socket cleanly across `aetherflow-api.service` restarts without stranding on an unlinked socket inode (upgraded hosts run `sudo af sandbox apply jellyfin` once).

### Post-P9 Pre-Release Hardening (Bundles A–D)

All pre-release escalation items tracked after `f20a3a99` landed on `feat/peer-clustering` across four cohesive hardening bundles (full details in [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md#tracked-pre-release-escalation-queue)):

*   **Bundle A (Security & Runtime Reliability):** Wired `PeerNetworkRequest::EnsurePackages` into `pairing.rs::ensure_local_identity`; added `afpeer0` `ifindex` tracking (`ListenerHandle`, `TunnelClientBindingKey`, `clear_tunnel_clients`) and health-tick `reconcile_dispatcher_if_configured`; broadened Jellyfin sandbox `ReadWritePaths` to directory `"-/run/aetherflow-transcode"`; added self-update shim refresh + active worker restart in `af-release/src/health.rs` and `deploy/release-manager.sh`; enforced worker `MountTranscodeDirs` allowlist, `BindMedia.calling_link_segment` confinement, controller-holds-media allowlist + empty-dir check + conditional `BindsTo=`/`After=`, atomic mount rollback + SQLite transaction, `st_dev`-pruned transcode exports, hardened `af-transcode-worker.service` + dynamic `30-aetherflow-transcode-paths.conf`, managed `nfs-server.service.d/20-aetherflow-peers.conf` + unmanaged `/etc/exports` warning, `ProbeSentinel` single-flight + `MAX_CONCURRENT_SENTINEL_PROBES = 4` dedicated OS threads, pairing `https_url` SSRF + DNS pinning, transcode-before-storage link revocation ordering with error propagation, per-unit runner transcode locks, `180 s` mount-sync timeout, deterministic `ScheduleApiRestart` debounce, P7 storage auto-resync, no-op `transcode_workers` upsert skipping, and `tracing::warn!` on malformed `AF_PEER_*` env vars.
*   **Bundle B (Design Decisions `(a)`–`(d)`):** Implemented `(a)` automatic teardown on `enabled: false`, `worker_service_enabled: false`, and worker inbound `transcoding: write` revocation/downgrade; `(b)` secret-free `/etc/aetherflow/transcode.env` (`0640 root:jellyfin`) loaded by all 4 consuming units + `worker_max_jobs` advertisement and controller auto-clamping; `(c)` managing-side and target-side in-flight non-WS HTTP stream cancellation on `RevocationEvent` (`<< 1 s`) + narrowing `updates: write` package updates strictly to `jellyfin`/`jellyfin-ffmpeg*`; and `(d)` worker `WORKER_LOCAL_PROTOCOL_WHITELIST` + `cwd` clamping, dispatcher `RunLocal` bypass for network inputs, and public `GET /health` `"transcode": null`.
*   **Bundle C (CLI, Protocol, & Observability Parity):** Aligned `af cluster diagnose` to canonical `inbound`/`outbound` grants, public `state` + `internal_state`/`wg_peer_owned`, media-only probes, and `af_models` DB resolution + `--root` confinement; added health-loop offline `grant-revoke` reconciliation via tunnel `/health` `"inbound_grant_generation": null`; moved `prune_old_transcode_jobs` to `main.rs:317`'s 15-minute maintenance loop; standardized `PeerError` JSON across all `Bytes`/`Json` extractors with `request_id` in `PeerErrorBody` and Cluster UI `PeerErrorAlert`; and propagated `X-Request-ID` into `aetherflow-runner` Unix socket requests and logs.
*   **Bundle D (Documentation & Contract Sync):** Synchronized all 3 peer-clustering documents (`docs/peer-clustering.md`, `docs/designs/peer-clustering.md`, `docs/designs/peer-clustering-drift.md`) and companion docs/configs with the live post-hardening implementation.

--------------------------------------------------------------------------------

## Verification Plan

Local build, test, lint, supply-chain, and standalone E2E gates passed on Server A through `f20a3a99` and cover the post-P9 hardening Bundles A–D on `feat/peer-clustering`. Two-server acceptance checks remain tracked against the corresponding phase commits until Server B is provisioned.

### Common local gate for every phase

Run all commands from repository root (there is no root `Cargo.toml`; see [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md#authoritative-local-and-ci-verification-commands) for exact CI parity and Playwright/Python E2E invocations):

1.  Build backend: `cargo build --manifest-path backend-rs/Cargo.toml --workspace --release --locked`.
2.  Build frontend: `(cd frontend-rs && trunk build --release)` (or `bash scripts/build_wasm_frontend.sh --stage` to stage `web/dist/`).
3.  Run unit and integration tests: `cargo test --manifest-path backend-rs/Cargo.toml --workspace --locked` (`-- --test-threads=1` in `.github/workflows/release.yml:218`; `RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"` in `scripts/build_gold.sh:378`) and `cargo test --manifest-path frontend-rs/Cargo.toml --workspace --locked`.
4.  Run static, formatting, supply-chain, and hygiene checks across both workspaces:
    *   `cargo fmt --manifest-path backend-rs/Cargo.toml --all -- --check` & `cargo fmt --manifest-path frontend-rs/Cargo.toml --all -- --check`
    *   `cargo clippy --manifest-path backend-rs/Cargo.toml --workspace --all-targets --locked -- -D warnings`
    *   `cargo clippy --manifest-path frontend-rs/Cargo.toml --workspace --all-targets --locked -- -D warnings` & `cargo clippy --manifest-path frontend-rs/Cargo.toml --workspace --target wasm32-unknown-unknown --locked -- -D warnings`
    *   `cargo deny --manifest-path backend-rs/Cargo.toml --locked check advisories bans licenses sources`, `cargo deny --manifest-path frontend-rs/Cargo.toml --locked check advisories bans licenses sources`, `cargo audit --file backend-rs/Cargo.lock`, `cargo audit --file frontend-rs/Cargo.lock`, `python3 scripts/finalize_wasm_assets.py --self-test`, and `python3 tests/check_shell_hygiene.py`.
5.  Run local phase-specific fixture checks strictly against isolated fixtures without modifying host WireGuard, NFS, or systemd.

### Local phase-specific checks (historical commit gates)

Each phase commit (`a80f123b`–`f20a3a99`) passed its phase-specific suite below at landing; at branch HEAD (`f20a3a99`), `af-db/src/tests.rs` asserts `max_ver == 27` and `peers::capabilities()` returns all four capabilities (`["links", "grants", "storage", "transcode"]`):

*   **P0 (`a80f123b`):** Tested Migration 25 (`max_ver == 25`) on fresh and legacy databases, bounded 128-byte `X-Request-ID` in JSON logs, and `/health` protocol 1 with `[]`.
*   **P1 (`4e1255cb`):** Tested local URL/CSRF behavior, single peer-prefix rewriting, malformed-path rejection, telemetry ticket/URL paths, local-only profile avatars, and direct call sites.
*   **P2 (`e8ebe461`):** Tested WireGuard config generation, `syncconf`, `Status` (`present_live` vs. `persistent`), route-check rollback, `PeerCredentialSlot` files, and `wg0.conf` preservation with fake `wg` fixtures.
*   **P3 (`1848be91`):** Tested pairing expiry/reuse, closed windows, rate limiting, typed `PeerError` responses, wrong tunnel source, attempt-bound bootstrap, retries, 10-state `peer_links.state` projection, lazy listener startup, and revocation.
*   **P4 (`f2c2c85f`):** Verified Migration 26 (`max_ver == 26`) on fresh and upgraded databases, removal of legacy `cluster_daemon/` and `cluster_*` routes/tables, and Cluster tab wiring (`e2e/tests/e2e/wasm.cluster.spec.ts`).
*   **P5 (`8e9ec370`):** Verified Migration 27 (`max_ver == 27`), `ensure_peer_grant_schema_invariants`, `TrackedRouter` route-classification completeness, canonicalization (`//`, `%2e%2e`, mixed case), forbidden routes, all 5 write-requiring `GET`/`HEAD` routes, `ScopeRequirement::Any` package update rule, wrong source/token denials, audited peer metadata, and healthy links after grant revocation.
*   **P6 (`6dc2dbee`):** Tested 6-method proxy header/cookie stripping (`af_backup_download` scoping), request/response streaming permits, WebSocket ticket/upgrade/1-second revocation closure, `SERVER_EPOCH`/`AreaFence` frontend isolation, and `e2e/tests/e2e/wasm.peer-switching.spec.ts`.
*   **P7 (`86a81951`):** Used fake `exportfs`/mount/sentinel fixtures for `PeerStorageRequest` runner-derived options, `FORBIDDEN_EXPORT_PREFIXES`, non-root writable enforcement, `PEER_MANAGED_HEADER`, `apply_plex_peer_mount_safety_best_effort`, and immediate mount stop on peer removal or stale WireGuard handshake (`> 180 s`).
*   **P8 (`03940e70`):** Tested all 10 `wincode 0.6.3` frames (`0..=9`, `StdinEof`), oversized/trailing-byte rejection, 5-field `Capability` across real Jellyfin argv cases, `AF_TRANSCODE_SHIM_ACTIVE` exit-1 recursion guard, non-UTF-8 local fallback, shim handshake/signal/disconnect handling, and `detect_render_nodes()`.
*   **P9 (`f20a3a99`):** Verified `bin/af-transcode` release bundle staging and backward compatibility, dispatcher selection, `WsWriteError::BeforeAnyBytesSent` no-duplicate boundary, `POST /peer/v1/transcode/mounts`, parity test + `CleanupParityFile`, `ScheduleApiRestart`, `af cluster diagnose` read-only/redaction/offline behavior, `e2e/tests/e2e/wasm.cluster.spec.ts`, and standalone Python `tests/e2e/` tiers.

### Deferred two-server acceptance

After Server B is provisioned, run the checks below in order on approved candidates targeting `afpeer0` while verifying `wg0` remains untouched:

*   **P0:** Verify protocol 1 and capabilities in `/health` on both deployed servers, plus standalone sign-in.
*   **P1:** Smoke-test both deployed dashboards and existing telemetry.
*   **P2:** Confirm peer networking stays dormant on both deployed hosts before initial pairing.
*   **P3:** Pair over private VLAN via admin API; verify healthy link before grants, restart `wg-quick@afpeer0.service` while `aetherflow-api.service` stays running (verifying listener recovery), revoke from B, verify notice on A, re-pair, and confirm `wg0` preservation.
*   **P4:** Confirm Migration 26 applied cleanly on both hosts; repeat pair, endpoint edit, and revoke via `/?tab=cluster`; confirm standalone startup and `wg0` preservation.
*   **P5:** Exercise `none`, `read`, and `write` scopes, two-way grants, target audit entries, and link health surviving grant revocation.
*   **P6:** Browse all tabs under a read-only grant, force a write (`403 PEER_SCOPE_DENIED` + audit), then with write access restart a service, change a setting, install/uninstall a Marketplace app, upload a 2 GB file via McBrowser `tus`, verify live logs close within 1 s of revocation, and confirm identity bar + audit entries.
*   **P7:** Export the test library read-only from B, scan and play a 4K remux over NFSv4.2 from A, remove B's `afpeer0` peer on A, verify mount stops and interior `/library` path disappears within 30 s, confirm Jellyfin 12.4 keeps items across a scan, verify mount recovery, and test host reboot ordering (`wg-quick@afpeer0.service` vs. `nfs-server.service`).
*   **P8:** Confirm local Jellyfin playback succeeds unchanged on both hosts when transcode offloading is disabled.
*   **P9:** Run live distributed transcoding acceptance:
    1.  Run `sudo af sandbox apply jellyfin` if upgraded, enable B as a worker (with `jellyfin.service` stopped/disabled on B), pass **Run parity test**, play a VA-API job, and verify `ffmpeg` runs on B with HLS segments written to A, Jellyfin progress updates advancing, seek restarting without playback error or orphaned worker `ffmpeg` processes, and stop terminating remote `ffmpeg`.
    2.  Force an NVENC job and confirm local execution on A; stop `aetherflow-api` on A and confirm local fallback.
    3.  Revoke the link mid-stream: active remote job terminates without duplicate local encode, and subsequent playback runs locally.
    4.  Upgrade `jellyfin-ffmpeg` on one server: verify mismatch notification, local fallback, **Update to match** alignment, and re-eligibility within one health tick.
    5.  Pause worker `ffmpeg` with `kill -STOP` to trigger Jellyfin's stop timeout; within timeout + 5 s verify zero orphan worker processes (`pgrep -u jellyfin ffmpeg`).
    6.  Confirm Jellyfin reports `/usr/lib/aetherflow/transcode/ffmpeg`.

--------------------------------------------------------------------------------

## Future Improvements

*   **`rclone` for high-latency WAN peers:** Optional storage transport when RTT regularly exceeds `AF_PEER_RTT_WARN_MS`.
*   **In-band WireGuard key rotation:** If re-pairing proves operationally disruptive.
*   **Multi-server fleet views:** Topology and combined aggregate dashboards beyond two-server setups.
*   **Per-link worker mount namespaces:** Isolating `/var/cache/jellyfin*` mounts per controller to lift the 1-controller-per-worker constraint.
*   **`tokio-tungstenite` transcode client reuse:** Wrapping `tokio-tungstenite::client_async` over a byte-counting `SO_BINDTODEVICE` stream (reusing `middlewares/proxy_helpers.rs::connect_upstream_tcp`) to retire the custom RFC 6455 client in `peers/transcode.rs`.
*   **Plex and Emby remote transcoding:** If either vendor exposes a supported transcoder hook.

## Additional Resources

*   [docs/API.md](../API.md#8-peer-clustering)
*   [docs/configuration.md](../configuration.md#peer-clustering-and-api-logs)
*   [docs/architecture.md](../architecture.md)
*   [docs/rust-admin-cli.md](../rust-admin-cli.md)
*   [docs/peer-clustering.md](../peer-clustering.md)
*   [docs/designs/peer-clustering-drift.md](peer-clustering-drift.md)
*   [Jellyfin documentation](https://jellyfin.org/docs/) (hardware acceleration, `rffmpeg` shared paths, Debian installation, `JELLYFIN_FFMPEG` configuration)
*   Debian 13 manuals: `nfs.conf(5)` (`/etc/nfs.conf.d`, `[nfsd] host=`), `exports(5)`, `wg-quick(8)`.

--------------------------------------------------------------------------------

<!-- Provenance: Initial structural drafting via EGM; Round 1, Round 2, Round 3, Round 4, and Round 5 Goldfish review fixes applied on feat/peer-clustering. -->

*Drafted with EGM*
