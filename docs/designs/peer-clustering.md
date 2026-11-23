# AetherFlow Peer Clustering

*   **Author:** Donovan Everitt
*   **Status:** Ten-phase implementation plan. Local preflight passed on server A.
*   **Supersedes:** The five-phase plan, `concepts_brief.md` and `peer_clustering_plan.md`. The original 52 file numbers still identify the work.
*   **Date:** 2026-11-22
*   **Code baseline:** `nightly` @ `702ae0d2` ("Hide direct launch URLs for loopback-only marketplace apps"). This was the head of `origin/nightly` when fetched on 2026-11-22, and it is 97 commits ahead of `master` (`32f324e1`). All file and line references below point at this commit. The implementation worktree starts at nightly `447e04fe`. Use the [drift report](peer-clustering-drift.md) for current source targets.
*   **Target environment:** Debian 13 "trixie" on both servers, with Jellyfin **12.4**. Jellyfin dropped the `10.` prefix after 10.11, so 12.x is the successor of 10.11.

--------------------------------------------------------------------------------

## Overview

Peer Clustering lets several servers, each running a full copy of AetherFlow, manage each other from the existing Cluster page (`/?tab=cluster`).

Two servers **pair** with each other. Pairing creates an encrypted **WireGuard link** that AetherFlow manages itself. Over that link:

*   A server with a **grant** manages the other server through that server's own existing API. A grant sets read-only or read-write access per area, and it can be one-way or two-way.
*   Media folders are shared with **NFS inside the tunnel**.
*   Jellyfin transcodes go to a paired server with a matching encoder, through a **Rust-native transcode dispatcher**.

This replaces the current master/worker clustering in `backend-rs/crates/af-services/src/cluster_daemon.rs`, which gets deleted.

## The Problem

Today AetherFlow can manage only the server it runs on. Its clustering is a single-master fleet monitor:

*   One role per node (`CLUSTER_MODE=standalone|master|worker`).
*   Heartbeats every 5 seconds.
*   TLS certificates provisioned by hand.
*   A command queue limited to start, stop, restart, reload and ping.

It can't manage another server's settings, Marketplace apps, files or users. It can't stream media between servers or share transcoding work, and it has no two-way management.

The author is adding a second datacenter server and needs to manage both from one place. Both servers have 1 Gbps+ links and may share a private VLAN.

The solution is peer links with scoped grants, a generic management proxy, NFS media sharing and transcode offload, all inside one WireGuard tunnel. No feature needs its own remote-control code.

## Goals

*   Pair two AetherFlow servers from `/?tab=cluster` by pasting one string and confirming a matching fingerprint. No hand-made certificates or env-file edits.
*   Grants can be one-way or two-way. Each grant sets **none / read-only / read-write** for every area: services, Marketplace, settings, files, users, network, updates, transcoding. There are two presets, **Read-only (everything)** and **Read and write (everything)**.
*   A server holding a read-write grant can do everything the target's own dashboard can, through the target's own API. Every dashboard tab works without remote code written for that tab.
*   A read-only grant must never allow a change on the target. Unknown routes are denied.
*   Media folders are shared over NFS inside the tunnel, read-only by default. If the link fails, mounts never show up as empty library folders.
*   Jellyfin transcodes run on a paired server whose encoder matches the job. An unavailable worker triggers local execution before a job starts. A dropped remote stream ends that job and Jellyfin can retry locally.
*   Either side can revoke a link or grant, and the revocation cuts every flow immediately.
*   Every action a peer takes is audited on the target with the link, the run-as account, the operator and the request ID.
*   Each server keeps working on its own when its peers are unreachable.
*   All new AetherFlow code is Rust.

## Non-Goals

*   High availability, automatic failover, moving services between servers, or general app scheduling. Distributed transcoding is the only cross-server compute in scope.
*   Desired-state configuration management, where one server declares another's config.
*   Proxying third-party app UIs (Sonarr, Plex and so on) through the link. Those open on the peer's own URL.
*   NAT traversal and relays. Both servers must be directly reachable on the chosen endpoint.
*   Topology views and combined dashboards for many servers.
*   Remote transcoding for Plex or Emby.
*   Rotating keys in band. A key changes by re-pairing.
*   Migrating legacy `cluster_nodes` enrollments. The legacy system is deleted, not migrated.

## Environment Facts (Debian 13 + Jellyfin 12.4)

Use Jellyfin 12.4 on both servers with matching apt package versions. Verify the media and transcode assumptions on the actual pair during P7 and P9.

| Topic | Fact | Design consequence |
| :--- | :--- | :--- |
| **Jellyfin ffmpeg path** | Since 10.9, the ffmpeg path in the dashboard is read-only, and 12.x keeps it that way. Jellyfin takes its ffmpeg path from the `JELLYFIN_FFMPEG` environment variable or the `--ffmpeg` startup argument. | af-runner adds a systemd drop-in, `/etc/systemd/system/jellyfin.service.d/20-aetherflow-transcode.conf`, separate from the sandbox drop-in `aetherflow-sandbox.conf` / `10-aetherflow-sandbox.conf` (`backend-rs/crates/af-runner/src/lib.rs:3670`), setting `Environment=JELLYFIN_FFMPEG=/usr/lib/aetherflow/transcode/ffmpeg`. It doesn't edit `encoding.xml` or AetherFlow's own sandbox drop-in. |
| **Jellyfin stop sequence** | Jellyfin stops a transcode by writing `q` to ffmpeg's stdin. If ffmpeg hasn't exited when the timeout runs out, Jellyfin kills the **whole process tree**. | stdin is relayed, which covers `q`. A process-tree kill is SIGKILL, which the shim can't catch, so the **dispatcher** notices the shim's socket closing without an `Exit` frame and sends `Signal(Kill)` to the worker. The worker also kills ffmpeg if its stream drops. |
| **Jellyfin temp folder** | rffmpeg-style setups need Jellyfin 10.10+ to point `TMPDIR` at storage the worker can also reach, because ffmpeg writes auxiliary files there. | The same drop-in sets `Environment=TMPDIR=/var/cache/jellyfin/af-tmp`, and that folder is exported to workers together with the transcode folder. |
| **Jellyfin paths under AetherFlow** | AetherFlow installs Jellyfin from apt (`config/package_automation.json:20-38`). It keeps data and config in `/var/lib/jellyfin` (config under `/var/lib/jellyfin/config`, per `backend-rs/crates/af-runner/src/app_metadata.rs:602-621`) and the cache in `/var/cache/jellyfin`. The real ffmpeg comes from the `jellyfin-ffmpeg` package at `/usr/lib/jellyfin-ffmpeg/ffmpeg`. | The transcode folder is read from `TranscodingTempPath` in `/var/lib/jellyfin/config/encoding.xml`, defaulting to `/var/cache/jellyfin/transcodes`. Paths are never hardcoded without that read. |
| **Jellyfin sandbox** | AetherFlow runs `jellyfin.service` under its `dotnet` sandbox profile. Writable paths are limited to `/var/lib/jellyfin`, `/var/cache/jellyfin`, `/var/log/jellyfin`, `/etc/jellyfin`, plus the optional `/mnt`, `/media`, `/srv`, `/downloads` (`config/package_automation.json:24-38`, writable paths at L25-34). | The shim's dispatcher socket must be reachable from inside the sandbox. Add `-/run/aetherflow/transcode.sock` to the Jellyfin `sandbox_rw_paths` (file 52). Peer mounts under `/mnt/af-peers` are already covered by `-/mnt`. |
| **NFS on Debian 13** | trixie ships nfs-utils 2.8.x, which reads drop-ins from `/etc/nfs.conf.d/` and supports `[nfsd] host=` to bind `nfsd` to one address. | Use `/etc/nfs.conf.d/aetherflow-peers.conf` and `/etc/exports.d/`. No edits to `/etc/nfs.conf`. |
| **WireGuard on Debian 13** | The trixie kernel (6.12) has WireGuard built in. `wireguard-tools` provides `wg` and `wg-quick@.service`. | `EnsurePackages` installs `wireguard-tools`, `nfs-kernel-server` and `nfs-common` from trixie main. No DKMS needed. |
| **AetherFlow installer** | The setup scripts already detect trixie as Debian 13 (`setup/modules/00-core.sh:117-129`). | No installer changes for OS detection. |
| **WebSocket routes** | Defined at `/api/v1/auth/ws`, `/api/v1/auth/ws/ticket` and `/api/v1/auth/ws/logs` (`backend-rs/crates/af-api/src/routes.rs:387-389`, under the auth router). The frontend fetches the ticket through `ApiClient` (`frontend-rs/crates/af-web-core/src/ws.rs:280`) and builds an absolute `ws(s)://<window host>/api/v1/auth/ws?ticket=` URL (`ws.rs:307-311`). | Both calls must go through `api_url()`, giving `/api/v1/peers/{id}/auth/ws/ticket` and `/api/v1/peers/{id}/auth/ws?ticket=` (file 6). The proxy maps them to the peer's `/api/v1/auth/ws*`. |

## Open Questions

*   **Jellyfin 12.4 when a library root is missing.** Confirm that when a library's root folder is gone (the peer mount stopped), a scan keeps that library's items instead of removing them. Jellyfin has no Plex-style "empty trash" toggle, so this behavior is the safeguard. The P7 E2E test checks it. If Jellyfin removes items, P7 adds a step that pauses Jellyfin's library scan tasks through its API while any peer mount is down.
*   **Decided: `jellyfin-ffmpeg` stays on the same apt state on every server.** No version pinning. See "Keeping `jellyfin-ffmpeg` aligned" under the dispatcher design.

## Critical User Journeys (CUJs)

### CUJ 1: Pair two servers

*   **Given**: Servers A and B run this release. The admin is logged into both dashboards, and B's link endpoint (VLAN or public IP, UDP 51821) is reachable from A.
*   **When**:
    1.  On B, the admin opens **Cluster → Allow a server to manage this one** and copies the pairing string.
    2.  On A, the admin opens **Cluster → Pair with a server** and pastes it.
    3.  On B, the admin confirms that the fingerprint shown matches A's screen.
*   **Then**:
    *   Both Cluster pages list the other server as *Linked, healthy*, with round-trip time and version shown.
    *   `afpeer0` is up on both servers.
    *   No grant exists yet, so neither server can manage the other.

### CUJ 2: Grant and manage (one-way, read-write)

*   **Given**: A and B are linked.
*   **When**: On B, the admin grants A **Read and write (everything)**. On A, the admin opens B from the Cluster page, restarts a service, changes a setting and installs a Marketplace app.
*   **Then**:
    *   All three actions succeed.
    *   A coloured "Managing **media-2**" bar stays visible on every tab.
    *   B's Audit tab shows each action as `peer-seedbox-1` with "via seedbox-1, operator alice".

### CUJ 3: Read-only grant

*   **Given**: B grants A **Read-only (everything)**.
*   **When**: A browses every tab of B and tries to stop a service.
*   **Then**:
    *   Every view loads.
    *   Change controls are disabled, each with a reason.
    *   A forced request returns `403 PEER_SCOPE_DENIED` and is audited on B.

### CUJ 4: Two-way

*   **Given**: B has granted A access.
*   **When**: On A, the admin grants B **Read-only (services)**.
*   **Then**:
    *   Each Cluster page shows both directions in words, for example "*seedbox-1 can manage media-2 (read-write)*" and "*media-2 can view seedbox-1 services*".
    *   Revoking one direction leaves the other unchanged.

### CUJ 5: Stream media from a peer

*   **Given**: B shares `/srv/media/movies` read-only with A.
*   **When**: A's Jellyfin library points at `/mnt/af-peers/media-2/movies/library`, and a 4K remux plays.
*   **Then**:
    *   Playback runs from the NFS mount.
    *   If the link is cut, the mount unit stops, and `/mnt/af-peers/media-2/movies` disappears instead of showing an empty folder. Jellyfin keeps its library items.
    *   Both Cluster pages show the mount as *Stopped: link down*.

### CUJ 6: Offload a transcode

*   **Given**: A runs Jellyfin. B has a VA-API GPU and is enabled as a transcode worker with weight 1.
*   **When**: A client plays a file that needs a VA-API transcode.
*   **Then**:
    *   ffmpeg runs on B, and segments appear in A's transcode folder.
    *   Jellyfin progress and stopping work normally.
    *   An NVENC-only job stays local.
    *   With B's link revoked, or the dispatcher stopped, playback transcodes locally.

### CUJ 7: Revoke

*   **Given**: A and B are linked with grants and mounts.
*   **When**: On B, the admin deletes the link.
*   **Then**:
    *   The WireGuard peer is removed on B immediately.
    *   A's open WebSockets, proxied requests, NFS mounts and transcode streams end.
    *   A shows "Link revoked by media-2".
    *   Both audit logs record the event.

### CUJ 8: Version mismatch

*   **Given**: A runs a newer release than B, and a feature flag is missing on B.
*   **When**: A opens B.
*   **Then**: The link shows **Limited**, and the affected features are disabled with "Update media-2 to use this". If B's protocol version is below A's minimum, the link shows **Incompatible** and management pauses.

## Technical Plan (Architecture)

### Components

```text
                Server A (managing; runs Jellyfin)                         Server B (managed; storage + GPU)
 ┌─────────────────────────────────────────────────────┐      ┌─────────────────────────────────────────────────────┐
 │ Browser /?tab=cluster ──► af-api                    │      │ af-api                                              │
 │   ApiClient base-path hook: /api/v1/peers/{id}/...  │      │   peer listener  (tunnel IP : 9443, plain HTTP)     │
 │   peers::proxy  (admin-only, streaming, WS)  ───────┼──┐   │     1. source IP ∈ link tunnel IP                  │
 │   peers::transcode dispatcher (unix socket) ◄─ shim │  │   │     2. X-AF-Link-Token verified (hash)             │
 │   peers::health loop                                │  │   │     3. path canonicalized → area → access level    │
 │ af-runner (root)                                    │  │   │     4. grant token + PeerPrincipal and AuthUser    │
 │   afpeer0 (WireGuard, UDP 51821)                    │  │   │     5. existing af-api router & handlers           │
 │   NFS mounts of B exports  (/mnt/af-peers/...)      │  │   │   peers::transcode worker relay ──► af-transcode   │
 │   NFS export: Jellyfin transcode + cache dirs       │  │   │                                     worker (ffmpeg)│
 │ Jellyfin ──ffmpeg path──► af-transcode shim         │  │   │ af-runner (root)                                    │
 └─────────────────────────────────────────────────────┘  │   │   afpeer0, NFS export of media (ro), worker unit    │
                                                          │   └─────────────────────────────────────────────────────┘
                                 WireGuard (keys pinned both ways; endpoint = VLAN or public IP)
                                                          └──────────────────────────────────────────►
```

### Transport: AetherFlow-managed WireGuard

*   **Dedicated interface.** AetherFlow manages `afpeer0` through `wg-quick@afpeer0.service` and `/etc/wireguard/afpeer0.conf`. It never touches the user's `wg0`, which `backend-rs/crates/af-runner/src/network.rs` manages.
    *   The new module copies `network.rs`'s identity reconciliation, `syncconf` and recovery patterns (L452, L820, L926, L1007).
    *   The runner's unit allowlist already accepts `wg-quick@*` (`backend-rs/crates/af-runner/src/lib.rs:3329`).
*   **Addressing.** Each server picks one tunnel address from `AF_PEER_TUNNEL_CIDR` (default `10.231.0.0/16`) the first time it pairs. Each peer is added with `AllowedIPs = <peer tunnel IP>/32`. Pairing rejects a tunnel address that collides with an existing one. The default UDP port is `AF_PEER_WG_PORT=51821`.
*   **Endpoint.**
    *   The admin chooses the endpoint from detected interfaces. Private (VLAN) addresses are labelled as recommended.
    *   It's stored per link and never silently falls back to another address.
    *   It can be edited later from the Cluster page.
*   **Why WireGuard.** It pins keys on both sides, sends no response to packets without a valid key, and guarantees a tunnel source IP belongs to its key. API, NFS and transcode traffic share one encrypted tunnel, so none of them needs its own certificates.

### Peer authentication and authorization (on the managed server)

**Peer listener.** P3 binds an axum server to `<own tunnel IP>:AF_PEER_LISTEN_PORT` (default 9443) over WireGuard. P3 serves pairing completion, health and link lifecycle. P5 adds scoped management.

1.  **Link check.** Require an active link’s tunnel source IP. The only pre-activation route is `POST /peer/v1/hello`, bound to the pending peer’s pinned WireGuard identity and unexpired attempt ID.
2.  **Link token.** An active link requires `X-AF-Link-Token` to match the incoming SHA-256 digest in `peer_links.inbound_token_hash`, using `af_models::constant_time_eq` (`backend-rs/crates/af-models/src/constant_time.rs:4`). Each side issues a separate 256-bit incoming token. The issuer stores the incoming hash and the calling peer stores the held token in a runner-managed file.
3.  **Peer-internal routes.** Explicit link operations require the link token, including tunnel `GET /health`, link view, revoke notice and later grant delivery and offers. Transcode jobs also require an active grant with `transcoding: write`. Unknown internal routes are denied.
4.  **Grant check for management.** Verify `X-AF-Grant-Token` against the active grant’s independent digest before applying the route and method checks.
    1.  Canonicalize the path: collapse `//`, percent-decode once, reject `..`.
    2.  Classify the route into an **area**, with `route_pattern_matches` (`backend-rs/crates/af-api/src/plugins.rs:418-449`) running over a fixed table in `peers::scopes`.
    3.  Check the method against the area's access level. Read-only allows `GET`, `HEAD` and the WebSocket upgrade on read routes. Read-write allows all methods.
    4.  **Fail closed.** Unclassified routes get `403 PEER_ROUTE_UNCLASSIFIED`.
5.  **Never reachable through a grant:** `/api/v1/admin/peers/*`, `/api/v1/peers/*`, pairing routes, and auth routes that create sessions or change credentials. This blocks a peer from widening its own grant or hopping to a third server.
6.  **Inject the identity.** The listener inserts `PeerPrincipal { link_id, grant_id, access }` and the grant's run-as `AuthUser`, then forwards the request into the existing `routes::build_router()`.
    *   **Role:** `admin` for read-write grants. Read-only grants also get `admin`, because many read routes require it, and the access check in step 4 is what enforces read-only.
    *   **Middleware:** `csrf_middleware` (`backend-rs/crates/af-api/src/auth.rs:1179-1232`) and `host_validation_middleware` (`backend-rs/crates/af-api/src/middlewares.rs:1600-1665`) skip their browser-specific checks only when `PeerPrincipal` is present. Clients can't set that extension.

**Run-as account.** Confirming a grant creates a dedicated local user named `peer-<peer name>`:

*   `account_type = 'peer'`, with no password hash.
*   Rejected by password login and OIDC.
*   Hidden from normal user lists, and can't be deleted from the Users tab.
*   Deleting the grant disables the account.

Existing handlers that need a real user then work unchanged: WebSocket tickets and live re-checks (`backend-rs/crates/af-api/src/ws.rs:876,1167,1591`), and McBrowser's `user_id > 0` rule (`backend-rs/crates/af-api/src/mcbrowser.rs:199-215`). `load_active_human_subject` (`auth.rs:114-116`) is extended to accept `account_type='peer'` only when a `PeerPrincipal` is present.

**Password re-check routes.** Routes that need a fresh password check (`backend-rs/crates/af-api/src/storage.rs:1201,1415`) are allowed only with read-write access to their area. The check is satisfied by `PeerPrincipal`, because the granting admin made that choice.

### Remote management (on the managing server)

*   **Proxy.** `ANY /api/v1/peers/{id}/{*rest}` forwards to `http://<peer tunnel IP>:9443/api/v1/{rest}` and adds the held link and grant tokens for the selected link.
*   **Who may call it.** It sits behind `admin_only_middleware` (`auth.rs:1139-1155`). Plugin tokens and peer principals are rejected.
*   **Transport.** It reuses the streaming body and HTTP/WebSocket upgrade tunnel from `app_subdomain_proxy_middleware` (`middlewares.rs:838-1360`, upgrade path `987-1120`). That code is extracted into a shared `stream_proxy` function; nothing is copied.
*   **Header handling.**
    *   It strips `Cookie`, `Authorization`, `X-Forwarded-*`, `Host`, `Origin` and client-supplied peer auth or audit headers. It sets the peer auth and audit headers itself.
    *   It sets `X-Request-ID`, reusing the inbound ID generated in `backend-rs/crates/af-api/src/routes.rs:150-180`.
    *   It sets `X-AF-Origin-Operator: <A username>`. B stores this as audit metadata only and never uses it for authorization.
    *   It rewrites root-relative `Location` (for example tus uploads, `mcbrowser/uploads.rs:2568,2927`) and `Set-Cookie` paths under `/api/v1/peers/{id}`.
*   **Targets.** The target is always the stored tunnel IP. The proxy never accepts a host from the request.
*   **Limits.**
    *   Per-link caps: `AF_PEER_MAX_CONN=64` concurrent requests and `AF_PEER_MAX_WS=16` WebSockets.
    *   Timeouts: 30 s connect and headers, none on streaming bodies.
*   **Frontend.** `ApiClient` gets an **active server** setting.
    *   When a peer is selected, every `/api/v1/<rest>` request becomes `/api/v1/peers/{id}/<rest>`. That covers the request builders (`frontend-rs/crates/af-web-core/src/api.rs:806-860`), the CSRF prefix list (`api.rs:165-202`) and the WebSocket ticket fetch and URL builder (`frontend-rs/crates/af-web-core/src/ws.rs:280,307-311`).
    *   A new `api_url(path)` helper replaces the six places that build URLs directly. The full list is in the Detailed Implementation Plan.
    *   Resource caches are keyed by server.
*   **UI safety.**
    *   An identity bar with the server's name and colour stays on every tab while a peer is selected.
    *   Destructive confirmations name the server.
    *   Areas without write access show their controls disabled.
    *   Third-party app launch buttons open the peer's own URL, because launches depend on per-host Apache vhosts and `__Host-` cookies (`backend-rs/crates/af-api/src/app_launch.rs:18,93-149`).
*   **Compatibility.** `GET /health` (`routes.rs:338`) adds `peer_protocol` (an integer, starting at 1) and a `capabilities` string array.
    *   **Compatible:** same protocol, A's capabilities are a subset of B's.
    *   **Limited:** same protocol, some capabilities missing on B. Those features are disabled.
    *   **Incompatible:** protocol below A's minimum. Management pauses.
*   **Long jobs.** Marketplace installs keep running on B under B's own job reconciliation (`reconcile_package_jobs`, `backend-rs/crates/af-api/src/main.rs:265-282`). A polls them through the proxy. The UI shows every remote action as done, failed (with reason) or unknown (peer unreachable).

### Pairing protocol

1.  **Open the window (B).** `POST /api/v1/admin/peers/pairing-window` opens a 10-minute window. It returns `afpair1:<base64url(json{https_url, wg_pubkey, endpoint, wg_port, tunnel_ip, code})>`. Store only the SHA-256 digest of the single-use code. Port the issuance and consumption patterns from `cluster_daemon.rs:716-740,968-986`.
2.  **Start pairing (A).** `POST /api/v1/admin/peers/pair {pairing_string, name, endpoint}` ensures identity, chooses A’s tunnel IP and adds B’s pinned key and tunnel IP to `afpeer0` as a pending peer. A sends its public key, endpoint, tunnel IP, name, version, timestamp and code to B’s `POST /api/v1/peer-pairing/request` over validated HTTPS. B enforces the 4 KiB body limit, five attempts per minute per source IP and atomic single-use consumption.
3.  **Record the attempt.** B stores the attempt and expiry, and returns its ID and the six-digit comparison code derived from `sha256(A_pubkey ‖ B_pubkey)`. A records the attempt ID against its pending link. Both dashboards show the comparison code.
4.  **Confirm (B).** After the admin compares the fingerprints, `POST /api/v1/admin/peers/pairing/{attempt}/confirm` records B’s pending link and adds A’s pinned key and tunnel IP to B’s `afpeer0`. B creates its incoming link token and calls `POST /peer/v1/hello` over the tunnel. The bootstrap handler allows only the pending peer with the matching WireGuard source IP and attempt ID, within the attempt’s expiry.
5.  **Complete on both sides.** A verifies the pinned peer and attempt, stores B’s held token, and returns the distinct token it issued for requests from B. B stores A’s held token and acknowledges with it. Send the acknowledgement through the hello endpoint with the newly issued link token. A validates it and activates the link. B activates after A’s reply. A accepts an authenticated retry for the same acknowledged attempt until expiry. Retries reuse the same credentials. Keep any temporary issuer token in a runner-controlled file. Remove temporary files after acknowledgement or expiry. Terminal failure or cancellation cleans up that attempt’s pending peer and credentials. Active peers use token-authenticated `GET /health` for health and capability exchange.
6.  **Typed errors.** `CODE_EXPIRED`, `CODE_USED`, `WINDOW_CLOSED`, `KEY_MISMATCH`, `TUNNEL_IP_CONFLICT`, `ENDPOINT_UNREACHABLE`, `HANDSHAKE_TIMEOUT`, `VERSION_INCOMPATIBLE` and `CLOCK_SKEW` (over 5 min). Messages name the server, step and next action. Keep codes and credentials out of logs and audit entries.
7.  **Two-way grants (P5).** Each direction is created only on the server it applies to. Authenticated `/peer/v1/grant-offer` messages are informational. Grant creation issues its separate credential through `/peer/v1/grant-token` over the active link.

**Revocation.**

*   **Grant.** Clear the grant hash, disable the run-as account, invalidate its sessions and broadcast revocation. P6 closes open WebSockets for that grant within 1 s. The link token remains valid for health and link operations.
*   **Link.** Send a best-effort authenticated revoke notice, remove the WireGuard peer, clear related credentials and stop its flows. A received notice shows “Link revoked by {name}”. Without a notice, show the link as down. A transient outage can recover on a later health check.

### Media sharing: NFS inside the tunnel

*   **Server side (B).**
    *   af-runner writes `/etc/exports.d/aetherflow-peer-<link>.exports`. Each line restricts one export to the peer's tunnel IP.
    *   Read-only exports use `ro,root_squash,secure,no_subtree_check`. Read-write exports are opt-in per folder, with a warning, and use `rw,all_squash,anonuid=<owner>,anongid=<group>,secure`.
    *   `nfsd` is limited to the tunnel address through `/etc/nfs.conf.d/aetherflow-peers.conf` (`[nfsd] host=<tunnel IP>`). Then `exportfs -ra` applies the change.
    *   `sec=sys` is enough, because WireGuard authenticates the host and `secure` requires a privileged source port.
*   **Client side (A).**
    *   af-runner writes one systemd `.mount` unit per link and export. The unit name comes from `systemd-escape --path /mnt/af-peers/<link>/<export>`.
    *   Options: `nfs4`, `vers=4.2`, `soft`, `timeo=100`, `retrans=2`, `ro` (or `rw`), `_netdev`, and `x-systemd.requires=wg-quick@afpeer0.service`.
    *   Library apps are pointed at a folder **inside** the mount, such as `/mnt/af-peers/<link>/<export>/library`. The mount root itself is never handed to them.
*   **Health gating.**
    *   The health loop stats a sentinel file `.af-peer-sentinel` at the export root (B's runner creates it), with a 5 s timeout, every 15 s.
    *   It also checks `afpeer0` handshake age; more than 180 s counts as down.
    *   Two consecutive sentinel failures stop the mount unit. A detected WireGuard peer removal stops the mount on the first health tick. Recovery restores the mount and library path.
*   **Media-app safety.**
    *   **Jellyfin 12.4** has no "empty trash" setting. The safeguard is that the library root disappears with the mount, and the P7 E2E test checks that Jellyfin keeps those items (see Open Questions for the fallback).
    *   **Plex**: when AetherFlow sets up a Plex library on a peer mount, it turns off "Empty trash automatically after every scan".
    *   **Emby and *arr apps**: the Cluster page reminds the admin to turn off automatic removal of missing items for libraries on peer mounts.
*   **High-latency warning.** Above `AF_PEER_RTT_WARN_MS` (default 25 ms), the Cluster page warns that NFS throughput will drop.

### Rust-native transcode dispatcher

**Crate.** A new `backend-rs/crates/af-transcode` crate builds one binary with three modes:

| Mode | Invoked as | Runs where | Role |
| :--- | :--- | :--- | :--- |
| **shim** | `/usr/lib/aetherflow/transcode/ffmpeg <args…>` (the binary, installed under the name `ffmpeg`) | Jellyfin server, as the Jellyfin user | Takes the place of ffmpeg for Jellyfin. |
| **worker** | `af-transcode worker`, as `af-transcode-worker.service` (`User=jellyfin`, `SupplementaryGroups=render video`) | Worker server | Listens on `/run/aetherflow/transcode-worker.sock` and runs the real ffmpeg. |
| **probe** | `af-transcode capabilities` | Any server | Prints the real ffmpeg's version, encoders and render nodes as JSON for `/health`. |

The shim folder also has an `ffprobe` symlink pointing at the real `ffprobe`. The real binaries' paths come from `AF_TRANSCODE_REAL_FFMPEG`, default `/usr/lib/jellyfin-ffmpeg/ffmpeg`.

**Job flow.**

1.  **Probe calls run locally.** If the arguments are a probe (`-version`, `-encoders`, `-decoders`, `-hwaccels`, `-filters`, `-h`, `-buildconf`, or no input), the shim `exec`s the real ffmpeg, so Jellyfin's feature detection is unchanged.
2.  **Real jobs ask the dispatcher.** The shim connects to the dispatcher socket `/run/aetherflow/transcode.sock`, owned by root with group `jellyfin` and mode 0660. It sends `Start { args, cwd, env_subset }`. If the socket is missing or doesn't answer within 2 s, the shim `exec`s the real ffmpeg locally.
3.  **The dispatcher (in A's af-api, `peers::transcode`) picks a target.**
    1.  `argv::required_capability(args)` reads the encoder needs: `-hwaccel`, `-hwaccel_output_format`, `-init_hw_device`, the `-c:v` encoder name, and the `vaapi`, `qsv` or `cuda` filters.
    2.  Eligible workers have:
        *   an active link holding a grant with **transcoding: read-write** on the worker
        *   status healthy
        *   `parity_ok`
        *   the same `jellyfin-ffmpeg` version string
        *   the required encoder
        *   fewer running jobs than their concurrency cap
    3.  Selection is weighted random over the eligible workers. If none is eligible, the reply is `RunLocal` and the shim `exec`s the real ffmpeg.
4.  **Remote run.** The dispatcher opens the WebSocket `/peer/v1/transcode/jobs` on the worker's peer listener, with the link and grant tokens, and relays frames both ways between the shim's unix socket and that WebSocket.
    *   The worker's af-api forwards the stream to the local worker service socket.
    *   The worker service spawns the real ffmpeg with **identical arguments**. The only rewrite is the `/dev/dri/renderD*` path, mapped to the worker's render node.
5.  **Stream protocol** (`af-transcode::protocol`).
    *   Length-prefixed bincode frames: `Start`, `RunLocal`, `Started`, `Stdin(bytes)`, `Stdout(bytes)`, `Stderr(bytes)`, `Signal(Term|Int|Kill)`, `Exit(code)`, `Error(kind, msg)`.
    *   **Start result.** Send `RunLocal` when no remote job can start. Send `Started` when the worker accepts the job. A lost acknowledgment after a worker may have accepted the job uses the dropped-stream cleanup path to avoid starting a duplicate local encode.
    *   **Backpressure** comes from bounded 64-frame channels.
    *   **Exit.** The shim writes `Stdout`/`Stderr` to its own stdout and stderr, and exits with `Exit(code)`.
    *   **Signals.** The shim catches SIGTERM and SIGINT and forwards them as `Signal`. Its stdin is forwarded as `Stdin`, which covers Jellyfin's `q` stop command.
    *   **Hard kills.** When Jellyfin's stop timeout runs out, it kills the shim's whole process tree with SIGKILL, which the shim can't catch. The **dispatcher** detects the shim's unix socket closing without an `Exit` frame and sends `Signal(Kill)` to the worker. The worker also kills its ffmpeg whenever its stream closes without a clean `Exit`, so no orphan ffmpeg keeps running on the worker.
6.  **Path parity.** The worker must see Jellyfin's paths:
    *   **Media.** If the worker is the storage server, af-runner creates a systemd bind `.mount` that makes the local media folder appear at the path Jellyfin uses on A. Otherwise the worker mounts A's media export at the same path.
    *   **Transcode, temp and cache folders.** A exports these `rw,all_squash` (mapped to Jellyfin's UID/GID on A) to the worker's tunnel IP:
        *   the transcode folder (`TranscodingTempPath` from `/var/lib/jellyfin/config/encoding.xml`, default `/var/cache/jellyfin/transcodes`)
        *   the `TMPDIR` folder `/var/cache/jellyfin/af-tmp`
        *   the cache folders ffmpeg reads (attachments and fonts under `/var/cache/jellyfin`)

        The worker mounts them at the identical paths.
    *   **Parity test.** Turning on a worker runs a 2-second test job: encode a generated test pattern into the transcode folder, then read it back on A. Workers that fail get `parity_ok = false` and the reason is shown.
7.  **Failure handling.**

    | Failure | Behavior |
    | :--- | :--- |
    | Worker unreachable at start | Run locally. Mark the worker unhealthy for 60 s. |
    | Stream drops mid-job | The shim exits 1, and Jellyfin's normal retry or failure path takes over. Mark the worker unhealthy. |
    | Link revoked | Streams end, and new jobs run locally. |
    | Dispatcher down | The shim runs ffmpeg locally. |
    | Jellyfin hard-kills the shim (SIGKILL) | The dispatcher sees the socket close without `Exit` and sends `Signal(Kill)`. The worker kills ffmpeg. |

8.  **Recording.** Each job writes `transcode_jobs`: worker, start and end, exit code, request ID. Rows are pruned after 7 days.

**Keeping `jellyfin-ffmpeg` aligned.** All servers stay on the same apt state for `jellyfin` and `jellyfin-ffmpeg`. There is no pinning.

*   **Reporting.** Each server's `/health` capability JSON reports its installed `jellyfin-ffmpeg` version, taken from `dpkg-query -W -f='${Version}' jellyfin-ffmpeg*`, alongside the `ffmpeg -version` string.
*   **When versions differ.** The health loop compares the Jellyfin server against every enabled worker. If a worker differs:
    *   it becomes ineligible, and jobs run locally
    *   the Cluster page shows *"jellyfin-ffmpeg differs: seedbox-1 7.1.x-1 vs media-2 7.1.y-1"*
    *   a notification is sent
*   **Align button.** **Update to match** runs the existing apt package update for `jellyfin-ffmpeg` on whichever server is older. Locally, it goes through the existing package-update path. On a peer, it goes through the proxy and needs that peer's grant to include `updates: read-write`. Once the versions match, the worker becomes eligible again on the next health tick.
*   **Automatic updates.** If AetherFlow's automatic package updates (`backend-rs/crates/af-services/src/workers/package_updates.rs`) upgrade `jellyfin-ffmpeg` on one server, the health loop sends an "update the other server to match" notification, instead of quietly keeping the worker disabled.

**Enabling transcoding on the Jellyfin server.** Turning it on makes af-runner:

1.  Install the shim folder `/usr/lib/aetherflow/transcode/`: the `ffmpeg` shim, plus an `ffprobe` symlink to `/usr/lib/jellyfin-ffmpeg/ffprobe`.
2.  Create `/var/cache/jellyfin/af-tmp`, owned by `jellyfin`.
3.  Write `/etc/systemd/system/jellyfin.service.d/20-aetherflow-transcode.conf` containing:

    ```ini
    [Service]
    Environment=JELLYFIN_FFMPEG=/usr/lib/aetherflow/transcode/ffmpeg
    Environment=TMPDIR=/var/cache/jellyfin/af-tmp
    ```

4.  Run `systemctl daemon-reload` and restart Jellyfin.
5.  Check the dashboard's read-only ffmpeg path shows the shim. If it doesn't, the drop-in is removed again and an error is shown.

Turning it off removes the drop-in, reloads systemd and restarts Jellyfin. AetherFlow's sandbox drop-in is never edited.

### Data model (migrations 25–27 in `af-db`)

**Migration 25: "Peer clustering"**

```sql
CREATE TABLE peer_identity (id INTEGER PRIMARY KEY CHECK (id = 1), wg_pubkey TEXT NOT NULL,
  tunnel_ip TEXT NOT NULL, wg_port INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE peer_links (id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, wg_pubkey TEXT NOT NULL UNIQUE,
  tunnel_ip TEXT NOT NULL UNIQUE, endpoint TEXT NOT NULL, wg_port INTEGER NOT NULL, state TEXT NOT NULL,
  peer_version TEXT, peer_protocol INTEGER, capabilities TEXT, rtt_ms REAL, last_ok_at TEXT,
  last_error TEXT, consecutive_failures INTEGER NOT NULL DEFAULT 0, inbound_token_hash TEXT,
  pending_attempt_id TEXT, pending_expires_at INTEGER, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE peer_grants (id TEXT PRIMARY KEY, link_id TEXT NOT NULL REFERENCES peer_links(id) ON DELETE CASCADE,
  run_as_user_id INTEGER NOT NULL, access TEXT NOT NULL /* JSON {area: "none"|"read"|"write"} */,
  token_hash TEXT, created_by TEXT NOT NULL, created_at TEXT NOT NULL, revoked_at TEXT);
CREATE TABLE peer_pairing_windows (id TEXT PRIMARY KEY, code_hash TEXT NOT NULL UNIQUE, expires_at INTEGER NOT NULL,
  consumed_at INTEGER);
CREATE TABLE peer_pairing_attempts (id TEXT PRIMARY KEY, window_id TEXT, remote_name TEXT, remote_pubkey TEXT,
  remote_tunnel_ip TEXT, remote_endpoint TEXT, source_ip TEXT, status TEXT NOT NULL, error_code TEXT,
  expires_at INTEGER NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE peer_exports (id TEXT PRIMARY KEY, link_id TEXT NOT NULL REFERENCES peer_links(id) ON DELETE CASCADE,
  path TEXT NOT NULL, writable INTEGER NOT NULL DEFAULT 0, squash_uid INTEGER, squash_gid INTEGER, created_at TEXT NOT NULL);
CREATE TABLE peer_mounts (id TEXT PRIMARY KEY, link_id TEXT NOT NULL REFERENCES peer_links(id) ON DELETE CASCADE,
  remote_path TEXT NOT NULL, mount_path TEXT NOT NULL UNIQUE, unit_name TEXT NOT NULL, writable INTEGER NOT NULL DEFAULT 0,
  purpose TEXT NOT NULL /* media|transcode */, state TEXT NOT NULL, last_error TEXT);
CREATE TABLE transcode_workers (link_id TEXT PRIMARY KEY REFERENCES peer_links(id) ON DELETE CASCADE,
  enabled INTEGER NOT NULL DEFAULT 0, weight INTEGER NOT NULL DEFAULT 1, max_jobs INTEGER NOT NULL DEFAULT 2,
  ffmpeg_version TEXT, encoders TEXT, render_node TEXT, parity_ok INTEGER NOT NULL DEFAULT 0, parity_error TEXT);
CREATE TABLE transcode_jobs (id TEXT PRIMARY KEY, link_id TEXT, started_at TEXT NOT NULL, ended_at TEXT,
  exit_code INTEGER, request_id TEXT, ran_locally INTEGER NOT NULL);
ALTER TABLE users ADD COLUMN account_type TEXT NOT NULL DEFAULT 'human';
```

**Migration 26: "Remove legacy master/worker clustering"**

```sql
DROP TABLE IF EXISTS cluster_commands;
DROP TABLE IF EXISTS cluster_enrollment_tokens;
DROP TABLE IF EXISTS cluster_nodes;
```

**Migration 27. Peer grant metadata**

`peer_received_grants` tracks the access a peer grants this server and the ID of its committed credential. `peer_grant_epochs` orders grant delivery and revocation. `peer_received_grant_cleanups` records staged and superseded credential IDs until the runner confirms deletion. Rotation stages a new runner file before committing its ID, so interrupted writes leave the prior committed file available.

Raw secrets live in runner-managed files.

*   WireGuard private key: `/etc/aetherflow/peers/afpeer0.key` (0600)
*   Held link token: `/etc/aetherflow/peers/tokens/<link>.token` (0640, group `aetherflow`).
*   Held grant tokens use `/etc/aetherflow/peers/tokens/<credential-id>.grant.token` (0640, group `aetherflow`). Existing grant rows without a credential ID use the link ID.
*   Pending issuer tokens for handshake retries are attempt-scoped (0600). Clean them up after acknowledgement, cancellation or expiry.

## Alternatives Considered

### Alternative A: Separate dashboards plus single sign-on and a server switcher

*   **Pros**: Cheapest, and adds no new trust path.
*   **Cons**: Two logins, two audit trails, and no single place to act on both servers.
*   **Reason for Rejection**: Rejected by author. Management must happen in one place, `/?tab=cluster`.

### Alternative B: Extend the existing master/worker cluster

*   **Pros**: The code already exists.
*   **Cons**:
    *   A single master contradicts two-way management.
    *   The polling command queue can't carry forms, WebSockets, uploads or long jobs.
    *   It needs hand-made certificates.
    *   Its schema sits outside versioned migrations.
*   **Reason for Rejection**: Rejected by author. The system is deleted.

### Alternative C: A dedicated pinned mTLS peer listener on the public or VLAN address

*   **Pros**: No WireGuard dependency.
*   **Cons**:
    *   Needs certificate pinning and a rustls verifier.
    *   Exposes a public handshake surface and needs its own allowlist.
    *   NFS and transcode traffic would each need separate protection.
*   **Reason for Rejection**: Rejected by author in favor of WireGuard. WireGuard gives key pinning, sends no response to packets without a valid key, and carries every protocol in one tunnel.

### Alternative D: Load B's UI bundle inside A

*   **Pros**: B's UI always matches B's API.
*   **Cons**:
    *   A compromised B would run script on A's origin and could take over A's admin session.
    *   The compiled `/api/v1` paths would send B's actions to A.
    *   `X-Frame-Options: DENY` blocks framing (`routes.rs:206-274`).
*   **Reason for Rejection**: Rejected in review: unsafe, and it would act on the wrong server.

### Alternative E: rclone WebDAV or SFTP mounts for peer media

*   **Pros**: Handles high-latency links well with large local caches, and rclone is already a Marketplace package.
*   **Cons**:
    *   FUSE and HTTP/SSH add CPU cost per stream.
    *   Library scans are slower.
    *   Write caching delays segment visibility, so it can't hold transcode output.
    *   The sandboxed `rclone.service` can't mount FUSE (`backend-rs/crates/af-runner/src/package_executor/declarative_recipes.rs:1920-1924`).
*   **Reason for Rejection**: Rejected by author ("whatever is best at handling media"). NFS performs better on low-latency datacenter links and is needed for transcode folders anyway.

### Alternative F: Package rffmpeg

*   **Pros**: An existing community tool.
*   **Cons**:
    *   Needs SSH keys for each worker and a separate host database.
    *   Brings in Python.
    *   Has no encoder awareness, so mixed encoders need flag-rewriting wrappers.
    *   Isn't covered by link revocation or audit.
*   **Reason for Rejection**: Rejected by author in favor of the Rust-native dispatcher.

### Alternative G: Reuse plugin scopes and tokens as grants

*   **Pros**: The code already exists.
*   **Cons**:
    *   Hard-denies `/api/v1/admin` and `/api/v1/auth/*` (`plugins.rs:39-66,287-312`).
    *   `admin_only_middleware` rejects plugin tokens.
    *   Tokens are signed with each server's local secret.
*   **Reason for Rejection**: Rejected in review. Only `route_pattern_matches` is reused.

### Alternative H: A per-feature typed remote client, or the browser calling peers directly

*   **Pros**: No generic proxy.
*   **Cons**:
    *   A per-feature client costs more with every new feature.
    *   Direct browser calls break the same-origin client and `__Host-` cookies, and need a login on every peer.
*   **Reason for Rejection**: Rejected in review.

--------------------------------------------------------------------------------

## Non-Functional Requirements

*   **Security & Privacy**:
    *   A read-write grant is root-equivalent on the target, and two-way links put both servers at risk.
    *   Mitigations:
        *   per-area access with read-only presets
        *   unknown routes fail closed
        *   grants can't chain
        *   requests need the link token *and* the tunnel source IP
        *   instant revocation
        *   full audit on the target
    *   The proxy never takes its target from the request.
    *   NFS exports use `secure` (privileged source port) and are restricted to the peer's tunnel IP.
    *   Secrets are kept in root/aetherflow-only files.
    *   `X-AF-Origin-Operator` is audit metadata only.
*   **Performance & Latency**:
    *   The proxy streams bodies and never buffers them.
    *   Per-link connection and WebSocket caps.
    *   NFS is kernel-to-kernel, so 1 Gbps carries about 12 simultaneous 4K remuxes.
    *   Transcode control streams are small, because segments travel over NFS.
    *   Audit, health and job writes go through the existing single-writer SQLite pool, at most 1 health write per link every 15 s.
*   **Rollout & Rollback**:
    *   Each phase ships on its own. Migrations only add things, except migration 26, which ships in P4 with the legacy code removal.
    *   Rolling back one release, while the peer stays one release ahead, is safe:
        *   an older peer answers `/peer/v1/*` with 404, which shows as **Incompatible**
        *   unknown peer principals get 401
        *   unknown link rows are ignored
    *   With transcoding off, nothing touches Jellyfin. Turning it off removes the drop-in.

--------------------------------------------------------------------------------

### Additional Resources

*   `backend-rs/crates/af-runner/src/network.rs`: existing WireGuard management (the pattern to copy).
*   `backend-rs/crates/af-api/src/middlewares.rs:838-1360`: streaming HTTP/WebSocket proxy (to extract).
*   `backend-rs/crates/af-hardware/src/lib.rs:180-246`: GPU encoder detection.
*   Jellyfin documentation, at `https://jellyfin.org/docs/`:
    *   hardware acceleration and rffmpeg sections: shared media, transcode and `TMPDIR` paths
    *   installation on Debian
    *   configuration (ffmpeg path via `JELLYFIN_FFMPEG` / `--ffmpeg`)
*   Debian 13 manuals: `nfs.conf(5)` (drop-ins under `/etc/nfs.conf.d`, `[nfsd] host=`), `exports(5)`, `wg-quick(8)`.

### Future Improvements

*   **rclone for peers on high-latency links.** Use it when the round-trip time regularly exceeds the warning threshold.
*   **Rotating keys in band.** Only needed if re-pairing proves disruptive.
*   **Fleet views.** Topology and combined dashboards once there are more than two servers.
*   **Plex and Emby transcoding.** If either vendor exposes a supported transcoder hook.

--------------------------------------------------------------------------------

## Detailed Implementation Plan

Phases build on each other. Each produces a local commit and passes its local exit gate on server A before the next phase begins. Two-server acceptance is deferred until server B is provisioned. The acceptance checks remain required before release.

### Before You Start

Server A has the required Jellyfin version. The operator authorized local implementation while server B awaits provisioning.

- [x] Base the implementation branch on fetched nightly. Use the [drift report](peer-clustering-drift.md) for corrected source targets.
- [x] Run `cargo build --workspace --release` and `cargo test --workspace` on unmodified nightly. Record existing failures and resolve the default baseline before implementation.
- [x] Confirm Rust, the WASM toolchain and Trunk on server A.

Before two-server acceptance, verify Debian 13, Jellyfin 12.4 and matching installed Jellyfin and ffmpeg package versions on A and B. Confirm B’s SSH destination, both VLAN addresses, UDP `51821` reachability, approved artifact delivery, the test media library and the supported GPU worker.

### Roadmap

The original entry numbers remain stable. A file touched by several phases has one owner in each phase.

| Phase | File numbers and follow-up wiring | Builder lanes | Local exit gate |
| --- | --- | --- | --- |
| **P0 Backend groundwork** | 1, 2, 3, 4 | db 1–2 · api 3–4 | Fresh and legacy migration 25 pass. Health advertises protocol 1 with empty capabilities. Request IDs appear in configured JSON logs. Standalone behavior is preserved. |
| **P1 Browser transport groundwork** | 5, 6, 7 | web-core 5–6 · web-app 7, after 5 exports the helper | Local URLs, CSRF and telemetry work. Peer paths use one prefix. Ticket, log URL and direct call-site tests pass. |
| **P2 Privileged peer networking** | 20, 21, 22 | runner 20–22 | Fake-runner tests pass for config, sync, status, rollback, credential handling and `wg0` preservation. An unlinked candidate starts with peer networking dormant. |
| **P3 Tunnel pairing and lifecycle** | 12, 13, 14, 15, 16, 17, 18, 30 | api 12–18 and the link-only slice of 30 | Pairing, expiry, retry and revocation tests pass over the staged listener and fake runner. Credentials cannot cross attempts or authorize management. |
| **P4 Cluster UI and legacy retirement** | 8, 9, 10, 11, 19, 23, 24, 25, 26, 27 · legacy cleanup in 17–18 | db 19 · legacy-backend 8–11 and cleanup in 17–18 · web 23–25 · coordinator 26–27 | Fresh and upgraded migration 26 pass. Legacy routes, module and tables are gone. The Cluster tab uses the new link API. Standalone startup succeeds. |
| **P5 Grants and scope enforcement** | 28, 29, 32, 33, 36 · scoped listener in 30 | authz 28–30 and 32–33 authorization slices · web 36 | Route coverage, token and source validation, per-area access and audit assertions pass. Grant revocation leaves authenticated link health available. |
| **P6 Management proxy and server switching** | 31, 34, 35 · proxy transport in 32 | proxy-ws 31, 32 transport slice and 34 · web 35 | Proxy header, streaming, WebSocket and frontend server-state tests pass. A revoked grant closes its socket within 1 s in the fixture. |
| **P7 Media over NFS** | 37, 38, 39, 40 · runner and module wiring | runner 37–38 and relevant 22 wiring · api 39 and storage wiring · web 40 | Fake export, mount and health fixtures pass. Peer removal stops the mount in the health fixture. Recovery restarts it. |
| **P8 Local transcode foundation** | 41, 42, 43, 44, 45, 46, 47 | transcode-crate 41–46 · hardware 47 | Protocol and argv tests pass. The shim probes and falls back locally. A fixture worker streams output, forwards signals and exits on disconnect. |
| **P9 Remote transcoding and standalone regression** | 48, 49, 50, 51, 52 · runner, API, tab and release wiring | dispatcher-api 48 and API wiring · runner 49 and relevant 22 wiring · web 50 · ops 51–52 and release staging | Dispatcher selection, fallback, version gating and worker cleanup pass in local fixtures. The release bundle validates and standalone E2E tiers pass. |

### Coordination

- The coordinator completes preflight, writes the briefs, integrates lane commits, and verifies the integrated candidate. Record deviations in the drift report.
- Assign one Gemini 4 Neon X-High builder per lane and pin the model and effort on every dispatch. Assign disjoint file paths in each phase. Builders edit in the shared phase checkout. Reviewers and verifiers inherit the coordinator’s checkout read-only.
- Each brief lists owned entry numbers and paths, forbidden paths, dependencies, drift and phase verification. Builders report the local commit SHA, checks, deviations and reasons. Require crate builds and tests, `cargo clippy -p <crate> --all-targets -- -D warnings` and `cargo fmt --all -- --check`.
- Add one fresh Gemini 4 Neon X-High reviewer for the integrated diff before each local gate. Check file coverage, design deviations, authorization branches, command construction and secret handling.
- Close each locally passing phase with one `feat(peers): P<n> <title>` commit and a gate report listing local evidence, the candidate SHA, and the pending two-server acceptance checks. Finish the builders after integration. Keep work local unless publication is explicitly requested.

### Phase P0: Backend groundwork

#### 1. `backend-rs/crates/af-db/src/lib.rs` (Modify)

*   **Type / Scope**: Database schema and helpers.
*   **Proposed Changes**:
    *   In `init_db()`, add `migrate(&conn, 25, "Peer clustering", &[...])` with the migration 25 SQL above, after the v23 verification in `init_db`, which follows the v24 streaming migration.
    *   Preserve the current `record_audit` error logging in `audit.rs` for connection and insert failures.
    *   Add `pub mod peers;`.
    *   Update the schema test in `af-db/src/tests.rs` to expect `25`.
*   **Rationale**: The new tables need versioned migrations, and audit failures must be visible.

#### 2. `backend-rs/crates/af-db/src/peers.rs` (Create)

*   **Type / Scope**: Data-access module.
*   **Proposed Changes**: Typed structs and CRUD for every peer table: `PeerIdentity`, `PeerLink`, `PeerGrant`, `PairingWindow`, `PairingAttempt`, `PeerExport`, `PeerMount`, `TranscodeWorker`, `TranscodeJob`. Each takes a `&Connection`. `AccessMap` is serialized as JSON. Includes unit tests against an in-memory database.
*   **Rationale**: Keeps the SQL out of the handlers.

#### 3. `backend-rs/crates/af-api/src/routes.rs` (Modify)

*   **Type / Scope**: Router and middleware.
*   **Proposed Changes**:
    *   In `security_headers_middleware` (L150-180), record the effective request ID in the current tracing span. Honor inbound IDs up to 128 bytes using letters, digits or `-_.:`. Generate an ID for other input and use the same ID in the trace, forwarded request and response. Wrap the router in a `TraceLayer` span that declares `request_id`.
    *   In `health_check` (route at L338), add `peer_protocol: 1` and `capabilities: [..]`. The current `routes/health.rs` handler returns an empty capability list. File 12 introduces the shared capability function in P3.
*   **Rationale**: Request correlation and the version handshake.

#### 4. `backend-rs/crates/af-api/src/main.rs` (Modify)

*   **Type / Scope**: Startup.
*   **Proposed Changes**: When `AF_LOG_FORMAT=json`, turn on the JSON formatter of `tracing_subscriber` near L234-239. The feature is already enabled in the workspace.
*   **Rationale**: Logs that machines can read, for cross-server triage.

### Phase P1: Browser transport groundwork

#### 5. `frontend-rs/crates/af-web-core/src/api.rs` (Modify)

*   **Type / Scope**: API client.
*   **Proposed Changes**:
    *   Add `pub fn set_active_server(Option<String>)` and `pub fn active_server() -> Option<String>`, backed by a thread-local `RefCell<Option<String>>` in `af-web-core`. P6 drives it from the app’s reactive state using the existing dependency graph.
    *   Add `pub fn api_url(path: &str) -> String`. It rewrites `/api/v1/<rest>` to `/api/v1/peers/{id}/<rest>` when a peer is active, and leaves local paths and already rewritten URLs at their intended destination. Preserve query strings and keep admin peer controls local.
    *   Route every request builder (L806-860) through `api_url`.
    *   Make the CSRF prefix check (L165-202) match both forms.
    *   Unit tests for the rewrite.
*   **Rationale**: One hook makes every tab work remotely.

#### 6. `frontend-rs/crates/af-web-core/src/ws.rs` (Modify)

*   **Type / Scope**: WebSocket client.
*   **Proposed Changes**: Route the telemetry ticket request at L280 through the rewritten `ApiClient` path once. Build the telemetry socket path at L307-311 with `api_url("/api/v1/auth/ws")`. Keep the current window host and `ws(s)` scheme. Test the `/api/v1/auth/ws/logs` rewrite in the helper. P6 adds the live-log client and server integration.
*   **Rationale**: Live telemetry and logs then work for peers.

#### 7. The six direct URL sites (Modify)

*   `frontend-rs/crates/af-web-app/src/tabs/mediaflow.rs:374`
*   `frontend-rs/crates/af-web-app/src/shell.rs:1172`
*   `frontend-rs/crates/af-web-app/src/tabs/fileshare/local_storage.rs:578`
*   `frontend-rs/crates/af-web-app/src/tabs/mcbrowser/helpers.rs:488`
*   `frontend-rs/crates/af-web-app/src/tabs/streaming/live.rs:67`
*   `frontend-rs/crates/af-web-app/src/tabs/settings/backups_oidc.rs:123`

*   **Type / Scope**: Frontend call sites.
*   **Proposed Changes**: Replace each hardcoded `/api/v1/...` URL with `api_url(...)`. Before finishing P1, grep `frontend-rs/crates/af-web-app/src` for other URLs that skip `ApiClient`, such as `href`, `fetch` or `EventSource` with `/api/v1`, and convert them too.
*   **Rationale**: These sites bypass `ApiClient`.

### Phase P2: Privileged peer networking

#### 20. `backend-rs/crates/af-runner/src/peer_network.rs` (Create)

*   **Type / Scope**: Privileged WireGuard management.
*   **Proposed Changes**:
    *   `PeerNetworkRequest` actions: `EnsureIdentity`, `AddPeer{pubkey, endpoint, port, tunnel_ip}`, `RemovePeer{pubkey}`, `SetEndpoint`, `Status`, `EnsurePackages`.
    *   Writes `/etc/wireguard/afpeer0.conf` (0600) and the key at `/etc/aetherflow/peers/afpeer0.key`.
    *   Invoke `wg-quick strip afpeer0` and `wg syncconf afpeer0` through argument-vector commands. Pass configuration through runner-owned storage and protect credential-bearing output.
    *   Enables `wg-quick@afpeer0.service`.
    *   `Status` parses `wg show afpeer0 dump`, reusing `network.rs` parsing.
    *   `EnsurePackages` installs `wireguard-tools` through the runner's existing apt path used by Marketplace recipes.
    *   Copies the identity reconciliation and recovery from `network.rs` (L452, L820, L926, L1007). Never reads or writes `wg0`.
*   **Rationale**: Root-only network changes belong in af-runner.

The runner lane also owns the peer credential file operations used by pairing and grants. The API works through the runner socket.

#### 21. `backend-rs/crates/af-runner/src/peer_network/tests.rs` (Create)

*   **Proposed Changes**: Tests with a fake `wg` binary, following `network/tests.rs`: config generation, syncconf, add and remove, recovery after a failed apply, and a check that `wg0.conf` is never touched.

#### 22. `backend-rs/crates/af-runner/src/lib.rs` (Modify)

*   **Proposed Changes**:
    *   Declare `mod peer_network;` in P2, `mod peer_storage;` in P7 and `mod peer_transcode;` in P9.
    *   Register each phase’s socket route adjacent to the existing network registration. Use the corrected runner paths in the drift report.
    *   Add and re-export `dispatch_peer_network` in P2, `dispatch_peer_storage` in P7 and `dispatch_peer_transcode` in P9. Use the current runner client module.
    *   Extend the current `sandbox_ops.rs` unit policy for `nfs-server.service` and `mnt-af\x2dpeers-` mount units in P7, and `af-transcode-worker.service` in P9.
*   **Rationale**: Runner plumbing.

### Phase P3: Tunnel pairing and lifecycle

The API lane owns files 12–18 and the link-only slice of file 30. Keep the legacy runtime and Cluster UI through this API gate.

#### 12. `backend-rs/crates/af-api/src/peers/mod.rs` (Create)

*   **Type / Scope**: The peer module's root.
*   **Proposed Changes**:
    *   Declares the submodules.
    *   `pub fn admin_routes() -> Router`, mounted under `/api/v1/admin/peers`.
    *   `pub fn public_routes() -> Router`, for `/api/v1/peer-pairing/request`.
    *   `pub fn capabilities() -> Vec<&'static str>`, which returns `["links"]` in P3 when the link service is available. Wire the health handler from file 3 to this helper.
    *   `pub async fn start(state)`. P3 starts the health loop and link-only listener when identity exists. P5 enables scoped management, P7 adds mount checks and P9 starts the dispatcher.
    *   Holds the revocation broadcast channel: `tokio::sync::broadcast<RevocationEvent>`.
*   **Rationale**: One entry point for the feature.

#### 13. `backend-rs/crates/af-api/src/peers/pairing.rs` (Create)

*   **Proposed Changes**:
    *   Window open and close.
    *   Pairing string encode and decode (`afpair1:` plus base64url JSON).
    *   Code hashing, single use, and the 10-minute expiry.
    *   A per-source-IP rate limiter: 5 per minute.
    *   The public request handler, comparison-code derivation, confirmation, and the A-side "pair" call to B's public endpoint, using a `reqwest` client with strict TLS (no `danger_accept_invalid_certs`).
    *   Clock-skew check.
    *   Typed errors from file 14.
*   **Rationale**: Implements the pairing protocol.

Test the matching pending WireGuard peer, attempt ID and expiry for bootstrap. Cover idempotent retry, cancellation and cleanup after a failed confirmation.

#### 14. `backend-rs/crates/af-api/src/peers/errors.rs` (Create)

*   **Proposed Changes**:
    *   `enum PeerError` with every typed code: the pairing codes plus `PEER_SCOPE_DENIED`, `PEER_ROUTE_UNCLASSIFIED`, `LINK_DOWN`, `LINK_REVOKED`, `VERSION_INCOMPATIBLE`.
    *   `IntoResponse` producing `{code, server, step, message, action}`.
*   **Rationale**: Error messages that tell the admin what to do.

#### 15. `backend-rs/crates/af-api/src/peers/health.rs` (Create)

*   **Proposed Changes**:
    *   Every 15 s per link:
        *   WireGuard handshake age, via af-runner status
        *   link-authenticated `GET /health` over the tunnel, with RTT
        *   the capability diff, giving Compatible, Limited or Incompatible
        *   mount sentinel probes (P7)
        *   worker capabilities (P9)
    *   Updates the link's health columns, emits notifications on state changes, and triggers mount stop and start (P7).
*   **Rationale**: Link health and gating.

#### 16. `backend-rs/crates/af-api/src/peers/links.rs` (Create)

*   **Proposed Changes**: Handlers for:
    *   `GET /api/v1/admin/peers`: links, grants in both directions, health, mounts and worker state
    *   `DELETE /api/v1/admin/peers/{id}`: revoke notice, af-runner remove-peer, broadcast, audit
    *   `PUT /api/v1/admin/peers/{id}/endpoint`

    It also handles the incoming `/peer/v1/revoke-notice`.
*   **Rationale**: Link lifecycle.

#### 17. `backend-rs/crates/af-api/src/routes.rs` (Modify)

*   **Proposed Changes**:
    *   **P4** removes the legacy cluster imports and routes at the corrected targets.
    *   **P3** mounts `peers::admin_routes()` under the admin router, behind `admin_only_middleware`.
    *   Mount `peers::public_routes()` outside auth, with a body limit of 4 KiB.
*   **Rationale**: Adds peer routes in P3 and retires legacy routes in P4.

#### 18. `backend-rs/crates/af-api/src/main.rs` (Modify)

*   **Proposed Changes**: **P3** starts `peers::start(state)` alongside the legacy runtime. **P4** removes the legacy startup call at the corrected target.
*   **Rationale**: Startup wiring.

#### 30. `backend-rs/crates/af-api/src/peers/listener.rs` (Create)

*   **Proposed Changes**:
    *   **P3** binds `<tunnel_ip>:AF_PEER_LISTEN_PORT` with `axum::serve` and `ConnectInfo` when identity is configured. Serve pending hello, authenticated health and link lifecycle.
    *   **P5** adds grant delivery and scoped management. Validate the source IP and link token before internal dispatch. Management routes additionally verify the grant token, check method and scope, inject `PeerPrincipal` and `AuthUser`, strip both peer credential headers, and forward to `routes::build_router()`.
    *   Applies per-link concurrency limits.
    *   Every denial is audited.
*   **Rationale**: The single entry point for peer requests.

### Phase P4: Cluster UI and legacy retirement

Apply the legacy cleanup slices of files 17–18. The coordinator writes files 26–27 after integrating the code.

#### 8. `backend-rs/crates/af-services/src/cluster_daemon.rs` (Delete)

*   **Rationale**: The legacy system is replaced. P3 ports single-use code issuance and consumption into file 13 before P4 removes the legacy module and its child files. Use the drift report for current paths.

#### 9. `backend-rs/crates/af-services/src/lib.rs` (Modify)

*   **Proposed Changes**: Remove `pub mod cluster_daemon;` (L1) and anything that only exists to serve it.
*   **Rationale**: The module is deleted.

#### 10. `backend-rs/crates/af-api/src/intelligence.rs` (Modify)

*   **Proposed Changes**: Delete these handlers from the current `intelligence/cluster.rs` module and its re-exports. Preserve unrelated coverage in the mixed test modules:
    *   `get_cluster_nodes` (starts near L5899)
    *   `enroll_worker` (L6183-6213)
    *   `remove_worker` (L6215-6243)
    *   `dispatch_worker_command`
    *   `list_worker_commands`
    *   `get_worker_metrics` (L6337 onward)
    *   the cluster tests near L6609-6674
*   **Rationale**: These are the legacy endpoints.

#### 11. `backend-rs/crates/af-api/src/oidc.rs` (Modify)

*   **Proposed Changes**: Replace `af_services::cluster_daemon::constant_time_eq` at L380, L1137 and L1160 with `af_models::constant_time_eq`.
*   **Rationale**: The old helper is removed.

#### 19. `backend-rs/crates/af-db/src/lib.rs` (Modify, again)

*   **Proposed Changes**:
    *   Remove the base `cluster_nodes` DDL and its index statement in migration 5 at the corrected targets. Verify fresh and upgraded databases.
    *   Add `migrate(&conn, 26, "Remove legacy master/worker clustering", &[...])`.
    *   Update the schema test to `26`.
*   **Rationale**: Drops the legacy tables.

#### 23. `frontend-rs/crates/af-web-app/src/tabs/cluster.rs` (Delete)

*   **Rationale**: Replaced by the module in file 24. `TabId::Cluster` and the key `cluster` in `frontend-rs/crates/af-web-app/src/state.rs` stay unchanged, so `/?tab=cluster` keeps working.

#### 24. `frontend-rs/crates/af-web-app/src/tabs/cluster/mod.rs` and `peers.rs`, `pairing.rs` (Create)

*   **Proposed Changes**:
    *   `mod.rs` renders the page:
        *   a peer list with name, direction in words, access summary, health, RTT, version and compatibility
        *   **Allow a server to manage this one**, which opens the window and shows a copy box and countdown
        *   **Pair with a server**, which takes the pasted string and an endpoint picker
        *   the pending-confirmation card with the comparison code
        *   revoke and endpoint-edit dialogs that list consequences
    *   Typed errors render with their `action` text.
*   **Rationale**: The rebuilt `/?tab=cluster`.

P4 switches the Cluster tab to the P3 link API. Add grant controls in P5, remote management entry in P6, storage in P7 and transcoding in P9.

#### 25. `frontend-rs/crates/af-web-app/src/tabs/mod.rs` and `frontend-rs/crates/af-web-app/src/tabs/l10n.rs` (Modify)

*   **Proposed Changes**: Point the cluster module path at the new folder. Add the new user-facing strings to the l10n catalog, and remove coordinator/worker wording.

#### 26. Docs (Modify)

*   `docs/API.md`: replace §8 (L116-126) with the peer endpoints.
*   `docs/configuration.md`: remove `CLUSTER_MODE`/`CLUSTER_PSK` (L114-115). Add `AF_PEER_TUNNEL_CIDR`, `AF_PEER_WG_PORT`, `AF_PEER_LISTEN_PORT`, `AF_PEER_MAX_CONN`, `AF_PEER_MAX_WS`, `AF_PEER_RTT_WARN_MS`, `AF_TRANSCODE_REAL_FFMPEG` and `AF_LOG_FORMAT`.
*   `docs/architecture.md`: update L15, L33 and L56.
*   `config/openapi-v1.yaml`: replace the cluster operations (around L725).
*   `CHANGELOG.md`: list the breaking removal of `CLUSTER_*`.

#### 27. `docs/peer-clustering.md` (Create)

*   **Proposed Changes**: An operator guide covering:
    *   prerequisites (UDP 51821 reachable, firewall note)
    *   pairing
    *   grants and presets
    *   exports and mounts
    *   transcoding setup
    *   troubleshooting by typed error code

### Phase P5: Grants and scope enforcement

Extend file 30 with the scoped listener and grant delivery. Apply the host-validation slice of file 32. The authz lane owns router registration changes needed for classification.

#### 28. `backend-rs/crates/af-api/src/peers/scopes.rs` (Create)

*   **Proposed Changes**:
    *   `enum Area { Services, Marketplace, Settings, Files, Users, Network, Updates, Transcoding, Read }`.
    *   A static table of route patterns mapped to areas, covering every route registered in `routes.rs`. Read-only overview routes go to `Read`.
    *   `canonicalize(path)`.
    *   `classify(method, path) -> Result<(Area, Mode), PeerError>`.
    *   A forbidden-route list: admin peers, peers proxy, pairing, credential and session creation.
    *   **A test that walks the real router's route list** and fails if any route has no classification. This forces new endpoints to be classified.
*   **Rationale**: Unknown routes fail closed, and new routes can't silently go unclassified.

Derive route and method coverage from the actual registration path. A newly registered route must fail the test until classified.

#### 29. `backend-rs/crates/af-api/src/peers/grants.rs` (Create)

*   **Proposed Changes**:
    *   Handlers `GET`, `PUT` and `DELETE /api/v1/admin/peers/{id}/grant` (the grant this server gives that peer), plus the presets.
    *   Creating a grant:
        *   provisions or re-enables `peer-<name>` with `account_type='peer'` and role `admin`
        *   mints a distinct 256-bit grant token, stores only its hash, and activates the grant after credential delivery
        *   delivers the grant token over the authenticated link at `/peer/v1/grant-token`
    *   Revoking a grant disables the account, clears the grant hash, broadcasts `RevocationEvent` and writes an audit entry. Keep the link credential for health and link operations.
    *   Also: `/peer/v1/grant-offer` for two-way prompts.
*   **Rationale**: Grant lifecycle and the run-as account.

#### 32. `backend-rs/crates/af-api/src/middlewares.rs` (Modify)

*   **Proposed Changes**:
    *   **P6** extracts the streaming body and upgrade-tunnel logic from `app_subdomain_proxy_middleware` (L838-1360, upgrade path L987-1120) into `pub(crate) async fn stream_proxy(req, target: Url, client, opts) -> Response`. The existing middleware then calls it.
    *   **P5** makes `host_validation_middleware` (L1600-1665) skip its Host check when the request has `PeerPrincipal`.
*   **Rationale**: Reuse the proxy, and accept requests from the peer listener.

#### 33. `backend-rs/crates/af-api/src/auth.rs` (Modify)

*   **Proposed Changes**:
    *   Define `pub struct PeerPrincipal { link_id, grant_id, access }`.
    *   `csrf_middleware` (L1179-1232) passes requests that carry `PeerPrincipal`.
    *   `load_active_human_subject` (around L114) accepts `account_type='peer'` when called with a peer context, and rejects it otherwise.
    *   Password and OIDC login reject `account_type='peer'`.
    *   The storage password re-check path accepts `PeerPrincipal` with write access to the area.
*   **Rationale**: Lets existing handlers serve peer requests safely.

#### 36. `frontend-rs/crates/af-web-app/src/tabs/cluster/grants.rs` (Create)

*   **Proposed Changes**: A grant editor with a per-area none/read/write selector and the two presets. It shows the direction in words, and lets you send a two-way offer.

### Phase P6: Management proxy and server switching

Apply the streaming transport slice of file 32. The API lane owns WebSocket server and proxy router wiring. The web lane owns the live-log client and server-switch wiring.

#### 31. `backend-rs/crates/af-api/src/peers/proxy.rs` (Create)

*   **Proposed Changes**:
    *   `ANY /api/v1/peers/{id}/{*rest}`, behind `admin_only_middleware`.
    *   Looks up the link and refuses anything that isn't an active link.
    *   Builds the target from the stored tunnel IP.
    *   Strips and sets the headers described in the Technical Plan, and adds the link and grant tokens.
    *   Calls the shared `stream_proxy` (file 32) for HTTP and WebSocket.
    *   Rewrites `Location` and `Set-Cookie`.
    *   Enforces the per-link caps.
*   **Rationale**: The managing side of remote management.

#### 34. `backend-rs/crates/af-api/src/ws.rs` (Modify)

*   **Proposed Changes**:
    *   Tickets for the run-as user are issued when the ticket request carries `PeerPrincipal`.
    *   The `Origin`/`Host` checks (L1100, L1565) accept peer-listener requests.
    *   Subscribe to `RevocationEvent` and close sockets for the revoked run-as user within 1 s.
*   **Rationale**: Live telemetry and logs work through the proxy, and revocation tears sockets down.

The web lane owns the peer live-log frontend and routes its connection through `api_url("/api/v1/auth/ws/logs")`.

#### 35. `frontend-rs/crates/af-web-app/src/state.rs` and `shell.rs` (Modify)

*   **Proposed Changes**:
    *   Add an app-owned reactive `active_server` signal wired to `af_web_core::api::set_active_server`.
    *   Key resource caches by server.
    *   `shell.rs` renders the identity bar (name and colour) with an "Exit to this server" button.
    *   Destructive-confirmation helpers include the server name.
    *   Controls are disabled when the grant's access for that area is `read` or `none`. The access summary comes from `GET /api/v1/admin/peers`.
*   **Rationale**: UI safety while managing a peer.

### Phase P7: Media over NFS

Apply the P7 slice of file 22 and wire storage into the API listener, health loop and Cluster module.

#### 37. `backend-rs/crates/af-runner/src/peer_storage.rs` (Create)

*   **Proposed Changes**:
    *   `PeerStorageRequest` actions:
        *   `EnsurePackages`: `nfs-kernel-server`, `nfs-common`
        *   `WriteExports{link, tunnel_ip, exports[]}`: writes `/etc/exports.d/aetherflow-peer-<link>.exports`, then runs `exportfs -ra`
        *   `ConfigureNfsd{tunnel_ip}`: writes `/etc/nfs.conf.d/aetherflow-peers.conf`, then restarts `nfs-server`
        *   `EnsureSentinel{path}`
        *   `WriteMount{unit, what, where, ro, opts}` and `RemoveMount`
        *   `StartMount` and `StopMount`
        *   `WriteBindMount` (used in P9)
    *   Mount unit names come from the Rust equivalent of `systemd-escape --path`.
*   **Rationale**: Exports and mounts are privileged changes.

#### 38. `backend-rs/crates/af-runner/src/peer_storage/tests.rs` (Create)

*   **Proposed Changes**: Tests for export line generation (options, IP restriction), unit naming and escaping, the nfsd host config, and a check that nothing outside the owned files is touched.

#### 39. `backend-rs/crates/af-api/src/peers/storage.rs` (Create)

*   **Proposed Changes**: Handlers for:
    *   `GET`, `POST` and `DELETE /api/v1/admin/peers/{id}/exports` (B side)
    *   `GET`, `POST` and `DELETE /api/v1/admin/peers/{id}/mounts` (A side; checks the remote export through `/peer/v1/exports`)

    It also adds media-app safety hooks where AetherFlow configures the app, and gating functions the health loop calls.
*   **Rationale**: The API for media sharing.

The API lane also owns storage wiring in `peers/mod.rs`, `peers/health.rs` and the listener.

#### 40. `frontend-rs/crates/af-web-app/src/tabs/cluster/storage.rs` (Create)

*   **Proposed Changes**: An export picker with folders and a read-only/writable toggle that shows a warning. A mount list with state, last error and the library subfolder hint. An RTT warning banner.

The web lane owns the Cluster module wiring for the storage view.

### Phase P8: Local transcode foundation

#### 41. `backend-rs/Cargo.toml` (Modify)

*   **Proposed Changes**: Add `"crates/af-transcode"` to `members`, and `af-transcode = { path = "crates/af-transcode", version = "=4.0.0" }` to `[workspace.dependencies]`.

#### 42. `backend-rs/crates/af-transcode/Cargo.toml`, `src/lib.rs` and `src/main.rs` (Create)

*   **Proposed Changes**: Dependencies: `tokio`, `serde`, `bincode`, `anyhow`, `nix` (signals), `af-models`. `main` picks the mode: argv0 `ffmpeg` means shim, `worker` means worker, `capabilities` means probe.

Expose the shared protocol and argv code through the library target. P9 adds the API’s local dependency on this crate.

#### 43. `backend-rs/crates/af-transcode/src/protocol.rs` (Create)

*   **Proposed Changes**: The frame enum, including `RunLocal` and `Started`, a length-prefixed codec, and bounded channel helpers. Unit tests round-trip every frame and reject oversized frames (over 1 MiB).

#### 44. `backend-rs/crates/af-transcode/src/argv.rs` (Create)

*   **Proposed Changes**:
    *   `is_probe(args)`
    *   `required_capability(args) -> Capability { hwaccel: Option<..>, encoder: Option<String>, filters: Vec<..> }`
    *   `rewrite_render_node(args, from, to)`
    *   Table-driven tests built from real Jellyfin command lines: VA-API, QSV, NVENC, software, subtitle burn-in, probe calls.

#### 45. `backend-rs/crates/af-transcode/src/shim.rs` (Create)

*   **Proposed Changes**:
    *   If `is_probe`, `exec` the real ffmpeg.
    *   Otherwise connect to `/run/aetherflow/transcode.sock` with a 2 s timeout. On any error, `exec` the real ffmpeg.
    *   Send `Start` and `exec` on `RunLocal`. Once the worker confirms `Started`, a dropped stream fails the current job and Jellyfin may retry.
    *   Otherwise pump stdin into `Stdin`, `Stdout`/`Stderr` into its own stdio, and SIGTERM/SIGINT into `Signal`, then exit with the `Exit` code.

#### 46. `backend-rs/crates/af-transcode/src/worker.rs` and `src/capabilities.rs` (Create)

*   **Proposed Changes**:
    *   The worker listens on `/run/aetherflow/transcode-worker.sock`. Each connection spawns the real ffmpeg with the rewritten device path, pumps frames, forwards signals, and returns `Exit`.
    *   `capabilities` runs the real ffmpeg with `-version` and `-encoders`, and lists `/dev/dri/renderD*`. It prints JSON.

Use disposable local ffmpeg fixtures in P8. P9 installs and enables the worker service.

#### 47. `backend-rs/crates/af-hardware/src/lib.rs` (Modify)

*   **Proposed Changes**: Add `pub fn detect_render_nodes() -> Vec<RenderNode>`, factored out of the scan in `get_gpu_transcode_flags` (L189-246). Leave `get_gpu_transcode_flags` behaving exactly as before.

### Phase P9: Remote transcoding and standalone regression

Apply the P9 slice of file 22 and wire the dispatcher into the API and Cluster module. Integrate release staging before verifying the deployment candidate.

#### 48. `backend-rs/crates/af-api/src/peers/transcode.rs` (Create)

*   **Proposed Changes**:
    *   **Dispatcher.** A unix socket server at `/run/aetherflow/transcode.sock`, mode 0660, group `jellyfin`. It does worker selection and relays frames to `/peer/v1/transcode/jobs` over the peer link.
    *   **Worker side.** The `/peer/v1/transcode/jobs` WebSocket handler requires `transcoding: write` and relays to the local worker socket.
    *   **Settings.** `GET` and `PUT /api/v1/admin/peers/transcode` cover the enable flag, weights, caps and the parity test trigger.
    *   **Records.** Job records and pruning.
    *   **Capabilities.** Adds `"transcode"` to `peers::capabilities()` and worker capability JSON to `/health`.
*   **Rationale**: The core of remote transcoding.

Own API startup, listener and health wiring. The worker route requires both credentials and write access to transcoding.

#### 49. `backend-rs/crates/af-runner/src/peer_transcode.rs` (Create)

*   **Proposed Changes**:
    *   `PeerTranscodeRequest` actions:
        *   `InstallShim`: copies `af-transcode` to `/usr/lib/aetherflow/transcode/ffmpeg` and symlinks `ffprobe`
        *   `EnableJellyfin` and `DisableJellyfin`: write or remove `/etc/systemd/system/jellyfin.service.d/20-aetherflow-transcode.conf` (`JELLYFIN_FFMPEG` and `TMPDIR`), create `/var/cache/jellyfin/af-tmp`, then run `daemon-reload` and restart `jellyfin.service`
        *   `InstallWorkerUnit`: `af-transcode-worker.service` with `User=jellyfin`, `SupplementaryGroups=render video`, `RuntimeDirectory=aetherflow`
        *   `ExportTranscodeDirs{tunnel_ip, uid, gid}`
        *   `MountTranscodeDirs`
        *   `BindMedia{from, to}`

Source the shim and worker from the verified release bundle. Apply the P9 runner wiring and unit policy from file 22.

#### 50. `frontend-rs/crates/af-web-app/src/tabs/cluster/transcode.rs` (Create)

*   **Proposed Changes**:
    *   A "Use paired servers for Jellyfin transcoding" switch on the Jellyfin server.
    *   A `jellyfin-ffmpeg` version row for each server, with a mismatch warning and an **Update to match** button.
    *   A per-worker card with its encoders, ffmpeg version, weight, max jobs, parity status and a "Run parity test" button.
    *   Recent jobs, showing local or remote and the exit code.

The web lane owns the Cluster module wiring for the transcode view.

#### 51. `backend-rs/crates/af-cli/src/lib.rs` (Modify)

*   **Proposed Changes**: Add `cluster diagnose <link>`. It prints link health, the `afpeer0` handshake, the grant access summary, exports and mounts with probe results, worker status, and the last 20 audit entries for the link.

The ops lane owns staging `bin/af-transcode` in `scripts/build_gold.sh` for each full server release architecture. Update the bundle checks in `.github/workflows/release.yml` and executable handling in `af-release/src/artifact/archive.rs` and their existing tests. Verify that the runner finds the binary in the installed release and that older bundles remain installable.

#### 52. `config/package_automation.json` (Modify)

*   **Type / Scope**: Package sandbox config.
*   **Proposed Changes**: In the `jellyfin` entry's `sandbox_rw_paths` (L25-34), add `"-/run/aetherflow/transcode.sock"` so the sandboxed Jellyfin process can connect to the dispatcher socket. Keep the leading `-`, which marks the path optional and keeps the unit starting when transcoding is off.
*   **Rationale**: Jellyfin runs under AetherFlow's `dotnet` sandbox profile. Without this, the shim falls back to local ffmpeg every time.

### Verification Plan

Run the build and tests on server A. Record local results before closing each phase. Track two-server acceptance against the same phase commit.

#### Common local gate for every phase

1. Run `cargo build --workspace --release` in the backend workspace.
2. Run `trunk build --release` in `frontend-rs`, which owns `Trunk.toml` and `index.html`. This builds `af-web-app` through the workspace entry point.
3. Test `af-db`, `af-api`, `af-runner` and `af-hardware` in the backend workspace, plus `af-transcode` from P8 onward. Test `af-web-core` in the frontend workspace.
4. Run `cargo clippy --workspace --all-targets -- -D warnings` and `cargo fmt --all -- --check` in each workspace. Run `python3 tests/check_shell_hygiene.py` from the repository root.
5. Run the local phase-specific checks. Use isolated test data, processes and runner fixtures. Get approval before changing WireGuard, NFS or systemd on A.

#### Local phase-specific checks

- **P0** tests migration 25 on fresh and legacy databases, request IDs in JSON logs, and `/health` protocol 1 with an empty capability list. Verify standalone sign-in and standard API responses with local fixtures.
- **P1** tests local URL and CSRF behavior, single peer-prefix rewriting, telemetry ticket and upgrade paths, log URL and direct requests.
- **P2** tests config generation, sync, status, add and remove, rollback and credential handling with fake `wg` and runner fixtures. Verify dormant startup and that the peer runner never accesses `wg0.conf`.
- **P3** tests pairing-code expiry and reuse, closed windows, rate limiting, typed errors, wrong tunnel source, attempt-bound bootstrap, retries and pending cleanup. Cover successful pairing, link health and revocation with a local listener fixture and fake privileged runner.
- **P4** verifies migration 26 on fresh and legacy databases and removal of legacy routes and tables. Verify Cluster tab routing and control actions against the peer API contract with fixtures. Check startup with no links.
- **P5** tests full route classification against actual registrations. Exercise `//`, `%2e%2e`, mixed case, forbidden routes, read-only method denial, wrong tunnel source with a valid token, wrong link or grant token with a valid source, and every listener and scope decision branch. Cover one-way and two-way grants, audited denials and healthy links after grant revocation.
- **P6** tests proxy header stripping and rewriting, stored-link target selection, request and response streaming, WebSocket upgrade and revocation, active-server isolation and audit identity. Verify live-log fixture sockets close within 1 s of revocation.
- **P7** uses fake `exportfs` and unit fixtures for exports, escaped mounts, host binding and write boundaries. Verify stop and recovery behavior for an explicitly removed peer and consecutive sentinel failures.
- **P8** tests every protocol frame, oversized frame rejection, VA-API, QSV, NVENC, software, subtitle and probe arguments. Test the shim’s local probe and fallback, worker output, signals and termination on disconnect using disposable local fixtures.
- **P9** verifies the release bundle and tests dispatcher selection, mismatch and fallback, relay lifecycle and worker death cleanup with local fixtures. Pass the existing `tests/e2e` tiers on a standalone instance with no links.

#### Deferred two-server acceptance

After B is ready, build or select the exact passing commit for each phase and run the following checks in order. State the exact commands and receive approval before changing server B or WireGuard, NFS or systemd on either server. All peer networking changes target `afpeer0`. Verify `wg0` preservation without changing it.

- **P0.** Verify protocol 1 and empty capabilities in `/health` on both deployed servers, plus standalone sign-in and standard API responses.
- **P1.** Smoke-test both deployed dashboards and the existing telemetry.
- **P2.** Start both deployed candidates with peer networking dormant.
- **P3.** Pair over the VLAN using the admin API. Both links become healthy before grants exist. Revoke from B, see the notice on A, re-pair, and verify `wg0` preservation.
- **P4.** Deploy migration 26. Repeat pair and revoke through `/?tab=cluster`, exercise endpoint editing, and verify unlinked operation and `wg0` preservation.
- **P5.** Exercise none, read and write through the scoped listener, two-way grants and revocation. Verify target audit entries and that grant revocation preserves authenticated link health.
- **P6.** On A, browse all B’s dashboard tabs under a read-only grant, force a write and verify denial and audit on B. With a write grant, restart a service, change a setting, install and uninstall a Marketplace app, and upload a 2 GB file through McBrowser over tus. Verify live logs, B’s read-only services grant on A, closure of the live-log socket within 1 s of revocation, target audit identity and the active-server bar.
- **P7.** Export the test library read-only from B. Scan and play a 4K remux over NFS from A. With approval, remove B’s peer on A’s `afpeer0`. Within 30 s the mount stops and the library path disappears. Rescan without a drop in the Jellyfin item count. Restore the link and verify the mount returns.
- **P8.** Smoke-test that both deployed hosts keep their ordinary Jellyfin setup.
- **P9.** Run these checks on the two hosts with approved Jellyfin and worker changes.
    1. Enable B as a worker and pass the parity test. Play a VA-API job. Verify ffmpeg runs on B, segments appear on A, and seeking and ordinary stopping work.
    2. Force an NVENC job and see it run locally on A. Stop af-api on A and verify local transcoding.
    3. Revoke the link mid-stream. The current remote stream ends. The next request falls back to local transcoding.
    4. Upgrade `jellyfin-ffmpeg` on one server. Verify local fallback and the Cluster mismatch warning. Use **Update to match** and check eligibility within one health tick.
    5. Pause the worker’s ffmpeg with `kill -STOP` to exercise Jellyfin’s hard-kill path. Within Jellyfin’s kill timeout plus 5 s, confirm no orphan worker ffmpeg remains with `pgrep -u jellyfin ffmpeg`.
    6. Check that Jellyfin reports `/usr/lib/aetherflow/transcode/ffmpeg`.

--------------------------------------------------------------------------------

<!-- Provenance: Initial structural drafting via EGM. -->

*Drafted with EGM*
