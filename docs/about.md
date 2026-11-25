# About AetherFlow

AetherFlow is a self-hosted control plane for bare-metal Linux servers running media servers, seedboxes, and automation services directly under `systemd` and `Apache2`.

Rather than layering container orchestration over host services, AetherFlow consolidates 77 bare-metal Marketplace applications, capability-scoped tenant file management, real-time hardware and streaming telemetry, peer-to-peer multi-server clustering, subdomain TLS ingress, and human-gated AI diagnostics behind a single Rust control plane.

> [!NOTE]
> AetherFlow v4.0.0 compiles the 12-crate `backend-rs` workspace into `aetherflow-api` (unprivileged web API + `aetherflow-api runner` root socket daemon), `bin/af` (unified administrative CLI), `bin/speedtest-backend` (native Rust LibreSpeed server), and `bin/af-transcode` (Jellyfin FFmpeg shim and remote transcode worker), paired with the 4-crate Leptos Rust/WASM dashboard (`frontend-rs`) shipped as external `web/dist` assets.

---

## Architectural Foundation

AetherFlow enforces privilege separation and direct bare-metal integration ([System Architecture](./architecture.md)):

- **12-Crate Rust Control Plane + 4-Crate WASM UI**: `backend-rs` (`Axum` + `Tokio`) serves the compiled **Leptos Rust WebAssembly (`frontend-rs`)** 16-tab dashboard from external `web/dist` assets (`<exe-dir>/web/dist` by default, or explicit `STATIC_DIR`). The control plane and dashboard require no Node.js, Go, or Redis daemons (host release/maintenance operations require `python3` and `openssl`).
- **Zero-Sudo Socket Boundary (`aetherflow-runner.service`)**: Privileged root operations (`systemctl`, Marketplace installers, WireGuard/Tailscale control, Peer Clustering `afpeer0`/NFS/transcode setup, disk quotas, isolated `DynamicUser=yes` plugin units, and transient `aetherflow-self-update-<command>-<channel>-<8hex>.service` deployments) run inside `aetherflow-runner.service` (`aetherflow-api runner`) behind `/run/aetherflow/runner.sock` (`0660 root:aetherflow`) with `SO_PEERCRED` / `/proc/<pid>/exe` checks, strict allowlists, and ancestor-symlink guards.
- **Native McBrowser (`af-files` + `af-api::mcbrowser`)**: Built-in file manager pairing Linux `openat2` confinement primitives (`af-files`) with HTTP handlers in `af-api::mcbrowser` for `0700` per-user storage (`/var/lib/aetherflow/mcbrowser/user-<id>`), resumable TUS uploads up to 64 GiB, ETag-guarded UTF-8 editing, 9-format archive tools, public shares, and search ([Native McBrowser](./mcbrowser.md)).
- **Real-Time Telemetry**: Hardware, process, and NVIDIA NVML / DRM GPU metrics are pushed over full-duplex WebSockets with an immediate initial state snapshot on connect.

### Design Constraints

1. **Direct Host Visibility**: Manage Linux services natively via `systemd` and `Apache2` without a mandatory container runtime.
2. **Least-Privilege Control Plane**: Keep the web-facing API unprivileged (`User=aetherflow`, `ProtectSystem=strict`, `NoNewPrivileges=yes`) and isolate all root mutations behind `/run/aetherflow/runner.sock`.
3. **Human-Gated Automation**: Require explicit administrator approval before executing AI-proposed service mutations or default `af-heal` recovery actions.

---

## Core Capabilities

### 1. Rust WebAssembly Dashboard (`frontend-rs`)

Built on **Leptos Rust WebAssembly** across **16 dashboard tabs** (`Overview`, `Approval Inbox`, `Services`, `Marketplace`, `McBrowser`, `File Share`, `Streaming`, `MediaFlow`, `FlowAI`, `Network`, `Cluster`, `Users`, `Audit Trail`, `Settings`, `Notifications`, `Quotas`):

- **Real-Time Hardware Telemetry**: Live CPU, RAM, swap, Disk I/O (`/proc/diskstats`), NVML/DRM GPU utilization/VRAM/temperature, and network throughput charts with hover-pause inspection.
- **Canonical Streaming Analytics**: Live Jellyfin, Plex, and Emby (staged) session cards paired with a snapshot-consistent playback history archive, server-identity verification, and CSV/JSON portability ([Streaming History Contract](./streaming-history-contract.md)).
- **Native Network & VPN Control**: Built-in **WireGuard** (`wg0` peer and QR management), **Tailscale** mesh VPN routing controls, external subdomain ingress settings, and host network hardware inventory ([Network: WireGuard & Tailscale](./network-vpn.md)).

### 2. Peer Clustering (`Cluster` Tab & `af-transcode`)

Link independent AetherFlow servers over a dedicated AetherFlow-managed WireGuard interface (`afpeer0`) without fixed master/worker roles ([Peer Clustering](./peer-clustering.md)):

- **Zero-Access-by-Default Pairing & Delegated Grants**: Single-use 10-minute pairing windows with 6-digit verification codes and SSRF-guarded HTTPS bootstrap, followed by explicit per-area `none` / `read` / `write` grants across 8 areas (`services`, `marketplace`, `settings`, `files`, `users`, `network`, `updates`, `transcoding`) with sub-second revocation teardown.
- **Scoped Remote Server Switching**: Manage paired peers from the local dashboard through `/api/v1/peers/{id}/*` with `SERVER_EPOCH` and `AreaFence` isolation and a persistent remote-server identity bar.
- **Cross-Peer Storage Federation & Jellyfin Transcode Offload**: Share media folders over NFSv4.2 bound exclusively to `afpeer0` (`/v1/peer-storage`) with `.af-peer-sentinel` health gating, offload Jellyfin 12.4 `ffmpeg` jobs to paired `af-transcode-worker.service` hosts (`PrivateNetwork=yes`, secret-free `/etc/aetherflow/transcode.env`), and inspect links read-only via `sudo af cluster diagnose <link>`.

### 3. FlowAI Assistant

A multi-provider assistant integrated into the control plane (Gemini, Anthropic Claude, OpenAI, Ollama, LM Studio, and Anthropic-Local — see [FlowAI Assistant](./flowai.md)):

- **Chat & Support Diagnostics**: Answers administrator queries using an instantaneous hardware snapshot on `/chat`, and client-supplied metrics/logs (or the last 25 `admin_audit_log` rows as fallback) on admin-only `/support`.
- **Service Action Detection**: Extracts supported service `stop` and `restart` proposals for allowlisted service names from assistant responses for administrator callers.
- **Action Approval Gate**: Queues proposed service actions in SQLite (`pending_actions`) inside the **Approval Inbox** for explicit administrator approval or rejection before execution.

### 4. AetherMarketplace (77 Bare-Metal Apps) & Plugin Platform

A managed catalog of **77 native Linux applications** including Plex, Jellyfin, the `*Arr` stack, Palate, Maintainerr, Dispatcharr, Threadfin, qBittorrent, Qui, Autobrr, McVNC, KasmVNC, Tailscale, and WireGuard ([AetherMarketplace](./marketplace.md)):

- **Managed Lifecycles**: Installation, in-place update, reinstall, and data-preserving removal workflows backed by locked Bash installers by default and 9 opt-in declarative Rust recipes (`AETHERFLOW_ENABLE_RUST_PACKAGES=1`).
- **Automatic Subdomain Ingress**: Provisions `<app>.<baseDomain>` for HTTP-capable applications through Apache2, the streaming Subdomain Gateway, and `af-certbot-sync`.
- **Sandboxed Plugin Runtime**: Discovers `plugins/*/plugin.manifest.json`, runs managed backends in `DynamicUser=yes` transient systemd units via `af-runner`, and mounts plugin UIs inside strict-CSP opaque iframes ([Plugin Runtime & SDK](../plugins/README.md)).

---

## Security Controls

AetherFlow v4.0.0 applies defense-in-depth controls across the host ([Security Guide](./security.md), [Threat Model](./threat_model.md)):

- **TOTP 2FA & Built-In OIDC Provider**: Optional per-user TOTP two-factor authentication with bcrypt-hashed recovery codes for enrolled accounts, plus a built-in OIDC provider (authorization code + PKCE + device flow) for downstream SSO.
- **SQLite-Backed JWT Sessions**: 15-minute HS256 `aetherflow_session` cookies validated uniformly via `verify_active_session_on_conn` against SQLite `revoked_tokens`, unexpired `active_sessions`, client fingerprint, active user state, and `sessions_revoked_after`.
- **AES-256-GCM Envelope Encryption**: Stored AI provider API keys, user TOTP secrets (`users.totp_secret`), streaming server API keys (`streaming_servers.api_key`), notification channel secrets (`notification_channels.config`), `/var/lib/aetherflow/.master.creds`, and SQLite `system_config.master_credentials` are encrypted at rest (`enc:v1:<base64(nonce || ciphertext)>`) using `AES_MASTER_KEY`. OIDC client secrets are SHA-256 hashed (`oidc_clients.client_secret_hash`) and the OIDC RS256 signing key is stored in a `0600` PEM file.
- **CSRF, Host Validation & Supply-Chain Verification**: Double-submit `X-CSRF-Token` enforcement on state-mutating cookie requests, outer `ALLOWED_HOSTS` verification, and SHA-256 + Sigstore/SLSA v1 build provenance verification on pull-based releases.

---

## Target Operators

- **Home Server & Media Operators** managing bare-metal Linux media and automation stacks (single-node or multi-server via Peer Clustering) without Docker.
- **Seedbox Operators** requiring user disk quotas, automated subdomain routing, and multi-app lifecycle management.
- **Systems Administrators** seeking a compiled Rust control plane and unified [`af` CLI](./rust-admin-cli.md) for Debian 12/13 and Ubuntu 22.04/24.04 nodes.

> [!TIP]
> Start with the [Quickstart Guide](./quickstart.md) or browse the full [Documentation Index](./README.md).
