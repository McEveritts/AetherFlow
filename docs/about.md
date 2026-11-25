# About AetherFlow

AetherFlow is a self-hosted control plane for bare-metal Linux servers running media servers, seedboxes, and automation services directly under `systemd`.

Rather than coordinating separate container dashboards and ad-hoc scripts, AetherFlow consolidates service orchestration, scoped tenant file management, hardware telemetry, subdomain TLS ingress, and human-gated AI diagnostics behind a single Rust control plane.

> [!NOTE]
> AetherFlow v4.0.0 ships the `aetherflow-api` control-plane/runner binary, the unified `af` (`af-cli`) CLI (`bin/af`), the native Rust LibreSpeed `bin/speedtest-backend`, and external `web/dist` WASM dashboard assets.

---

## Architectural Foundation

AetherFlow enforces privilege separation and direct bare-metal integration ([System Architecture](./architecture.md)):

- **11-Crate Rust Control Plane + 4-Crate WASM UI**: `backend-rs` (`Axum` + `Tokio`) serves the compiled **Leptos Rust WebAssembly (`frontend-rs`)** dashboard from external `web/dist` assets (`STATIC_DIR` or `<exe-dir>/web/dist`). The control plane and dashboard require no Node.js, Go, or Redis daemons (host release/maintenance operations require `python3` and `openssl`).
- **Zero-Sudo Socket Boundary (`aetherflow-runner.service`)**: Privileged root operations (`systemctl`, Marketplace installers, WireGuard/Tailscale control, quotas, isolated `DynamicUser=yes` plugin units, and transient `aetherflow-self-update-<command>-<channel>-<8hex>.service` deployments) run inside the Unix socket daemon `aetherflow-runner.service` (`aetherflow-api runner`) behind `/run/aetherflow/runner.sock` with strict allowlists and ancestor-symlink guards.
- **Native McBrowser (`af-files` + `af-api::mcbrowser`)**: Built-in left-sidebar file manager pairing Linux `openat2` confinement primitives (`af-files`) with HTTP routes in `af-api::mcbrowser` for `0700` per-user storage (`/var/lib/aetherflow/mcbrowser`), resumable chunked uploads up to 64 GiB, ETag-guarded UTF-8 editing, 9-format archive tools, public shares, and search ([Native McBrowser](./mcbrowser.md)).
- **Real-Time Telemetry**: Hardware, process, and NVIDIA NVML / DRM GPU metrics are pushed over full-duplex WebSockets with an immediate initial state snapshot on connect.

### Design Constraints

1. **Direct Host Visibility**: Manage Linux services natively via `systemd` and Apache2 without introducing a mandatory container layer.
2. **Least-Privilege Control Plane**: Keep the web-facing API unprivileged (`User=aetherflow`, `ProtectSystem=strict`) and isolate all root mutations behind `/run/aetherflow/runner.sock`.
3. **Human-Gated Automation**: Require explicit administrator approval before executing AI-proposed service mutations or default `af-heal` recovery actions.

---

## Core Capabilities

### 1. Rust WebAssembly Dashboard (`frontend-rs`)

Built on **Leptos Rust WebAssembly**:

- **Real-Time Hardware Telemetry**: Live CPU, RAM, swap, Disk I/O (`/proc/diskstats`), NVML/DRM GPU utilization/VRAM/temperature, and network throughput charts with hover-pause inspection.
- **Canonical Streaming Analytics**: Live Jellyfin, Plex, and Emby (staged) session cards paired with a snapshot-consistent playback history archive, server-identity verification, and CSV/JSON portability ([Streaming History Contract](./streaming-history-contract.md)).
- **Native Network & VPN Control**: Built-in **WireGuard** (`wg0` peer and QR management), **Tailscale** mesh VPN routing controls, external subdomain ingress settings, and host network hardware inventory ([Network: WireGuard & Tailscale](./network-vpn.md)).

### 2. FlowAI Assistant

A multi-provider assistant integrated into the control plane (Gemini, Anthropic Claude, OpenAI, Ollama, and LM Studio — see [FlowAI Assistant](./flowai.md)):

- **Chat & Support Diagnostics**: Answers administrator queries using an instantaneous hardware snapshot on `/chat`, and client-supplied metrics/logs (or the last 25 `admin_audit_log` rows as fallback) on admin-only `/support`.
- **Service Action Detection**: Extracts supported service `stop` and `restart` proposals for allowlisted service names from assistant responses for administrator callers.
- **Action Approval Gate**: An administrator authorization gate that queues proposed service actions in SQLite (`pending_actions`) inside the **Approval Inbox** for explicit administrator approval or rejection.

### 3. AetherMarketplace (77 Bare-Metal Apps)

A managed catalog of **77 native Linux applications** including Plex, Jellyfin, the `*Arr` stack, Palate, Maintainerr, Dispatcharr, Threadfin, qBittorrent, Qui, Autobrr, McVNC, KasmVNC, Tailscale, and WireGuard ([AetherMarketplace](./marketplace.md)):

- **Managed Lifecycles**: Installation, in-place update, reinstall, and removal workflows backed by locked Bash installers by default and 9 opt-in declarative Rust recipes (`AETHERFLOW_ENABLE_RUST_PACKAGES=1`).
- **Automatic Subdomain Ingress**: Provisions `<app>.<baseDomain>` for HTTP-capable applications through Apache2, the streaming Subdomain Gateway, and `af-certbot-sync`.
- **Service Orchestration**: Manages app-specific `systemd` units (upstream names or `af-<app>.service`) and shared Apache2 vhosts where applicable, applying `af-systemd-sandbox` drop-ins to eligible non-privileged services.

---

## Security Controls

AetherFlow v4.0.0 applies defense-in-depth controls across the host ([Security & Hardening](./security.md), [Threat Model](./threat_model.md)):

- **TOTP 2FA & OIDC**: Optional per-user TOTP two-factor authentication with bcrypt-hashed recovery codes for enrolled accounts, plus a built-in OIDC provider for downstream SSO.
- **SQLite-Backed JWT Sessions**: 15-minute HS256 `aetherflow_session` cookies validated synchronously against SQLite `revoked_tokens` and user active state (`active_sessions` additionally checked on perimeter SSO verification, `/metrics`, and optional authenticated `GET /api/v1/public/marketplace`).
- **AES-256-GCM Envelope Encryption**: Stored AI provider API keys, user TOTP secrets (`users.totp_secret`), streaming server API keys (`streaming_servers.api_key`), notification channel secrets (`notification_channels.config`), `/var/lib/aetherflow/.master.creds`, and SQLite `system_config.master_credentials` are encrypted at rest (`enc:v1:<base64(nonce || ciphertext)>`) using `AES_MASTER_KEY`. OIDC client secrets are SHA-256 hashed (`oidc_clients.client_secret_hash`) and the OIDC RS256 signing key is stored in a `0600` PEM file.
- **CSRF & Host Validation**: Double-submit `X-CSRF-Token` cookie/header enforcement on state-mutating cookie-authenticated endpoints (Bearer tokens and `/refresh` exempt) plus `ALLOWED_HOSTS` verification.

---

## Target Operators

- **Home Server & Media Operators** managing bare-metal Linux media and automation stacks without Docker.
- **Seedbox Operators** requiring user disk quotas, automated subdomain routing, and multi-app lifecycle management.
- **Systems Administrators** seeking a compiled Rust control plane and unified [`af` CLI](./rust-admin-cli.md) for Debian 12/13 and Ubuntu 22.04/24.04 nodes.

> [!TIP]
> For a step-by-step installation walkthrough, see the [Quickstart Guide](./quickstart.md).
