# About AetherFlow

AetherFlow is a modern, sovereign control plane for self-hosted bare-metal infrastructure.

Designed as a unified **Mission Control** for cloud and local Linux systems, AetherFlow specializes in **media servers**, **seedboxes**, **home servers**, and automation-heavy infrastructure workflows.

Rather than treating the server as a loose collection of scripts and container panels, AetherFlow treats it as a cohesive managed platform: one place to operate services, manage files, observe real-time hardware telemetry, automate ingress, and safely delegate remediation through an AI-assisted interface.

> [!NOTE]
> AetherFlow v4.0.0 is built around a compiled 11-crate, single-binary **Rust (`Axum` + `Tokio`)** control plane (`aetherflow-api`), the unified **`af` (`af-cli`)** administrative CLI, an embedded **Next.js 16 (Obsidian V2)** static frontend, a privileged UNIX socket runner (`aetherflow-runner`), **Native McBrowser** (`af-files`), and native **systemd** service orchestration.

---

## Architectural Foundation

AetherFlow is engineered for bare-metal performance and strict privilege separation:

- **11-Crate Single-Binary Rust Control Plane**: The compiled **Rust (`Axum` + `Tokio`)** backend (`backend-rs`) embeds the **Next.js 16 (Obsidian V2)** static export directly via `rust-embed` (`af-api`), eliminating separate Node.js runtime daemons and external Redis dependencies.
- **Zero-Sudo Socket Boundary (`aetherflow-runner`)**: Privileged root operations (`systemctl`, Marketplace installers, WireGuard/Tailscale control, quotas, and isolated `aetherflow-self-update.service` deployments) are isolated behind `/run/aetherflow/runner.sock` (`aetherflow-runner.service`) with strict allowlists and ancestor-symlink guards.
- **Native McBrowser (`af-files`)**: Built-in left-sidebar file manager with capability-scoped per-user storage (`/var/lib/aetherflow/mcbrowser`), resumable chunked uploads up to 64 GiB, ETag-guarded Ace code editing, 9-format archive tools, and FlowAI natural-language BFS file search.
- **Frame-0 Real-Time Telemetry**: Immediate hardware, process, and NVML GPU telemetry delivered via full-duplex WebSockets ("Hyperspeed") with decoupled UI layout updates.

### Design Philosophy

AetherFlow is shaped by three core beliefs:
1. **Infrastructure tools should feel powerful, not fragile.**
2. **Operators deserve direct system visibility, not heavy container abstractions.**
3. **Automation is safest when bounded by a human-in-the-loop approval gate.**

---

## Core Capabilities

### 1. Unified Obsidian V2 Dashboard
A high-fidelity "Mission Control" interface built on Next.js 16 and React 19:
- **Open-Canvas Telemetry**: Density-aware real-time hardware tracking (CPU, RAM, Disk I/O, NVML/DRM GPU, Network BDP) with hover-pause sparklines.
- **Canonical Streaming Analytics**: Live Jellyfin & Plex session cards paired with a snapshot-consistent playback history archive, server-identity verification, and CSV/JSON portability.
- **Native Network & VPN Control**: Built-in **WireGuard** (`wg0` peer and QR management) and **Tailscale** mesh VPN routing controls.

### 2. FlowAI Assistant
A multi-provider infrastructure assistant integrated directly into the control plane (Gemini, Anthropic Claude, OpenAI, Ollama, LM Studio):
- **Support Mode**: Diagnoses issues by analyzing systemd journals and real-time hardware metrics.
- **Assistant Mode**: Proposes maintenance workflows, package operations, and system actions.
- **Action Approval Gate**: A cryptographic security boundary that queues state-mutating AI proposals (`pending_actions`) in the **Approval Inbox** for explicit administrator authorization.

### 3. AetherMarketplace (77 Bare-Metal Apps)
A managed ecosystem of **77 native Linux applications** (including Plex, Jellyfin, the `*Arr` stack, Palate, Maintainerr, Dispatcharr, Threadfin, qBittorrent, Qui, Autobrr, McVNC, KasmVNC, Tailscale, and WireGuard):
- **One-Click Deploy & In-Place Updates**: Idempotent installation, update, and removal lifecycles backed by 15 declarative Rust recipes and locked Bash installers.
- **Whatbox-Style Automatic Subdomain Ingress**: Automatically provisions `<app>.<baseDomain>` through Apache2, the streaming Subdomain Gateway, and `af-certbot-sync`.
- **Service Orchestration**: Manages dedicated `systemd` units and `af-systemd-sandbox` profiles for every installed application.

---

## Security First

AetherFlow v4.0.0 enforces defense-in-depth for production environments:
- **TOTP 2FA & OIDC**: Mandatory two-factor authentication with recovery codes and a built-in OIDC provider for downstream SSO.
- **SQLite-Backed JWT Sessions**: Stateless HS256 `aetherflow_session` cookies backed by SQLite `revoked_tokens` and `active_sessions` tracking.
- **AES-256-GCM Envelope Encryption**: All sensitive API keys, OIDC secrets, and webhook credentials are encrypted at rest (`enc:v1:`) in the bundled SQLite WAL database using `AES_MASTER_KEY`.
- **CSRF & Host Validation**: Native origin/token CSRF enforcement and `ALLOWED_HOSTS` verification across all API routes.

---

## Who is AetherFlow for?

AetherFlow is built for operators who value precision and control over their infrastructure:
- **Home Server & Media Enthusiasts** seeking a premium, zero-Docker control plane for their local hardware.
- **Seedbox Operators** who need high-concurrency bare-metal throughput, quota enforcement, and automated subdomain routing.
- **DevOps Engineers** who want a compiled Rust control plane and unified `af` CLI for bare-metal Debian/Ubuntu nodes.

> [!TIP]
> The core idea is not to hide infrastructure. It is to make infrastructure easier to understand, operate, and trust. For a guided setup path, see the [Quickstart Guide](./quickstart.md).
