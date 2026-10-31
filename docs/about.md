# About AetherFlow

AetherFlow is a modern control plane for self-hosted infrastructure.

AetherFlow is a sovereign, bare-metal control plane for self-hosted infrastructure: a unified **Mission Control** for cloud and local systems, specializing in **media servers**, **seedboxes**, **home servers**, and automation-heavy infrastructure workflows.

Rather than treating the server as a loose collection of scripts and panels, AetherFlow treats it as a managed platform: one place to operate services, observe the system, automate tasks, and safely delegate actions through an AI-assisted interface.

> [!NOTE]
> AetherFlow v3.2.5 is built around a compiled single-binary **Go** control plane (`aetherflow-api`), an embedded **Next.js 16 (Obsidian V2)** static frontend, a privileged UNIX socket runner (`aetherflow-runner`), and native **systemd** service orchestration.

---

## Architectural Foundation

AetherFlow is engineered for bare-metal performance and strict privilege separation:

- **Single-Binary Control Plane**: The compiled **Go (Gin)** backend embeds the **Next.js (Obsidian V2)** static export directly (`CGO_ENABLED=0`), eliminating separate Node.js runtime daemons.
- **Zero-Sudo Socket Boundary**: Privileged root operations (`systemctl`, Marketplace installers, atomic upgrades) are isolated behind `/run/aetherflow/runner.sock` (`aetherflow-runner.service`) with strict allowlists.
- **Real-Time Telemetry**: Frame-0 hardware and service telemetry delivered via full-duplex WebSockets ("Hyperspeed").

### Design Philosophy

AetherFlow is shaped by three core beliefs:
1. **Infrastructure tools should feel powerful, not fragile.**
2. **Operators deserve direct system visibility, not vague abstractions.**
3. **Automation is safest when it includes a human-in-the-loop approval gate.**

---

## Core Capabilities

### 1. Unified Dashboard
A high-fidelity "Mission Control" interface built on Next.js 16. It features:
- **Immersive Mode**: A density-aware UI that scales based on visual priority.
- **Live Metrics**: Real-time hardware performance tracking (CPU, RAM, Disk, Network).
- **App Topology**: A visual map of how your services interrelate.

### 2. FlowAI Assistant
A localized infrastructure management assistant integrated directly into the control plane.
- **Support Mode**: Diagnoses issues by analyzing system logs and real-time metrics.
- **Assistant Mode**: Proposes maintenance workflows and complex system actions.
- **Action Approval Gate**: A security layer that queues destructive AI proposals (restarts, deletions, config changes) for administrator approval.

### 3. AetherMarketplace
A managed ecosystem of 69 installable applications (e.g., Plex, Jellyfin, qBittorrent, Qui, Autobrr).
- **One-Click Deploy**: Reliable, idempotent installation scripts.
- **Real-Time Progress**: Visual circular progress tracking for active deployments.
- **Service Orchestration**: Automatically creates systemd units for every installed application.

---

## Security First

AetherFlow v3.1.x introduces hardened security protocols for production environments:
- **TOTP 2FA**: Mandatory two-factor authentication for local administrator accounts.
- **JWT Sessions**: Secure, stateless authentication using `aetherflow_session` cookies.
- **AES-256 Encryption**: All sensitive API keys and secrets are encrypted at rest in the SQLite database using a master key defined in your environment.
- **CSRF Protection**: Native protection for all state-changing API requests.

---

## Who is AetherFlow for?

AetherFlow is built for operators who value precision and control over their infrastructure:
- **Home Server Enthusiasts** seeking a premium, Vercel-like experience for their local hardware.
- **Seedbox Users** who need high-concurrency performance and reliable service management.
- **DevOps Professionals** who want a fast, scriptable control plane for VPS fleets.

> [!TIP]
> The core idea is not to hide infrastructure. It is to make infrastructure easier to understand, operate, and trust. For a guided setup path, see the [Quickstart Guide](./quickstart.md).
