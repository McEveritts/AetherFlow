# About AetherFlow

AetherFlow is a modern control plane for self-hosted infrastructure.

It began as the next evolution of **QuickBox**, then grew into something broader: a unified **Mission Control** for cloud and local systems, specializing in **seedboxes**, **home servers**, and automation-heavy infrastructure workflows.

Rather than treating the server as a loose collection of scripts and panels, AetherFlow treats it as a managed platform: one place to operate services, observe the system, automate tasks, and safely delegate actions through an AI-assisted interface.

> [!NOTE]
> AetherFlow v3.1.6 reflects a major architectural modernization. The platform is moving away from legacy PHP patterns and toward a high-concurrency stack built around Go, Next.js, and systemd-native orchestration.

---

## Evolution: QuickBox to AetherFlow

QuickBox established the foundation for practical server bootstrapping. AetherFlow carries that lineage forward with a complete architectural reset:

- **Performance**: Moving from PHP and Apache/Nginx-PHP-FPM to a compiled **Go** backend and a **Next.js** frontend.
- **Orchestration**: Transitioning from ad-hoc process management (PM2) to native **systemd** service units.
- **State**: real-time metrics and service status delivered via high-frequency WebSockets ("Hyperspeed").

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
A managed ecosystem of 37+ installable applications (e.g., Plex, qBittorrent, Autobrr).
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
