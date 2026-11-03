export const heroData = {
  h1: "Orchestrating the Next Era of Bare-Metal Infrastructure.",
  subheadline: "AetherFlow v4.0.0 is a sovereign, single-binary control plane and Obsidian V2 dashboard. Compiled from an 11-crate Rust workspace (Axum + Tokio) with an embedded Next.js 16 SPA, it orchestrates 77 native Linux services, scoped McBrowser file management, and human-gated FlowAI operations directly against systemd.",
  primaryCta: {
    label: "View on GitHub",
    href: "https://github.com/McEveritts/AetherFlow"
  }
};

export const directives = {
  title: "Precision engineering. Zero container theater.",
  body: "We rejected fragile shell panels and heavy container overlays. AetherFlow is built on an uncompromising philosophy: infrastructure software should be compiled, memory-safe, and verifiable.",
  cards: [
    {
      title: "100% Bare-Metal & systemd",
      copy: "Manage 77 native Linux services under granular systemd cgroups and af-systemd-sandbox profiles with zero Docker daemon overhead or bridge latency."
    },
    {
      title: "11-Crate Rust Control Plane",
      copy: "From the Axum HTTP/WebSocket API and bundled SQLite WAL engine to NVML GPU FFI and the unified af CLI, strict memory and type safety are enforced everywhere."
    },
    {
      title: "AI-Native, Human-Gated",
      copy: "FlowAI acts as a multi-provider diagnostic engine across Gemini, Claude, OpenAI, and Ollama. Models propose remediations; administrators authorize them in the Approval Inbox."
    }
  ]
};

export const architectureData = {
  title: "A Single-Binary Executable Built for Sovereign Hosts",
  body: "Uncompromising systems engineering designed for bare-metal longevity. Zero production Node.js daemons. Zero Docker runtime dependencies.",
  columns: [
    {
      title: "The Control Plane (11-Crate Rust Workspace)",
      copy: "Built on Axum and Tokio, aetherflow-api runs unprivileged under ProtectSystem=strict while isolating root lifecycle, WireGuard/Tailscale, and declarative package operations behind the /run/aetherflow/runner.sock UNIX domain socket daemon."
    },
    {
      title: "The Obsidian V2 Interface & Native McBrowser",
      copy: "A Next.js 16 static export embedded directly into the Rust binary via rust-embed, featuring Frame-0 WebSocket telemetry, canonical streaming analytics, and Native McBrowser (af-files) for capability-scoped file management and resumable 64 GiB uploads."
    }
  ]
};

export const aiNativeLoopData = {
  title: "Intelligence bounded by cryptographic authorization.",
  body: "AetherFlow integrates FlowAI directly into the operational feedback loop, pairing real-time telemetry and McBrowser natural-language search with strict execution gates.",
  bullets: [
    {
      title: "Multi-Provider Telemetry Diagnostics",
      copy: "FlowAI inspects live CPU/GPU metrics, systemd journals, and storage health using AES-256-GCM encrypted provider credentials."
    },
    {
      title: "The Action Approval Inbox",
      copy: "AI cannot arbitrarily mutate host state. Every proposed service restart, lock cleanup, or quota change is serialized into pending_actions for explicit administrator approval."
    }
  ]
};

export const statusMomentumData = {
  title: "Engineered for Production Resilience",
  body: "AetherFlow v4.0.0 delivers end-to-end atomic lifecycle management across your entire server.",
  bullets: [
    {
      title: "Atomic Self-Updates & Rollbacks",
      copy: "Isolated aetherflow-self-update.service deployments verify SHA256SUMS, capture WAL-safe SQLite backups, check executable readiness, and automatically roll back on failure."
    },
    {
      title: "Automatic Subdomain TLS Ingress",
      copy: "Configure a baseDomain once to automatically provision <app>.<baseDomain> Apache2 routes, Let's Encrypt SANs via af-certbot-sync, and .aether.local split-horizon DNS."
    },
    {
      title: "Unified Admin CLI (af)",
      copy: "Operate packages, services, disk quotas, sandbox drop-ins, verified staged backup restores, and 14-step bare-metal provisioning from a single compiled CLI."
    }
  ]
};

export const ctaData = {
  title: "Command your infrastructure.",
  body: "Explore the 11-crate Rust architecture, browse the 77-app bare-metal catalog, and deploy AetherFlow v4.0.0.",
  button: {
    label: "View Repository",
    href: "https://github.com/McEveritts/AetherFlow"
  }
};
