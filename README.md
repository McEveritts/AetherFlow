# 🌌 AetherFlow

> Orchestrating the Next Era of Bare-Metal Infrastructure.

AetherFlow is a modern, enterprise-grade bare-metal seedbox orchestration platform. Forked and heavily diverged from QuickBox CE, AetherFlow has been completely rebuilt from the ground up to provide unparalleled performance, security, and AI-driven automation for managing media-server applications.

Gone is the legacy PHP dashboard. Welcome to the future: a high-performance orchestration core and dashboard. Built entirely in pure Go and strictly-typed TypeScript, it rejects legacy bloat in favor of mathematical precision and AI-native operational workflows.

## 🏗️ The Architecture: An Executable Built for the Edge

Uncompromising technology choices designed for stability. No Rust rewrites. No legacy PHP.

*   **The Control Plane (Go)**: A robust, highly concurrent Go API. Designed for lightweight execution, connection stability, and pure backend operational control.
*   **The Visualization Layer (TypeScript)**: A premium Next.js Single Page Application utilizing standard-setting frontend tooling: `Zustand` for state tracking, `SWR` for real-time hydration, and `Framer Motion` for spatial transitions. Unified by our shared vertically integrated `@aetherflow/ui` foundation.

## ✨ Core Directives

We did not adopt complexity for the sake of it. AetherFlow is built on a rigid philosophy: infrastructure software should be fast, typed, and verifiable.

1.  **Bare-Metal First**: We manage bare-metal infrastructure without imposing heavy virtualization runtimes or orchestrator bloat. Direct, efficient execution.
2.  **Strict Typing**: From our compiled Go interfaces to our Next.js frontend state, strict typing is enforced everywhere. No silent runtime anomalies.
3.  **AI-Native, Human-Gated**: AI is not a side feature; it acts as the core diagnostic engine. Models *propose* mitigations; humans approve them.

## 🧠 Intelligence Bounded by Authorization

AetherFlow integrates AI directly into the operational feedback loop, shifting it from a chatbot to an active infrastructure agent.

*   **Deep Diagnostics**: AI assesses logs and telemetry to identify failure patterns.
*   **The Approval Inbox**: AI cannot arbitrarily mutate state. Every automated remediation is piped to a global Approval Inbox for explicit, cryptographically verifiable operator authorization.

## 🚀 Status & Momentum: Maturing for Production

AetherFlow is actively hardening its core operational surfaces.

*   **Repo Truth Mandate**: If it is not running in the compiler and passing CI, it does not exist.
*   **Unified Tooling**: Focusing on reliable integration between the backend control plane and the strictly-typed UI.
*   **Current Focus**: Finalizing the human-in-the-loop workflows for AI infrastructure management.

---

## 🛠️ Getting Started

### Prerequisites
*   OS: Ubuntu 20.04/22.04 LTS, Debian 11/12, or Kali Linux (rolling)
*   Kali Linux is supported as a Debian derivative — the installer auto-detects it and follows the Debian codepath.
*   *A clean, fresh OS installation is highly recommended.*

### Installation
Run the newly parallelized bootstrap installer to automatically configure the environment, compile the Go backend, and serve the Next.js UI:

```bash
apt-get update && apt-get -y upgrade
apt-get -y install git
git clone https://github.com/McEveritts/AetherFlow.git /opt/AetherFlow
cd /opt/AetherFlow/setup
sudo bash AetherFlow-Setup
```

Follow the interactive prompts to set your primary Admin credentials, configure your domain, and start the Onboarding Wizard in your browser.

## 📚 Documentation & Development

AetherFlow is built to be extensible. Whether you are writing a custom plugin or integrating an external billing platform, check out our core documentation:

*   [API Documentation (v1)](/docs/API.md) - Full OpenAPI/Swagger specs for the Go backend.
*   [Codebase Brain](/docs/CODEBASE_BRAIN.md) - Architectural overview and security context.
*   [Universal Plugin SDK](/plugins/README.md) - Boilerplate templates for Next.js/Go plugin development.

### Testing
We maintain a strict CI/CD pipeline.
*   **Backend**: `cd backend && go test ./... -count=1`
*   **Frontend**: `cd frontend && npm run test:e2e` (Includes Playwright visual regression testing).

## 📄 License

AetherFlow is an open-source project distributed under the MIT License.
