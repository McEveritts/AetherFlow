# 🌌 AetherFlow

AetherFlow is a modern, enterprise-grade bare-metal seedbox orchestration platform. Forked and heavily diverged from QuickBox CE, AetherFlow has been completely rebuilt from the ground up to provide unparalleled performance, security, and AI-driven automation for managing media-server applications.

Gone is the legacy PHP dashboard. Welcome to the future: a high-performance Go (Gin) backend API paired with a stunning Next.js (React) frontend featuring a fully responsive, animated Glassmorphism design system.

## ✨ What's New in v3.1.0 (Gold Release)

The v3.1.0 release marks a monumental shift in AetherFlow's capabilities, transforming it from a single-node dashboard into a scalable, intelligent orchestration platform:

*   **gRPC Multi-Node Clustering**: Manage multiple "Worker" seedboxes securely from a single "Master" dashboard using mTLS gRPC streams.
*   **OIDC Identity Provider**: AetherFlow now acts as your primary SSO (Single Sign-On) provider for apps like Plex, Jellyfin, and Nextcloud.
*   **Zero-Trust Network Access (ZTNA)**: Natively manage WireGuard and Tailscale routing directly from the UI.
*   **Strict Systemd Sandboxing**: Advanced bare-metal isolation (`ProtectSystem`, `PrivateTmp`, `NoNewPrivileges`) ensures apps never collide. No Docker overhead—just pure, sandboxed bare-metal performance.
*   **Enterprise Billing Webhooks**: Built-in listener support and user-level filesystem quotas designed for WHMCS and Blesta reseller integrations.
*   **AI-Powered Automation**: Deep integration with Google Gemini for intelligent bandwidth allocation, predictive resource scaling, smart backup scheduling, and an AI Support Chatbot.

## 🏗️ Architecture

AetherFlow utilizes a modern three-tier architecture to ensure maximum stability and responsiveness:

*   **Frontend (`/frontend`)**: A Next.js Single Page Application (SPA) utilizing Zustand for state management, SWR for caching, Framer Motion for fluid transitions, and `@tanstack/react-table` for highly performant DataGrids.
*   **Backend API (`/backend`)**: A robust Go binary utilizing the Gin framework. Handles JWT/OIDC authentication, gRPC cluster management, WebSockets, rate limiting, and SQLite database pooling optimized for high-concurrency environments.
*   **System Scripts (`/packages`, `/setup`)**: Idempotent, ShellCheck-compliant Bash scripts that handle the actual package installation, service templating, system healing (`af-heal`), and backup generation.

## 🚀 Key Features

### 💎 Glassmorphism UI
Experience a visually stunning, translucent dashboard. Features include dynamic data visualizations via Recharts, global Cmd+K command palette navigation, interactive app topology maps, and full Progressive Web App (PWA) support.

### 🛡️ Enterprise Security
AetherFlow ships with secure defaults: `SameSite=Lax` cookies, strict CSRF protection, WebSocket origin validation, comprehensive MIME-type upload blocking, and granular Rate Limiting.

### 🧠 Intelligent AI Core
Leverage the power of local or cloud LLMs to assist in server management:
*   **Smart Backups**: AI calculates your lowest I/O windows to schedule zero-impact backups.
*   **Predictive Scaling**: Analyzes 30-day resource trends to warn you of impending CPU/Disk bottlenecks.
*   **Media Metadata Enrichment**: Automatically scans, translates, and organizes unstructured media directories.

### 📦 Self-Healing Bare-Metal Packages
Say goodbye to orphaned lockfiles and crashed torrent clients. AetherFlow's `af-heal` daemon actively monitors system health, auto-clears `/tmp` bottlenecks, and safely restarts hung processes automatically.

## 🛠️ Getting Started

### Prerequisites
*   OS: Ubuntu 20.04/22.04 LTS or Debian 11/12
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
*   **Backend**: `cd backend && go test ./...`
*   **Frontend**: `cd frontend && npm run test:e2e` (Includes Playwright visual regression testing).

## 📄 License

AetherFlow is an open-source project distributed under the MIT License.
