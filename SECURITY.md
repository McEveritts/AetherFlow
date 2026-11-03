# Security Policy

This document outlines the security policy, supported release channels, architecture boundaries, and vulnerability disclosure process for **AetherFlow** ([`McEveritts/AetherFlow`](https://github.com/McEveritts/AetherFlow)).

---

## Supported Versions & Release Channels

AetherFlow is maintained as a single unified open-source platform with active release tracks managed by the built-in Rust Release Engine (`af-release` / `aetherflow-self-update.service`) and [`deploy/release-manager.sh`](./deploy/release-manager.sh):

| Version / Track | Branch / Source | Supported | Notes |
| :--- | :--- | :---: | :--- |
| **`4.0.x` (`stable`)** | `master` / GitHub Releases | ✅ | Production Rust control plane track with SHA-256 verified artifacts, WAL-safe snapshots, and atomic rollback |
| **`4.0.x` (`nightly`)** | `nightly` / Pre-Releases | ✅ | Rolling pre-release channel (`v4.0.0-nightly.<run>.<attempt>`) for early validation |
| **`4.0.x` (`experimental`)** | `experimental` / Pre-Releases | ✅ | Feature validation branch and manual pre-release track |
| **`3.2.x`** | Historical Go Tags | ⚠️ | Security fixes land in `4.0.x`; seamless in-place upgrade to v4.0.0 supported |
| **`< 3.2.0`** | Legacy | ❌ | Unsupported legacy architecture; upgrade required |

---

## Security Architecture & In-Scope Components

When evaluating or reporting a security issue, the following components and trust boundaries are in scope (see [`docs/security.md`](./docs/security.md) and [`docs/threat_model.md`](./docs/threat_model.md) for full details):

1. **Unprivileged Control Plane (`aetherflow-api.service` / `af-api`)**:
   - Single-binary **Rust (`Axum` + `Tokio`)** API and embedded **Next.js 16 (Obsidian V2)** SPA running as unprivileged user `aetherflow` (`ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `RestrictSUIDSGID=yes`, `MemoryMax=512M`).
   - Binds to `127.0.0.1:8080` behind the Apache2 reverse proxy and Subdomain Gateway.
2. **Privileged Runner Boundary (`aetherflow-runner.service` / `af-runner`)**:
   - Root helper daemon (`/opt/AetherFlow/current/aetherflow-api runner`) listening exclusively on `/run/aetherflow/runner.sock` (`0660 root:aetherflow`).
   - Enforces strict regex, enum, and `lstat` ancestor-symlink allowlists for `systemctl` unit lifecycle calls, Marketplace package installations (15 declarative Rust recipes + locked Bash installers), WireGuard/Tailscale control, quota changes, and isolated `aetherflow-self-update.service` deployments.
3. **Scoped Tenant File Manager (`af-files` / Native McBrowser)**:
   - Capability-scoped per-user storage (`/var/lib/aetherflow/mcbrowser`, mode `0700`) with strict symlink/traversal prevention, ETag conflict detection, bounded resumable uploads, and admin-only host path picker enforcement (`/api/v1/auth/fs`).
4. **Authentication, Sessions & Perimeter SSO**:
   - TOTP 2FA with hashed recovery codes, 15-minute HS256 JWT access tokens backed by SQLite `revoked_tokens` and `active_sessions` verification, CSRF token/origin enforcement on state-mutating routes, and ` ALLOWED_HOSTS` validation.
   - Streaming Subdomain Gateway and `/api/v1/public/auth/verify` strip untrusted client identity headers before injecting verified `X-Aetherflow-User` headers.
5. **Data & Secret Isolation (`af-db` & `af-host`)**:
   - Bundled SQLite WAL database stored in `/var/lib/aetherflow/aetherflow.sqlite` (`0700` directory, `0600` file) and environment secrets in `/etc/aetherflow/aetherflow.env` (`0600`).
   - All AI provider API keys, OIDC credentials, and webhook secrets are encrypted at rest with **AES-256-GCM** (`enc:v1:` envelope using `AES_MASTER_KEY`).
6. **Human-Gated FlowAI**:
   - AI output is treated as untrusted; any state-mutating remediation proposed by FlowAI is queued in `pending_actions` (Action Approval Inbox) and requires explicit administrator authorization before execution.

---

## Reporting a Vulnerability

**Do not open public GitHub issues or pull requests for suspected security vulnerabilities.**

Please report vulnerabilities privately through **[GitHub Security Advisories (Private Vulnerability Reporting)](https://github.com/McEveritts/AetherFlow/security/advisories/new)** on this repository.

### What to Include in Your Report

To help us triage and reproduce the issue quickly, please include:

- **Affected Component**: Rust control plane crate (`backend-rs/crates/af-*`), privileged runner (`af-runner`), McBrowser (`af-files`), frontend (`frontend/`), Apache2 Subdomain Gateway, or a specific Marketplace installer (`packages/`).
- **Version & Environment**: AetherFlow version/commit (e.g., `v4.0.0`), release channel (`stable`, `nightly`, or `experimental`), and host OS (`Debian 12/13` or `Ubuntu 22.04/24.04`).
- **Reproduction Steps**: Clear, step-by-step instructions or a minimal proof-of-concept request/payload demonstrating the vulnerability.
- **Security Impact**: What security boundary is crossed (e.g., authentication bypass, IDOR, privilege escalation across `runner.sock`, path/symlink traversal, command/SQL injection, SSRF, or secret exposure) and the relevant CWE if known.

### Disclosure & Remediation Process

1. **Acknowledgment**: Reports submitted via GitHub Security Advisories are reviewed promptly.
2. **Validation & Patching**: Confirmed vulnerabilities are patched on `master` / `nightly`, verified against CI security gates (`gitleaks`, `cargo test --workspace`, `cargo clippy`, and regression suites), and published in the next release with `SHA256SUMS` and build provenance attestations.
3. **Coordinated Disclosure**: Once a fix is released, the advisory is published with credit to the reporter (unless anonymity is requested).

---

## Preferred Languages

We prefer all security communications to be in English.
