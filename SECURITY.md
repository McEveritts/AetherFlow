# Security Policy

This document outlines the security policy, supported release channels, architecture boundaries, and vulnerability disclosure process for **AetherFlow** ([`McEveritts/AetherFlow`](https://github.com/McEveritts/AetherFlow)).

---

## Supported Versions & Release Channels

AetherFlow is maintained as a single unified open-source platform with two active release tracks managed by the built-in Updater and [`deploy/release-manager.sh`](./deploy/release-manager.sh):

| Version / Track | Branch / Source | Supported | Notes |
| :--- | :--- | :---: | :--- |
| **`3.2.x` (`stable`)** | `master` / GitHub Releases | ✅ | Production release track with SHA-256 verified artifacts and atomic rollback |
| **`3.2.x` (`nightly`)** | `nightly` / Pre-Releases | ✅ | Rolling pre-release channel for early validation |
| **`3.1.x`** | Historical Tags | ⚠️ | Security fixes land in `3.2.x`; upgrade recommended |
| **`< 3.1.0`** | Legacy | ❌ | Unsupported legacy architecture; upgrade required |

---

## Security Architecture & In-Scope Components

When evaluating or reporting a security issue, the following components and trust boundaries are in scope (see [`docs/security.md`](./docs/security.md) and [`docs/threat_model.md`](./docs/threat_model.md) for full details):

1. **Unprivileged Control Plane (`aetherflow-api.service`)**:
   - Single-binary Go (Gin) API and embedded Next.js (Obsidian V2) SPA running as unprivileged user `aetherflow` (`ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `RestrictSUIDSGID=yes`).
   - Binds to `127.0.0.1:8080` behind the Apache2 reverse proxy and Subdomain Gateway.
2. **Privileged Runner Boundary (`aetherflow-runner.service`)**:
   - Root helper daemon listening exclusively on `/run/aetherflow/runner.sock` (`0660 root:aetherflow`).
   - Enforces strict regex and enum allowlists for `systemctl` unit lifecycle calls, Marketplace package scripts, quota changes, and atomic `release-manager.sh` upgrades.
3. **Authentication, Sessions & Perimeter SSO**:
   - TOTP 2FA (`backend/api/totp.go`) with hashed recovery codes, 15-minute JWT access tokens backed by a Redis JTI revocation list, CSRF token enforcement on state-mutating routes, and `HostValidationMiddleware` (`ALLOWED_HOSTS`).
   - `AppSubdomainProxyMiddleware` and `/api/v1/public/auth/verify` strip untrusted client identity headers before injecting verified `X-Aetherflow-User` headers.
4. **Data & Secret Isolation**:
   - SQLite WAL database stored in `/var/lib/aetherflow/aetherflow.sqlite` (`0700`) and environment secrets in `/etc/aetherflow/aetherflow.env` (`0600`).
   - All AI provider API keys, OIDC credentials, and webhook secrets are encrypted at rest with **AES-256-GCM** (`AES_MASTER_KEY`).
5. **Human-Gated FlowAI**:
   - AI output is treated as untrusted; any state-mutating remediation proposed by FlowAI is queued in `pending_actions` (Action Approval Inbox) and requires explicit administrator authorization before execution.

---

## Reporting a Vulnerability

**Do not open public GitHub issues or pull requests for suspected security vulnerabilities.**

Please report vulnerabilities privately through **[GitHub Security Advisories (Private Vulnerability Reporting)](https://github.com/McEveritts/AetherFlow/security/advisories/new)** on this repository.

### What to Include in Your Report

To help us triage and reproduce the issue quickly, please include:

- **Affected Component**: Control plane API (`backend/`), privileged runner (`aetherflow-runner`), frontend (`frontend/`), Apache2 Subdomain Gateway, or a specific Marketplace installer (`packages/`).
- **Version & Environment**: AetherFlow version/commit (e.g., `v3.2.5`), release channel (`stable` or `nightly`), and host OS (`Debian 12/13` or `Ubuntu 22.04/24.04`).
- **Reproduction Steps**: Clear, step-by-step instructions or a minimal proof-of-concept request/payload demonstrating the vulnerability.
- **Security Impact**: What security boundary is crossed (e.g., authentication bypass, IDOR, privilege escalation across `runner.sock`, command/SQL injection, SSRF, or secret exposure) and the relevant CWE if known.

### Disclosure & Remediation Process

1. **Acknowledgment**: Reports submitted via GitHub Security Advisories are reviewed promptly.
2. **Validation & Patching**: Confirmed vulnerabilities are patched on `master` / `nightly`, verified against CI security gates (`gitleaks`, `govulncheck`, `gosec`, `staticcheck`, `go test -race`, and the 4-tier E2E suite), and published in the next patch release with `SHA256SUMS`.
3. **Coordinated Disclosure**: Once a fix is released, the advisory is published with credit to the reporter (unless anonymity is requested).

---

## Preferred Languages

We prefer all security communications to be in English.
