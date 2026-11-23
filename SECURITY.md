# Security Policy

This document outlines the security policy, supported release channels, architecture boundaries, and vulnerability disclosure process for **AetherFlow** ([`McEveritts/AetherFlow`](https://github.com/McEveritts/AetherFlow)).

---

## Supported Versions & Release Channels

AetherFlow release tracks are managed by the built-in Rust Release Engine (`af-release`, launched via dynamic transient systemd units `aetherflow-self-update-<command>-<channel>-<8hex>.service`) and [`deploy/release-manager.sh`](./deploy/release-manager.sh):

| Version / Track | Branch / Source | Supported | Notes |
| :--- | :--- | :---: | :--- |
| **`4.0.x` (`stable`)** | `master` / GitHub Releases | ✅ | Production Rust control plane track with SHA-256 + Sigstore/SLSA v1 verified artifacts, WAL-safe snapshots, and atomic rollback |
| **`4.0.x` (`nightly`)** | `nightly` / Pre-Releases | ✅ | Rolling pre-release channel (`v4.0.0-nightly.<run>.<attempt>`) for early validation (retired `experimental` aliases to `nightly`) |
| **`3.2.x`** | Historical Go Tags | ⚠️ | Security fixes land in `4.0.x`; see [`docs/upgrading.md`](./docs/upgrading.md) for the v3.2.x to v4.0.0 upgrade procedure |
| **`< 3.2.0`** | Legacy | ❌ | Unsupported legacy architecture; upgrade required |

---

## Security Architecture & In-Scope Components

When evaluating or reporting a security issue, the following components and trust boundaries are in scope (see [`docs/security.md`](./docs/security.md) and [`docs/threat_model.md`](./docs/threat_model.md) for full details):

1. **Unprivileged Control Plane (`aetherflow-api.service` / `af-api`)**:
   - **Rust (`Axum` + `Tokio`)** API serving the external **Leptos Rust WebAssembly (`frontend-rs`)** SPA from `web/dist` (`STATIC_DIR`) as unprivileged user `aetherflow` (`ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `RestrictSUIDSGID=yes`, `UMask=0027`, `DevicePolicy=closed`).
   - Bare `aetherflow-api` defaults to `0.0.0.0:8080`; `AetherFlow-Setup` configures `BIND_ADDR=127.0.0.1` and `PORT=8080` behind the Apache2 reverse proxy and Subdomain Gateway.
2. **Privileged Runner Boundary (`aetherflow-runner.service` / `af-runner`)**:
   - Root helper daemon (`/opt/AetherFlow/current/aetherflow-api runner`) listening exclusively on `/run/aetherflow/runner.sock` (`0660 root:aetherflow`) with `SO_PEERCRED` and `/proc/<pid>/exe` caller checks.
   - Enforces strict regex, enum, and `lstat` ancestor-symlink allowlists for `systemctl` unit lifecycle calls, Marketplace package operations (9 opt-in declarative Rust recipes gated behind `AETHERFLOW_ENABLE_RUST_PACKAGES=1`, defaulting to locked Bash installers), WireGuard/Tailscale control, quota changes, and isolated `aetherflow-self-update-<command>-<channel>-<8hex>.service` deployments.
3. **Managed Plugin OS Isolation (`af-runner` + Transient `DynamicUser=yes` Units)**:
   - Managed plugin backends and `lifecycle_hooks.on_stop` hooks are launched exclusively by `af-runner` inside hardened transient `aetherflow-plugin-<id>.service` units (`DynamicUser=yes`, empty `SupplementaryGroups=`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `InaccessiblePaths=` masking control-plane state, read-only `/run/aetherflow-plugin-{app,token}` mounts), failing closed with HTTP `503` (`PLUGIN_ISOLATION_UNAVAILABLE`) when isolation is unavailable.
   - **Network Boundary Caveat**: Managed units set `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` without `PrivateNetwork=yes`, `SocketBindDeny`/`SocketBindAllow`, or `IPAddressDeny` (`PLUGIN_BIND_ADDR=127.0.0.1` and `PLUGIN_PORT` are advisory; only `af-api`'s reverse proxy enforces targeting `127.0.0.1:<allocated_port>`). Plugins share the host network namespace and can reach host loopback services (including loopback-unauthenticated `/metrics` and loopback-bound gateway-protected Marketplace apps).
4. **Scoped Tenant File Manager (`af-files` & `af-api::mcbrowser` / Native McBrowser)**:
   - Capability-scoped per-user storage (`/var/lib/aetherflow/mcbrowser`, mode `0700`) rejecting traversal, NULs, backslashes, and symlinked mutation parents (opt-in internal symlink reads use Linux `openat2` confinement + target identity verification), with ETag conflict detection, bounded resumable uploads, and admin-only host path picker enforcement (`/api/v1/auth/fs`).
5. **Authentication, Sessions & Perimeter SSO**:
   - Optional TOTP 2FA with `bcrypt`-hashed recovery codes, 15-minute HS256 JWT access tokens verified against SQLite `revoked_tokens` and `sessions_revoked_after` (`active_sessions` additionally checked on `/api/v1/public/auth/verify`, non-loopback `/metrics`, optional authenticated `GET /api/v1/public/marketplace`, and HTTPS `__Host-aetherflow_app` cookies), double-submit CSRF cookie/header validation on state-mutating cookie-authenticated routes (`X-Requested-With: XMLHttpRequest` on cookie-authenticated `/refresh`), and `ALLOWED_HOSTS` validation (note: `local_control_plane_host` unconditionally accepts any valid IPv4/IPv6 literal, so pin explicit `PUBLIC_URL` and `OIDC_ISSUER` in `/etc/aetherflow/aetherflow.env` and reject catch-all IP `Host` headers at Apache2 to prevent arbitrary IP reflection in OIDC discovery or SPA CSP `connect-src`).
   - `/api/v1/public/auth/verify` returns `X-Aetherflow-User` and `Remote-User` response headers for forward-auth subrequests (the reverse proxy must strip untrusted client identity headers before forwarding downstream), while the streaming Subdomain Gateway strips spoofable client identity headers and injects `X-Aetherflow-User` only.
   - **Known Subdomain Gateway & Apache External Auth Trust Boundaries**:
     - *Provisioning Master-Credential & Static `htpasswd` Basic Auth Persistence*: First-admin setup generates provisioning credentials persisted across `/var/lib/aetherflow/.master.creds` and SQLite `system_config.master_credentials` (with legacy fallback reads from `/opt/AetherFlow/backend/data/.master.creds` and `/install/.aetherflow.conf`). Subdomain Gateway Basic Auth checks these credentials before verifying `users.role == "admin"`, so deleting, demoting, or rotating the initial admin password does not revoke Basic Auth via the provisioning secret (and deleting the matching `users` row bypasses the TOTP check). Likewise, static Apache Basic Auth files (`/etc/apache2/AetherFlow/htpasswd` for managed external non-gateway vhosts including ruTorrent, and `/etc/apache2/AetherFlow/rutorrent.htpasswd` for ruTorrent's local vhost) do not auto-revoke when accounts change or enroll in TOTP. Rotate or remove credentials across all four Rust stores **and** both Apache `htpasswd` files during admin offboarding.
     - *Unauthenticated `.aether.local` Routing*: Requests carrying `Host: <app>.aether.local` disable Subdomain Gateway authentication and implicitly bypass `ALLOWED_HOSTS` and `external_access_enabled=0` whenever the client IP falls within loopback (`127.0.0.0/8`, `::1`), RFC1918 LAN, link-local (`169.254.0.0/16`, `fe80::/10`), IPv6 ULA (`fc00::/7`), or **RFC 6598 CGNAT (`100.64.0.0/10`, covering Tailscale tailnet peers and ISP CGNAT ranges)**. Restrict host firewall and Tailscale ACLs accordingly.
6. **Data & Secret Isolation (`af-db` & `af-host`)**:
   - Bundled SQLite WAL database stored in `/var/lib/aetherflow/aetherflow.sqlite` (`0700` directory, `0600`/`0640` file under `UMask=0027`) and environment secrets in `/etc/aetherflow/aetherflow.env` (read as `root` by systemd PID 1 via `EnvironmentFile=`; `AetherFlow-Setup` creates `0640 root:aetherflow`, `af provision` enforces `0600`, and `af-release` legacy migration writes `0600` preserving source `uid:gid` or falling back to `aetherflow:aetherflow`).
   - AI provider keys (`settings`), `users.totp_secret`, `streaming_servers.api_key`, `notification_channels.config`, `/var/lib/aetherflow/.master.creds`, and SQLite `system_config.master_credentials` are encrypted at rest with **AES-256-GCM** (`enc:v1:<base64(nonce || ciphertext)>` keyed by `AES_MASTER_KEY`). OIDC client secrets are SHA-256 hashed (`oidc_clients.client_secret_hash`), the OIDC RS256 signing key is stored in `/var/lib/aetherflow/oidc_rsa.pem` (`0600`), and `GOOGLE_CLIENT_SECRET` is environment-only.
7. **Human-Gated FlowAI**:
   - AI output is treated as untrusted; state-mutating service actions proposed by FlowAI are queued in `pending_actions` (Action Approval Inbox) and require explicit administrator authorization before execution.

---

## Reporting a Vulnerability

**Do not open public GitHub issues or pull requests for suspected security vulnerabilities.**

Please report vulnerabilities privately through **[GitHub Security Advisories (Private Vulnerability Reporting)](https://github.com/McEveritts/AetherFlow/security/advisories/new)** on this repository.

### What to Include in Your Report

To help us triage and reproduce the issue quickly, please include:

- **Affected Component**: Rust control plane crate (`backend-rs/crates/af-*`), privileged runner (`af-runner`), McBrowser (`af-files` / `af-api::mcbrowser`), WASM frontend (`frontend-rs/crates/af-web-*`), Apache2 Subdomain Gateway, or a specific Marketplace installer (`packages/`).
- **Version & Environment**: AetherFlow version/commit (e.g., `v4.0.0`), release channel (`stable` or `nightly`), and host OS (`Debian 12/13` or `Ubuntu 22.04/24.04`).
- **Reproduction Steps**: Clear, step-by-step instructions or a minimal proof-of-concept request/payload demonstrating the vulnerability.
- **Security Impact**: What security boundary is crossed (e.g., authentication bypass, IDOR, privilege escalation across `runner.sock`, path/symlink traversal, command/SQL injection, SSRF, or secret exposure) and the relevant CWE if known.

### Disclosure & Remediation Process

1. **Acknowledgment**: Reports submitted via GitHub Security Advisories are triaged privately by repository maintainers.
2. **Validation & Patching**: Confirmed vulnerabilities are patched on `master` / `nightly`, verified against CI security gates (`gitleaks`, `cargo test --workspace`, `cargo clippy`, `cargo audit`/`cargo deny`, and regression suites), and published in the next release with `SHA256SUMS` and Sigstore/SLSA v1 build provenance attestations.
3. **Coordinated Disclosure**: Once a fix is released, the advisory is published with credit to the reporter (unless anonymity is requested).

---

## Preferred Languages

We prefer all security communications to be in English.
