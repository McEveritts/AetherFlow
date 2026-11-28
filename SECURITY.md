# Security Policy

This document outlines the security policy, supported release channels, architecture boundaries, and vulnerability disclosure process for **AetherFlow** ([`McEveritts/AetherFlow`](https://github.com/McEveritts/AetherFlow)).

---

## Supported Versions & Release Channels

AetherFlow release tracks are managed by the built-in Rust Release Engine (`af-release`, launched via dynamic transient systemd units `aetherflow-self-update-<command>-<channel>-<8hex>.service`) and [`deploy/release-manager.sh`](./deploy/release-manager.sh):

| Version / Track | Branch / Source | Supported | Notes |
| :--- | :--- | :---: | :--- |
| **`4.0.x` (`stable`)** | `master` / GitHub Releases | ✅ | Production Rust control plane track (`v4.0.1`) with SHA-256 + Sigstore/SLSA v1 verified artifacts, WAL-safe snapshots, atomic helper sync, and automatic rollback |
| **`4.0.x` (`nightly`)** | `nightly` / Pre-Releases | ✅ | Rolling pre-release channel (`v4.0.1-nightly.<run>.<attempt>`) for early validation (retired `experimental` aliases to `nightly`) |
| **`3.2.x`** | Historical Go Tags | ⚠️ | Security fixes land in `4.0.x`; see [`docs/upgrading.md`](./docs/upgrading.md) for the v3.2.x to v4.0.x upgrade procedure |
| **`< 3.2.0`** | Legacy | ❌ | Unsupported legacy architecture; upgrade required |

---

## Security Architecture & In-Scope Components

When evaluating or reporting a security issue, the following components and trust boundaries are in scope (see [`docs/security.md`](./docs/security.md) and [`docs/threat_model.md`](./docs/threat_model.md) for full details):

1. **Unprivileged Control Plane (`aetherflow-api.service` / `af-api`)**:
   - **Rust (`Axum` + `Tokio`)** API serving the external **Leptos Rust WebAssembly (`frontend-rs`)** SPA from `web/dist` (`STATIC_DIR`) as unprivileged user `aetherflow` (`ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `RestrictSUIDSGID=yes`, `UMask=0027`, `DevicePolicy=closed`).
   - Bare `aetherflow-api` defaults to `0.0.0.0:8080`; `AetherFlow-Setup` configures `BIND_ADDR=127.0.0.1` and `PORT=8080` behind the Apache2 reverse proxy and Subdomain Gateway.
2. **Privileged Runner Boundary (`aetherflow-runner.service` / `af-runner`)**:
   - Root helper daemon (`/opt/AetherFlow/current/aetherflow-api runner`) listening exclusively on `/run/aetherflow/runner.sock` (`0660 root:aetherflow`) with `SO_PEERCRED` and `/proc/<pid>/exe` caller checks and descriptor-confined `confined_fs` config reads.
   - Supervises child processes in tracked process groups (`af-release::process_group`, `20 s` shutdown drain `< 30 s TimeoutStopSec`, stdin credential streaming for Dispatcharr) and enforces strict regex, enum, and `lstat` ancestor-symlink allowlists for `systemctl` unit lifecycle calls, Marketplace package operations (9 opt-in declarative Rust recipes gated behind `AETHERFLOW_ENABLE_RUST_PACKAGES=1`, defaulting to locked Bash installers), WireGuard/Tailscale control, Peer Clustering (`afpeer0` WireGuard, NFSv4.2 exports/mounts, and `af-transcode-worker.service` provisioning), quota changes, and isolated `aetherflow-self-update-<command>-<channel>-<8hex>.service` deployments (preferring immutable `env::current_exe().parent()` helpers ahead of `/opt/AetherFlow/current`).
3. **Managed Plugin OS Isolation (`af-runner` + Transient `DynamicUser=yes` Units)**:
   - Managed plugin backends and `lifecycle_hooks.on_stop` hooks are launched exclusively by `af-runner` inside hardened transient `aetherflow-plugin-<id>.service` units (`DynamicUser=yes`, empty `SupplementaryGroups=`, `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `InaccessiblePaths=` masking control-plane state and `/run/aetherflow-transcode*`, read-only `/run/aetherflow-plugin-{app,token}` mounts), verifying unified cgroup v2 and `systemd >= 249` before start and failing closed with HTTP `503` (`PLUGIN_ISOLATION_UNAVAILABLE`) when isolation is unavailable.
   - **Systemd Network Enforcement & Loopback Boundary**: Managed units enforce `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `SocketBindDeny=any`, `SocketBindAllow=ipv4:tcp:<allocated_port>`, `IPAddressDeny=any`, and `IPAddressAllow=localhost` (blocking outbound LAN/internet egress and unauthorized binds). `/metrics` requires `METRICS_BEARER_TOKEN` or an active admin session even on loopback (unless `METRICS_PUBLIC=1`), and loopback `rutorrent` requires `/etc/aetherflow/rutorrent-proxy-token`; however, because `IPAddressAllow=localhost` filters by IP without `PrivateNetwork=yes`, managed plugins can still initiate TCP connections to sibling loopback-bound Marketplace apps on `127.0.0.1:<port>`.
4. **Peer Clustering & Distributed Transcoding (`af-api::peers`, `af-runner`, `af-transcode`)**:
   - Public pairing bootstrap (`POST /api/v1/peer-pairing/request`) enforces 10-minute single-use pairing windows, 6-digit verification codes, a 4 KiB body cap, 5 req/min/IP rate limiting, OS CA TLS validation, and DNS-pinned SSRF filtering (`AF_PEER_ALLOW_PRIVATE_PAIRING_URLS=false` by default).
   - Inter-server API traffic runs strictly over the dedicated `afpeer0` WireGuard interface (`SO_BINDTODEVICE`, `<tunnel_ip>:9443`) using distinct link/grant bearer tokens (`0640 root:aetherflow` under `/etc/aetherflow/peers/tokens/`, while `afpeer0.key` and temporary `pending/` issuer tokens remain `0600` root-only), fail-closed 8-area grants starting at `None`, non-grantable local-only routes (`PEER_SCOPE_DENIED`), and sub-second revocation teardown (`<< 1 s`, `SIGKILL` on active remote transcode jobs).
   - Peer NFSv4.2 binds exclusively to `afpeer0`, and `af-transcode-worker.service` runs hardened as `User=jellyfin` (`SO_PEERCRED` caller UID verification via `AF_TRANSCODE_ALLOWED_PEER_UIDS`, `PrivateNetwork=yes`, `RestrictAddressFamilies=AF_UNIX`, `ProtectSystem=strict`, `DevicePolicy=closed`) reading only secret-free `/etc/aetherflow/transcode.env` (`0640 root:jellyfin`, never `/etc/aetherflow/aetherflow.env`). See [`docs/peer-clustering.md`](./docs/peer-clustering.md).
5. **Scoped Tenant File Manager (`af-files` & `af-api::mcbrowser` / Native McBrowser)**:
   - Capability-scoped per-user storage (`/var/lib/aetherflow/mcbrowser`, mode `0700`) rejecting traversal, NULs, backslashes, and symlinked mutation parents (opt-in internal symlink reads use Linux `openat2` confinement + target identity verification, directory walks enforce `MAX_PATH_COMPONENTS (64)` depth caps with FD-free BFS path queuing, and recursive account cleanup enforces `RESOLVE_NO_XDEV` / `st_dev` mount-boundary guards via `remove_tree_with_outcome`), with ETag conflict detection, bounded resumable uploads, and admin-only host path picker enforcement (`/api/v1/auth/fs`).
6. **Authentication, Sessions & Perimeter SSO**:
   - Optional TOTP 2FA with `bcrypt`-hashed recovery codes, `>= 32`-byte trimmed non-control `JWT_SECRET` enforcement, 15-minute HS256 JWT access tokens verified uniformly via `verify_active_session_on_conn` against SQLite `revoked_tokens`, unexpired `active_sessions`, and `sessions_revoked_after` across all human-session HTTP, proxy, app-launch, `/metrics`, optional marketplace, WebSocket, and OIDC `/authorize` surfaces (`/refresh` fails closed on deleted `active_sessions` rows while retaining a 10-second strict-fingerprint rotation grace window gated on a live `leaf_jti` row, with `SecretString` volatile zeroization, `4096`-entry grace/successor caps, and 60-second sweeps), double-submit CSRF validation (`X-Requested-With: XMLHttpRequest` on cookie `/refresh`; outer `auth_rate_limit_middleware` sub-router layer ahead of `auth_middleware`/`csrf_middleware` on both `/api/v1/auth/refresh` and `/api/auth/refresh`; `CSRF_DISABLED` and `AF_DISABLE_RATELIMIT` ignored in `production`/`release`), and `host_validation_middleware` layered outside `security_headers_middleware` (trusting only canonical loopback IPs implicitly and rejecting unlisted IPv4/IPv6 `Host`/`X-Forwarded-Host` with `400 INVALID_HOST` before OIDC or SPA CSP runs).
   - `/api/v1/public/auth/verify` returns `X-Aetherflow-User` and `Remote-User` response headers for forward-auth subrequests (the reverse proxy must strip untrusted client identity headers before forwarding downstream), while the streaming Subdomain Gateway strips spoofable client identity headers and injects `X-Aetherflow-User` only (plus `X-Aetherflow-Rutorrent-Token` for local `rutorrent`).
   - **Subdomain Gateway & `.aether.local` Authentication**:
     - *Live-Admin Gateway Auth*: All 10 gateway-protected apps (including `rutorrent`) enforce active admin sessions (including `__Host-aetherflow_app` on HTTPS and `aetherflow_local_app` on HTTP `*.aether.local` for TOTP admins) or live SQLite admin Basic Auth (`totp_enabled == 0`, no `.master.creds` fallback). Local `127.0.0.1:8087` `rutorrent` requires `Require local` + `/etc/aetherflow/rutorrent-proxy-token.conf`, reserving static Apache `htpasswd` solely for legacy custom blocks, non-loopback `BIND_ADDR`, or `AF_APACHE_LISTEN_ALL=1`.
     - *Authenticated `.aether.local` by Default*: Internal `<app>.aether.local` routing permits authenticated clients from loopback, RFC 1918 LAN, link-local, IPv6 ULA, and Tailscale (`100.64.0.0/10`), requiring administrator authentication on all 10 protected apps by default. Opt-in `AF_ALLOW_UNAUTH_LOCAL_LAN=1` (default `false`) bypasses auth strictly for RFC 1918, link-local, and IPv6 ULA peers — never `100.64.0.0/10` or loopback.
7. **Data & Secret Isolation (`af-db`, `af-models` & `af-host`)**:
   - Bundled SQLite WAL database stored in `/var/lib/aetherflow/aetherflow.sqlite` (`0700` directory, `0600`/`0640` file under `UMask=0027`, migrated/restored via same-filesystem root-`0700` staging with FD `fchown`/`fchmod` and `renameat`) and environment secrets in `/etc/aetherflow/aetherflow.env` (`0750 root:aetherflow` directory; read as `root` by systemd PID 1 via `EnvironmentFile=`, written as `0640 root:aetherflow` by `AetherFlow-Setup`, `af-release`, and `deploy/release-manager.sh`, and tightened to `0600` by `af provision`).
   - AI provider keys (`settings`), `users.totp_secret`, `streaming_servers.api_key`, `notification_channels.config`, `/var/lib/aetherflow/.master.creds`, and SQLite `system_config.master_credentials` are encrypted at rest with **AES-256-GCM** (`enc:v1:<base64(nonce || ciphertext)>` keyed by `AES_MASTER_KEY`), while ephemeral secrets in memory use full-capacity volatile zeroization (`af_models::secret_zeroize::{SecretString, SecretBytes}`). OIDC client secrets are SHA-256 hashed (`oidc_clients.client_secret_hash`), the OIDC RS256 signing key is stored in `/var/lib/aetherflow/oidc_rsa.pem` (`0600`), and `GOOGLE_CLIENT_SECRET` is environment-only.
8. **Human-Gated FlowAI**:
   - AI output is treated as untrusted; state-mutating service actions proposed by FlowAI are queued in `pending_actions` (Action Approval Inbox) and require explicit administrator authorization before execution.

---

## Reporting a Vulnerability

**Do not open public GitHub issues or pull requests for suspected security vulnerabilities.**

Please report vulnerabilities privately through **[GitHub Security Advisories (Private Vulnerability Reporting)](https://github.com/McEveritts/AetherFlow/security/advisories/new)** on this repository.

### What to Include in Your Report

To help us triage and reproduce the issue quickly, please include:

- **Affected Component**: Rust control plane crate (`backend-rs/crates/af-*`), privileged runner (`af-runner`), McBrowser (`af-files` / `af-api::mcbrowser`), WASM frontend (`frontend-rs/crates/af-web-*`), Apache2 Subdomain Gateway, or a specific Marketplace installer (`packages/`).
- **Version & Environment**: AetherFlow version/commit (e.g., `v4.0.1`), release channel (`stable` or `nightly`), and host OS (`Debian 12/13` or `Ubuntu 22.04/24.04`).
- **Reproduction Steps**: Clear, step-by-step instructions or a minimal proof-of-concept request/payload demonstrating the vulnerability.
- **Security Impact**: What security boundary is crossed (e.g., authentication bypass, IDOR, privilege escalation across `runner.sock`, path/symlink traversal, command/SQL injection, SSRF, or secret exposure) and the relevant CWE if known.

### Disclosure & Remediation Process

1. **Acknowledgment**: Reports submitted via GitHub Security Advisories are triaged privately by repository maintainers.
2. **Validation & Patching**: Confirmed vulnerabilities are patched on `master` / `nightly`, verified against CI security gates (`gitleaks`, `cargo test --workspace`, `cargo clippy`, `cargo audit`/`cargo deny`, and regression suites), and published in the next release with `SHA256SUMS` and Sigstore/SLSA v1 build provenance attestations.
3. **Coordinated Disclosure**: Once a fix is released, the advisory is published with credit to the reporter (unless anonymity is requested).

---

## Preferred Languages

We prefer all security communications to be in English.
