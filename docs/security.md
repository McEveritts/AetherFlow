# Security Guide

AetherFlow v4.0.0 implements defense-in-depth across authentication, encryption at rest, capability-scoped file access, systemd namespace sandboxing, and CI/CD supply-chain verification.

## Authentication & Perimeter SSO

1. **TOTP and recovery codes**. The API enforces TOTP for enrolled administrator accounts and stores recovery codes as hashes.
2. **Hardened JWT Sessions**: `HttpOnly`, `Secure` HS256 session cookies (`aetherflow_session`) backed by SQLite `revoked_tokens` and `active_sessions` verification, paired with CSRF token/origin validation on all state-mutating endpoints.
3. **Perimeter Gateway & External Subdomain Authentication**:
   - `/api/v1/public/auth/verify` enforces active, unrevoked administrator sessions (validating JWT signature, SQLite token revocation, `sessions_revoked_after`, client fingerprint, and active admin role while rejecting plugin-scoped tokens) and injects verified `X-Aetherflow-User` identity headers into downstream applications while stripping untrusted client-supplied headers.
   - The Rust gateway requires an active administrator session or rate-limited Basic authentication for protected external applications. Administrators enrolled in TOTP use a verified session. The runner routes uncustomized managed vhosts for McVNC, Scrutiny, Prometheus, FlareSolverr, Threadfin, Unmanic, Netdata, and Autoscan through that gateway when it has a valid loopback address. ruTorrent and protected vhosts that use Apache for authentication retain the `/etc/apache2/AetherFlow/htpasswd` policy. Applications with native logins authenticate upstream.
4. **Plugin-Scoped RBAC & OS/Filesystem Isolation**:
   - Third-party plugins receive bounded tokens (`POST /api/v1/admin/plugins/:id/token` and read-only rotating `/run/aetherflow-plugin-token/runtime.token`) restricted to domain-matched `api_scopes` declared in `plugin.manifest.json`, with `/api/v1/admin/*` and `/api/v1/ingress/*` default-denied.
   - Managed plugin backends and `lifecycle_hooks.on_stop` hooks are **never** spawned directly by `af-api` as the `aetherflow` API user. `af-api` delegates managed plugin lifecycle (`start`, `stop`, `status`, `token`) to `aetherflow-runner.service` over `/run/aetherflow/runner.sock`, which independently validates the manifest and launches each plugin inside a hardened transient systemd unit (`aetherflow-plugin-<id>.service`) with `DynamicUser=yes`, empty `SupplementaryGroups=`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectProc=invisible`, `NoNewPrivileges=yes`, empty `CapabilityBoundingSet=`, `KillMode=control-group`, per-plugin `StateDirectory=aetherflow-plugin-<id>` (`0700`), read-only bind-mounted plugin assets (`/run/aetherflow-plugin-app`) and token directory (`/run/aetherflow-plugin-token` backed by `0700 root:root` `/run/aetherflow-runner-plugin-tokens`), and `InaccessiblePaths=` masking control-plane state (`/var/lib/aetherflow`, `/etc/aetherflow`, `/etc/AetherFlow`, `/run/aetherflow`, `/var/log/aetherflow`).
   - If `aetherflow-runner.service` or systemd isolation is unavailable, managed plugin execution fails closed with HTTP `503` (`PLUGIN_ISOLATION_UNAVAILABLE`) and zero fallback to the API OS identity. External plugin backends (manifests with no managed executable or local stop hook) remain supported independently.

---

## Data, Tenant Storage & Secret Isolation (FHS Layout)

- **Database Location**: `/var/lib/aetherflow/aetherflow.sqlite` (managed via `StateDirectory=aetherflow`, directory mode `0700`, file mode `0600`), using bundled `rusqlite` in `WAL` mode (`busy_timeout = 5000`, `foreign_keys = ON`).
- **Secrets File**: `/etc/aetherflow/aetherflow.env` (mode `0600`), never copied into or stored inside immutable code release directories.
- **AES-256-GCM at Rest (`enc:v1:`)**: All AI provider keys, OIDC secrets, and webhook credentials are encrypted in SQLite using `AES_MASTER_KEY` (`af-db`).
- **Native McBrowser Isolation (`af-files`)**: Per-user tenant directories under `/var/lib/aetherflow/mcbrowser/user-<id>` are enforced at mode `0700` with strict symlink/traversal rejection. The host filesystem path-picker (`/api/v1/auth/fs`) is restricted exclusively to active administrator accounts.

---

## Privilege Separation & Systemd Sandboxing

Rather than granting the web API unrestricted `sudo` or disabling `ProtectSystem=strict`, AetherFlow splits execution into two systemd units compiled from the same Rust workspace (`backend-rs`):

1. **`aetherflow-api.service` (Unprivileged Web Control Plane — `af-api`)**:
   - Runs as `User=aetherflow` with `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `ProtectControlGroups=yes`, `ProtectKernelTunables=yes`, `RestrictSUIDSGID=yes`, `DevicePolicy=closed` (`/dev/dri` and `/dev/nvidia*` device allowlists), `UMask=0027`, and `LimitNOFILE=65535`.
2. **`aetherflow-runner.service` (Root UNIX Socket Helper — `af-runner`)**:
   - Runs `/opt/AetherFlow/current/aetherflow-api runner` and listens exclusively on `/run/aetherflow/runner.sock` (`0660 root:aetherflow`), verifying caller `SO_PEERCRED` and `/proc/<pid>/exe` against trusted control-plane/CLI binaries (blocking plugin processes and scripting interpreters).
   - Enforces strict regex, enum, and `lstat` ancestor-symlink allowlists for `systemctl` actions, Marketplace package operations (9 native declarative Rust recipes + locked Bash installers serialized with `DPkg::Lock::Timeout=120`), blueprint/ingress mutations, WireGuard/Tailscale control, disk quotas, and isolated `aetherflow-self-update.service` updates.

---

## CI/CD & Release Security Gates

Every push and release runs through `.github/workflows/ci.yml`, `.github/workflows/security.yml`, and `.github/workflows/release.yml`:
- **Secret Scanning**: `gitleaks` scans the repository tree to block accidental credential or key commits.
- **Zero-Go Repository Hygiene**: CI, security, and release workflows assert `git ls-files '*.go' '*go.mod' '*go.sum'` is empty, enforcing a pure-Rust control plane and native Rust LibreSpeed backend (`af-librespeed`) with zero Go toolchain surface.
- **Rust Workspace Verification & Supply-Chain Audits**: `cargo test --workspace --locked` across all 11 backend crates and 4 WASM frontend crates (plus ignored systemd self-update survival integration checks `updater_survives_caller_restart`), strict `-D warnings` clippy across core crates (`af-models`, `af-host`, `af-release`, `af-cli`, `af-librespeed`), and `cargo audit` / `cargo deny`.
- **Signed/Checksummed Pull Releases (`af-release`)**: Production nodes verify `SHA256SUMS` and GitHub build provenance attestations before extracting `aetherflow-linux-amd64.tar.gz` into an exclusive `0700` staging directory, normalize executable permissions (`prepare_release_permissions`), capture a WAL-safe online SQLite `.backup` verified with `PRAGMA integrity_check`, verify the running binary path after restart, and automatically roll back if `/health/ready` fails.
