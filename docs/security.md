# Security Guide

AetherFlow v4.0.0 implements defense-in-depth across authentication, encryption at rest, capability-scoped file access, systemd namespace sandboxing, and CI/CD supply-chain verification.

## Authentication & Perimeter SSO

1. **Mandatory TOTP 2FA**: Enforced for administrator accounts (`af-api::auth`) with hashed recovery codes.
2. **Hardened JWT Sessions**: `HttpOnly`, `Secure` HS256 session cookies (`aetherflow_session`) backed by SQLite `revoked_tokens` and `active_sessions` verification, paired with CSRF token/origin validation on all state-mutating endpoints.
3. **Perimeter Gateway (True SSO)**: The streaming Subdomain Gateway and `/api/v1/public/auth/verify` validate session tokens, check JWT revocation and session bindings, and inject verified `X-Aetherflow-User` identity headers into downstream applications while stripping untrusted client-supplied headers.
4. **Plugin-Scoped RBAC**: Third-party plugins receive bounded tokens (`POST /api/v1/admin/plugins/:id/token`) restricted to segment-boundary `api_scopes` declared in `plugin.manifest.json`.

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
   - Runs as `User=aetherflow` with `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `ProtectControlGroups=yes`, `ProtectKernelTunables=yes`, `RestrictSUIDSGID=yes`, and `MemoryMax=512M`.
2. **`aetherflow-runner.service` (Root UNIX Socket Helper — `af-runner`)**:
   - Runs `/opt/AetherFlow/current/aetherflow-api runner` and listens exclusively on `/run/aetherflow/runner.sock` (`0660 root:aetherflow`).
   - Enforces strict regex, enum, and `lstat` ancestor-symlink allowlists for `systemctl` actions, Marketplace package operations (15 native declarative Rust recipes + locked Bash installers serialized with `DPkg::Lock::Timeout=120`), WireGuard/Tailscale control, disk quotas, and isolated `aetherflow-self-update.service` updates.

---

## CI/CD & Release Security Gates

Every push and release runs through `.github/workflows/ci.yml`, `.github/workflows/security.yml`, and `.github/workflows/release.yml`:
- **Secret Scanning**: `gitleaks` scans the repository tree to block accidental credential or key commits.
- **Rust Workspace Verification**: `cargo test --workspace --locked` across all 11 crates, plus ignored systemd self-update survival integration checks (`updater_survives_caller_restart`).
- **Signed/Checksummed Pull Releases (`af-release`)**: Production nodes verify `SHA256SUMS` and GitHub build provenance attestations before extracting `aetherflow-linux-amd64.tar.gz` into an exclusive `0700` staging directory, normalize executable permissions (`prepare_release_permissions`), capture a WAL-safe online SQLite `.backup` verified with `PRAGMA integrity_check`, verify the running binary path after restart, and automatically roll back if `/health/ready` fails.
