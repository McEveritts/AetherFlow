# Security Guide

AetherFlow v3.2.1+ implements defense-in-depth across authentication, data at rest, systemd namespace sandboxing, and CI/CD supply-chain verification.

## Authentication & Perimeter SSO

1. **Mandatory TOTP 2FA**: Enforced for administrator accounts (`totp.go`) with hashed recovery codes.
2. **Hardened JWT Sessions**: `HttpOnly`, `Secure` cookies paired with Redis JTI revocation and CSRF validation on all state-mutating endpoints.
3. **Perimeter Gateway (True SSO)**: Caddy `forward_auth` validates requests against `/api/v1/public/auth/verify` and injects `X-Aetherflow-User` identity headers into downstream applications.

---

## Data & Secret Isolation (FHS Layout)

- **Database Location**: `/var/lib/aetherflow/aetherflow.sqlite` (managed via `StateDirectory=aetherflow`, mode `0700`).
- **Secrets File**: `/etc/aetherflow/aetherflow.env` (mode `0600`), never copied into or stored inside code release directories.
- **AES-256-GCM at Rest**: All AI provider keys, OIDC secrets, and webhook credentials are encrypted in SQLite using `AES_MASTER_KEY`.

---

## Privilege Separation & Systemd Sandboxing

Rather than granting the web API unrestricted `sudo` or disabling `ProtectSystem=strict`, AetherFlow splits execution into two systemd units:

1. **`aetherflow-api.service` (Unprivileged Web Control Plane)**:
   - Runs as `User=aetherflow` with `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `ProtectControlGroups=yes`, `ProtectKernelTunables=yes`, and `RestrictSUIDSGID=yes`.
2. **`aetherflow-runner.service` (Root UNIX Socket Helper)**:
   - Listens exclusively on `/run/aetherflow/runner.sock` (`0660 root:aetherflow`).
   - Enforces strict regex and enum allowlists for `systemctl` actions, Marketplace installer scripts (serialized behind a global mutex with `DPkg::Lock::Timeout=120`), and atomic `release-manager.sh` updates.

---

## CI/CD Security Gates

Every push and release runs through `.github/workflows/security.yml` and `.github/workflows/release.yml`:
- **Secret Scanning**: `gitleaks` scans the repository to block accidental credential or key commits.
- **Go SAST & Vulnerability Checks**: `govulncheck`, `gosec`, `staticcheck`, `go vet`, and `go test -race`.
- **Signed/Checksummed Pull Releases**: Production nodes verify `SHA256SUMS` before extracting `aetherflow-linux-amd64.tar.gz` and perform an online SQLite `.backup` + `PRAGMA integrity_check` auto-rollback if `/health/ready` fails.
