# Configuration Reference

AetherFlow v4.0.0 uses a protected FHS environment file (`/etc/aetherflow/aetherflow.env`) for runtime secrets and host-specific configuration, keeping mutable state separated from immutable release directories (`/opt/AetherFlow/releases/<timestamp>`). Both `aetherflow-api.service` and `aetherflow-runner.service` load `/etc/aetherflow/aetherflow.env` via `systemd` `EnvironmentFile=`, which PID 1 reads as `root` before dropping privileges to `User=aetherflow`. `AetherFlow-Setup` creates the file with mode `0640` (`root:aetherflow`); `af provision` enforces mode `0600` on created or existing files; `af-release` legacy `.env` migration writes `0600` preserving source `uid:gid` or falling back to `aetherflow:aetherflow`. Keep the file `0600` (`root:root` or `aetherflow:aetherflow`) or `0640` (`root:aetherflow`).

## Environment File (`/etc/aetherflow/aetherflow.env`)

In production deployments provisioned by `AetherFlow-Setup`, environment variables live in `/etc/aetherflow/aetherflow.env` (for local development, a `.env` file in the repository root is also supported). After modifying `/etc/aetherflow/aetherflow.env`, restart the control plane services:

```bash
sudo systemctl restart aetherflow-runner aetherflow-api
```

---

## Core Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `JWT_SECRET` | Cryptographically random secret (`>= 32` bytes) used to sign HS256 session tokens. | `(Required)` |
| `AES_MASTER_KEY` | 32-byte key (32 raw bytes, 64 hex characters, or Base64 decoding to 32 bytes) for AES-256-GCM database secret encryption (`enc:v1:`). | `(Required in production)` |
| `AETHERFLOW_ENV` | Runtime environment (`production` or `release` enforces fail-closed `AES_MASTER_KEY` initialization and ignores `CSRF_DISABLED=true` and `AF_DISABLE_RATELIMIT=1\|true`). | `production` (packaged unit) |
| `AETHERFLOW_ENV_FILE` | Explicit path to the environment file inspected for `AES_MASTER_KEY` and release resolution. | `/etc/aetherflow/aetherflow.env` |
| `DATA_DIR` | Primary mutable state directory used by `aetherflow-api.service` and `aetherflow-runner.service`. | `/var/lib/aetherflow` |
| `PORT` | TCP listen port for the `aetherflow-api` Rust HTTP/WebSocket server. If you change `PORT`, update Apache2's reverse-proxy upstream target away from `127.0.0.1:8080`, set `HEALTH_ENDPOINT` (e.g., `http://127.0.0.1:<port>/health/ready`) in `/etc/aetherflow/aetherflow.env` (and restart `aetherflow-runner`) for UI/runner-socket updates, and also pass `sudo env HEALTH_ENDPOINT=...` or `--config <external-conf>` (`AETHERFLOW_RELEASE_CONF`) during standalone `af release ... --local` deploys/rollbacks (which ignore `HEALTH_ENDPOINT` in `aetherflow.env`; note Debian/Ubuntu `sudo` `env_reset` strips shell-exported vars). | `8080` |
| `BIND_ADDR` | Bind address for `aetherflow-api` (`AetherFlow-Setup` writes `BIND_ADDR=127.0.0.1` behind Apache2; bare execution and fresh `af provision` generation default to `0.0.0.0` unless isolated E2E mode is active — keep `127.0.0.1` behind Apache2). | `127.0.0.1` (Setup) / `0.0.0.0` (bare / `af provision`) |
| `STATIC_DIR` | Optional explicit path to the built Rust WASM dashboard bundle (overrides `<exe-dir>/web/dist`). | `<exe-dir>/web/dist` |
| `AF_DB_PATH` / `DB_PATH` / `AETHERFLOW_DB_PATH` | Absolute path to the SQLite WAL database. Conflicting non-empty overrides fail closed; installed units default to `/var/lib/aetherflow/aetherflow.sqlite` (bare execution without `DATA_DIR` falls back to `<exe-dir>/data/aetherflow.sqlite`). | `/var/lib/aetherflow/aetherflow.sqlite` |
| `AETHERFLOW_RUNNER_SOCK` | Unix domain socket path for the privileged `aetherflow-runner.service` daemon. | `/run/aetherflow/runner.sock` |
| `PRIVILEGED_RUNNER_ENABLED` | Enables privileged runner readiness probing (`/v1/health`) alongside SQLite on `/health/ready` and `/api/v1/auth/ready` (`1`, `true`, `yes`, `on`, case-insensitive). | `false` (`true` in packaged unit) |
| `AETHERFLOW_BASE_DOMAIN` | Optional default `baseDomain` for automatic `<app>.<baseDomain>` subdomain ingress provisioning. | `(Configured in UI)` |
| `AETHERFLOW_SETUP_TOKEN` | Explicit one-time bootstrap token authorizing remote or Apache-proxied first-admin creation (`POST /api/v1/public/auth/setup`) when the `users` table is empty (otherwise auto-generated at `/var/lib/aetherflow/.setup-bootstrap-token`, mode `0600`). | `(Auto-generated file)` |

---

## Storage & Native McBrowser (`af-files` + `af-api::mcbrowser`)

| Variable | Description | Default |
| :--- | :--- | :--- |
| `AF_MCBROWSER_ROOT` | Dedicated absolute directory owned by `aetherflow` (`0700`) for per-user McBrowser storage (`user-<id>`). | `/var/lib/aetherflow/mcbrowser` |
| `AF_MCBROWSER_MAX_UPLOAD_BYTES` | Maximum file size for resumable chunked uploads in Native McBrowser. | `68719476736` (`64 GiB`) |
| `AF_ALLOWED_FS_ROOTS` | Comma-separated roots accessible to administrator-only host path pickers (`GET /api/v1/auth/fs`). When unset, `af-api` allows `/mnt,/media,/srv,/data,/home` plus `env::temp_dir()` (`/tmp`) and `env::current_dir()` (when outside `/opt/AetherFlow` and `/var/lib/aetherflow`). | `/mnt,/media,/srv,/data,/home` + `/tmp` + non-service CWD |
| `AETHERFLOW_UPLOAD_DIR` | Directory used by the built-in authenticated FileShare store (`/api/v1/auth/fileshare/*`, separate from McBrowser public share links). | `/var/lib/aetherflow/uploads` |

---

## Security, SSO & Ingress

### Google OAuth2 & OIDC Provider

Optional external OAuth2 login and built-in OIDC provider settings for downstream application SSO:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `AETHERFLOW_GOOGLE_ALLOWED_EMAILS` | Comma-separated email allowlist permitted to auto-provision a standard `role = 'user'` account on first Google OAuth login (unknown emails are denied by default; Google OAuth never auto-bootstraps an `admin`). | `(Deny unknown)` |
| `AETHERFLOW_GOOGLE_ALLOWED_DOMAINS` | Comma-separated email domain allowlist permitted to auto-provision a standard `role = 'user'` account on first Google OAuth login. | `(Deny unknown)` |
| `GOOGLE_CLIENT_ID` | Google OAuth 2.0 Client ID. | `(Optional)` |
| `GOOGLE_CLIENT_SECRET` | Google OAuth 2.0 Client Secret (environment variable only; not stored in SQLite). | `(Optional)` |
| `GOOGLE_REDIRECT_URI` | Typically `https://<your-domain>/api/v1/public/auth/google/callback`. | `(Optional)` |
| `OIDC_ISSUER` | Issuer URL for the built-in AetherFlow OIDC provider. | `(Auto-detected)` |
| `OIDC_KEY_PATH` | Path to the persisted RSA 2048-bit PEM key (`0600`) used for OIDC JWKS signing. | `/var/lib/aetherflow/oidc_rsa.pem` |

### Cookie, Host, Webhook & CSRF Hardening

| Variable | Description | Default |
| :--- | :--- | :--- |
| `ALLOWED_HOSTS` | Comma-separated list of permitted `Host` header values (hostnames, IP literals, or `host:port`; middleware strips ports/trailing dots and automatically permits canonical loopback IPs `127.0.0.0/8` / `::1`, `localhost`, `baseDomain`, `<app>.aether.local`, and enabled per-app public domains; non-loopback IPv4/IPv6 literals must be listed explicitly). | `(Auto-populated by Setup / af provision)` |
| `PUBLIC_URL` | Optional public base URL whose host is automatically accepted by `host_validation_middleware`. | `(Optional)` |
| `ALLOWED_CORS_ORIGIN` | Comma-separated list of explicit frontend origin URLs for CORS and WebSocket `Origin` checks. | Localhost origins (`http://localhost:3000/8080/$PORT`, `http://127.0.0.1:3000/8080/$PORT`) |
| `COOKIE_SECURE` | Enforces `Secure` flag on `aetherflow_session` cookies. Set `false` only for local plain-HTTP testing. Note: both fresh `af provision` and fresh IP-only, `localhost`, or `*.local` `AetherFlow-Setup` runs write `COOKIE_SECURE=false` (unless `COOKIE_SECURE`, `AF_TLS_ENABLED=1`, or `SSL_ENABLED=1` is set in the setup environment), and `--repair` preserves that `false` value until changed — restore `true` behind HTTPS. | `true` (`false` in fresh `af provision` and IP/`*.local` Setup) |
| `CSRF_DISABLED` | Disables double-submit CSRF validation when `true` in non-production environments. **Ignored** whenever `AETHERFLOW_ENV` is `production` or `release`. | `false` |
| `AF_DISABLE_RATELIMIT` | Disables auth/OIDC/AI rate limiting when `1` or `true` in non-production/test environments. **Ignored** whenever `AETHERFLOW_ENV` is `production` or `release`. | `false` |
| `AF_ALLOW_UNAUTH_LOCAL_LAN` | Opt-in (`1` or case-insensitive `true`) allowing unauthenticated access to gateway-protected `*.aether.local` apps from RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`, `fe80::/10`), and IPv6 ULA (`fc00::/7`) LAN clients only — unconditionally excludes Tailscale/CGNAT (`100.64.0.0/10`) and loopback (`127.0.0.0/8`, `::1`). Note that `172.16.0.0/12` includes local Docker bridge subnets. | `false` |
| `AETHERFLOW_ALLOW_PRIVATE_WEBHOOKS` | Opt-in (`1`, `true`, `yes`) permitting outbound notification webhooks to target RFC1918/CGNAT/ULA private LAN addresses (loopback, link-local, metadata, unspecified, and multicast targets remain blocked). | `false` |

### Systemd Service Hardening & Operator Drop-ins

The packaged control plane unit (`aetherflow-api.service`) enables `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`, `NoNewPrivileges=yes`, `RestrictSUIDSGID=yes`, `DevicePolicy=closed` (with `/dev/dri`, `char-drm`, `/dev/nvidiactl`, `/dev/nvidia0`, `/dev/nvidia-modeset`, `/dev/nvidia-uvm`), `SupplementaryGroups=systemd-journal adm`, `ReadWritePaths=/var/lib/aetherflow /var/log/aetherflow /run/aetherflow` plus optional `-/srv -/mnt -/media -/data` and `-/opt/AetherFlow/backend/data`, and `UMask=0027`.

Host-specific overrides (custom supplementary groups, extra GPU devices, or additional `ReadWritePaths`) must not be edited directly in the packaged unit file. Configure them in an operator-owned systemd drop-in at `/etc/systemd/system/aetherflow-api.service.d/local.conf` (or via `systemctl edit aetherflow-api`):

```ini
[Service]
# Add host-specific supplementary groups (e.g. for shared media file access)
SupplementaryGroups=media

# Grant read/write access to host storage directories outside standard FHS paths
ReadWritePaths=/mnt/storage

# Optional: allow additional NVIDIA GPUs on multi-GPU hosts
DeviceAllow=/dev/nvidia1 rw
```

> [!WARNING]
> Do **not** bind-mount shared host directories beneath `/var/lib/aetherflow/mcbrowser/user-<id>/` via `BindPaths=`. Account deletion recursively deletes `user-<id>` without `st_dev` mountpoint guards, which would remove files inside a bind-mounted host directory.

After creating or modifying a drop-in, reload systemd and restart the service:

```bash
sudo systemctl daemon-reload
sudo systemctl restart aetherflow-api
```

---

## FlowAI Multi-Provider Engine

Settings here act as fallback defaults; API keys configured in **Settings → FlowAI Providers** are encrypted at rest in SQLite (`AES-256-GCM`) and take precedence:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `GEMINI_API_KEY` | Google AI Studio API key (default model: `gemini-4-argon`). | `(Optional)` |
| `ANTHROPIC_API_KEY` | Anthropic API key for allowlisted Claude models (`claude-sonnet-5-5`, `claude-opus-5-6`, `claude-sonnet-4-5`, `claude-opus-4-6`, and peers). | `(Optional)` |
| `OPENAI_API_KEY` | OpenAI API key for allowlisted OpenAI models (`gpt-6.1-sol`, `gpt-6.2-*`, `gpt-4o`, `gpt-4o-mini`, `o3`, and peers). | `(Optional)` |
| `OLLAMA_ENDPOINT` | Local Ollama endpoint URL. | `http://localhost:11434` |
| `LM_STUDIO_ENDPOINT` | Local LM Studio endpoint URL. | `http://localhost:1234` |

Settings API payloads (`GET /api/v1/auth/settings` and `GET`/`PUT /api/v1/admin/settings` — mutations are admin-only) serialize local AI preferences in camelCase (`localProvider`: `lm-studio`, `ollama`, or `anthropic-local`; `localModel`, e.g., `qwen2.5:14b`; `aiModel` for the active model), backed by snake_case columns (`local_provider`, `local_model`, `ai_model`) in SQLite `settings`. A remembered local runtime does not override a selected cloud model. Provider and runtime aliases (`lm-studio`, `ollama`, `anthropic-local`, `localai`, `local-test`, `local`, `gemini`, `openai`, `anthropic`) are rejected as inference model identifiers; legacy `<runtime>:<model>` settings remain readable. See [FlowAI Assistant](./flowai.md).

---

## Storage Quotas & Suspension

AetherFlow coordinates SQLite storage accounting with host Linux disk quotas:

- **Control-Plane Storage Quotas (UI & API)**: Managed per SQLite user ID via **Storage Quotas** (`GET /api/v1/admin/quotas`, `PUT /api/v1/admin/quotas/{id}`, and `POST /api/v1/admin/quotas/{id}/refresh`). Updating a quota via the API persists the limit in SQLite `user_quotas` **and** dispatches `af-runner` (AetherFlow's `setdisk` quota wrapper invoking Linux `setquota`), while **Scan Disk** / `POST .../refresh` invokes `af-runner` to scan both `/home/<username>` and `<AF_MCBROWSER_ROOT>/user-<id>`. A non-empty quota status other than `active` suspends storage access; quota inspection and refresh preserve that status. Both **Native McBrowser** (`/var/lib/aetherflow/mcbrowser/user-<id>`) and **FileShare** (built-in authenticated file storage under `/var/lib/aetherflow/uploads` / `AETHERFLOW_UPLOAD_DIR` via `/api/v1/auth/fileshare/*` and `/api/v1/admin/fileshare/*`, separate from McBrowser public share links) enforce suspension independently of available capacity, including empty uploads and replacements. Role changes and account deletion cannot remove the last active, non-plugin administrator.
- **Direct CLI POSIX Disk Quotas (`af quota` / `setdisk`)**: Running `sudo af quota set <user> <size>` directly applies Linux POSIX filesystem quotas via `aetherflow-runner` per POSIX username without modifying SQLite `user_quotas`.

---

## Release Engine, Package Executor & Cluster Flags

All runtime service variables below are read by `aetherflow-api.service` and `aetherflow-runner.service` from `/etc/aetherflow/aetherflow.env` (or a `systemd` drop-in via `sudo systemctl edit aetherflow-runner`). For multi-node cluster mode (master telemetry aggregation and durable worker command dispatch), generate worker enrollment tokens on the master via `POST /api/v1/admin/cluster/enroll` (or **Cluster Nodes**), provision operator-managed TLS 1.3 mTLS certificates signed by your cluster CA, and see [API Reference — Cluster Master & Worker](./API.md#8-cluster-master--worker-apiv1admincluster) and [Threat Model](./threat_model.md) for control-plane (`CLUSTER_PSK` / admin mTLS cert) versus worker auth rules:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `AF_GITHUB_TOKEN` | Optional GitHub token for higher rate limits during API update checks and direct `af release ... --local` / `deploy/release-manager.sh` runs (falls back to `GITHUB_TOKEN` / `GH_TOKEN`). Note: `af-runner` does not forward GitHub tokens into transient self-update units. | `(Unauthenticated)` |
| `HEALTH_ENDPOINT` | Readiness URL polled by `af-release` / `deploy/release-manager.sh` after symlink swap. Setting it in `/etc/aetherflow/aetherflow.env` (+ restarting `aetherflow-runner`) applies to UI/runner-socket updates only; standalone `--local` runs ignore `HEALTH_ENDPOINT` in `aetherflow.env` and require `sudo env HEALTH_ENDPOINT=...` (Debian/Ubuntu `sudo` strips shell exports) or passing `--config` / `sudo env AETHERFLOW_RELEASE_CONF=...`. | `http://127.0.0.1:8080/health/ready` |
| `AETHERFLOW_RELEASE_CONF` | Optional path to an external `KEY=VALUE` release config file (matching `deploy/release-manager.conf`, e.g., `/etc/aetherflow/release-manager.conf`) read by `af-release` and `deploy/release-manager.sh`. Set inside `/etc/aetherflow/aetherflow.env` (+ restart `aetherflow-runner`) for runner-mediated updates, or pass via `sudo env AETHERFLOW_RELEASE_CONF=...` / `--config` for `--local` runs (runner-socket `af release deploy` rejects shell-exported `AETHERFLOW_RELEASE_CONF` without `--local`). | `/opt/AetherFlow/current/deploy/release-manager.conf` |
| `AETHERFLOW_BACKUP_DIR` | Directory where `af backup` and scheduled SQLite snapshots store archives, manifests, and `.sha256` sidecars. | `/var/lib/aetherflow/backups` |
| `AETHERFLOW_SKIP_PROVENANCE_VERIFY` | Break-glass override (`1`) bypassing Sigstore/SLSA v1 build provenance verification. Honored **only** in the process environment of direct `sudo env AETHERFLOW_SKIP_PROVENANCE_VERIFY=1 af release ... --local` or `deploy/release-manager.sh` runs (not forwarded into runner-mediated transient self-update units). | `0` |
| `AETHERFLOW_ENABLE_RUST_PACKAGES` | Opt-in flag (`1` / `true`) enabling `af-runner`'s 9 built-in declarative Rust package recipes before Bash fallback. | `false` |
| `AETHERFLOW_FORCE_BASH_PACKAGES` | Override flag (`1` / `true`) forcing `LegacyBashFallback` even if `AETHERFLOW_ENABLE_RUST_PACKAGES` is set. | `false` |
| `AETHERFLOW_FORCE_BASH_RELEASE` | Escape-hatch flag (`1` / `true`, or `AETHERFLOW_RELEASE_ENGINE=bash`) routing `runner.sock` IPC `/v1/self-update` through legacy `deploy/release-manager.sh` instead of the default native Rust `af-release` engine (`AETHERFLOW_ENABLE_RUST_RELEASE` / `AETHERFLOW_USE_RUST_RELEASE` remain accepted no-op compatibility flags). | `false` |
| `AF_HEAL_AUTO_APPROVE` | When `1` or `true`, `af-heal` (10-second poll loop) restarts failed managed systemd units automatically via `aetherflow-runner` with exponential backoff (`10s * 2^(attempt - 1)` = `10s`, `20s`, `40s`, up to 3 retries) instead of queueing an Approval Inbox action. | `false` |
| `CLUSTER_MODE` | Multi-node fleet topology (`standalone`, `master`, `worker`). | `standalone` |
| `CLUSTER_PSK` | Master pre-shared key validated via `X-Cluster-PSK` for control-plane `/cluster/v1/{metrics,commands}` and gRPC `GetMetrics`/`ExecuteCommand` endpoints (alongside non-worker admin mTLS certs; enrolled workers use per-node PSKs or pinned worker mTLS certs). | `(Optional)` |
| `CLUSTER_ADMIN_CLIENT_CERT` | Optional path to a pinned admin mTLS leaf certificate (SHA-256 matched) for control-plane `/cluster/v1/{metrics,commands}` and gRPC `GetMetrics`/`ExecuteCommand`, superseding default Subject CN matching (`aetherflow-master`, `aetherflow-control-plane`, `aetherflow-admin`). | `(Subject CN fallback)` |
| `CLUSTER_GRPC_HOST` / `CLUSTER_GRPC_PORT` | Bind host and port for the TLS 1.3 mTLS cluster master listener (HTTP/2 gRPC + `/cluster/v1/*` HTTPS). | `127.0.0.1` / `50051` |
| `CLUSTER_MASTER_ADDR` / `CLUSTER_ENROLL_TOKEN` | Master address and enrollment token (issued by the master via `POST /api/v1/admin/cluster/enroll`) used by worker nodes (`CLUSTER_MODE=worker`). | `(Required for worker)` |
| `CLUSTER_CA_CERT`, `CLUSTER_SERVER_CERT`, `CLUSTER_SERVER_KEY`, `CLUSTER_CLIENT_CERT`, `CLUSTER_CLIENT_KEY` | Operator-provisioned TLS 1.3 mTLS certificate/key paths required by `CLUSTER_MODE=master` (CA + server cert/key) and `CLUSTER_MODE=worker` (CA + client cert/key); startup fails closed when missing. | `(Required for master/worker)` |

### Setup-Time Bootstrap Flags (`setup/AetherFlow-Setup`)

These environment variables apply when invoking `setup/AetherFlow-Setup` rather than runtime services:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `AETHERFLOW_WEB_ADMIN_PASSWORD` | Optional initial web administrator password for unattended bootstrap (when unset, the first web admin is created via web onboarding using `/var/lib/aetherflow/.setup-bootstrap-token`). | `(Web onboarding)` |
| `AETHERFLOW_PREBUILT_TARBALL` / `AETHERFLOW_PREBUILT_SHA256_FILE` | Local candidate release tarball and independent `SHA256SUMS` file passed into `setup/AetherFlow-Setup` for offline or custom-built deployments. | `(Download from GitHub)` |
| `AF_ENABLE_LEGACY_SEEDBOX_ALIASES` | Opt-in flag (`1`) enabling legacy MD5 Digest `/etc/htpasswd` and Apache `aliases-seedbox.conf` on fresh installations (existing upgraded hosts are preserved automatically). | `0` |
| `AF_ALLOW_DIRECT_8080` | Opt-in flag (`1`) binding `aetherflow-api` directly to `0.0.0.0:8080` during setup instead of loopback `127.0.0.1:8080` behind Apache2. | `0` |
| `AF_TLS_ENABLED` / `SSL_ENABLED` | Optional setup-time flags (`1`) signaling TLS is enabled on IP-only, `localhost`, or `*.local` installs so `AetherFlow-Setup` writes `COOKIE_SECURE=true` instead of `false`. | `(Unset)` |

---

## Database & Backup Inspection

AetherFlow uses bundled **SQLite (`rusqlite`)** in `WAL` mode as its sole persistence engine (Redis is not required in v4.0.0).

### Backup Download Re-Authentication & Chunked Uploads

- **Browser Download Flow**: Prompted for the current administrator password, the dashboard sends `{"password": ...}` to `POST /api/v1/admin/backup/download/{filename}` (attaching `X-Reauth-Password` when ASCII) with session and CSRF verification, receives a 60-second `HttpOnly` single-use proof cookie bound to that filename and session, and starts a streaming `GET`. Request a new download after expiry or a server restart.
- **Server Precedence & OAuth**: Password-backed admins check JSON body `password`, then `X-Reauth-Password-Encoded` (UTF-8 percent-encoded), then `X-Reauth-Password`. For passwordless OAuth administrators, `X-Reauth-TOTP` is **mandatory** whenever `totp_enabled != 0` (`X-Reauth-Confirm` is ignored/rejected); when `totp_enabled == 0`, `X-Reauth-Confirm` (`oauth` or `download-backup`, case-insensitive) requires a fresh session (`session_auth_time <= 300s` old) backed by an unexpired row in SQLite `active_sessions`.
- **CLI / API Clients**: Send the reauth header directly on the authenticated `GET` request; never place passwords in a URL.
- **Chunked Backup Uploads (`POST /api/v1/admin/backup/upload/{filename}`)**: Accept between `1` and `4,096` chunks per upload. Invalid chunk counts are rejected before staging files, progress inspection enumerates staged parts rather than probing every claimed index, and background `maintain_backup_upload_staging` cleans expired staging directories.

> [!CAUTION]
> Never copy a live SQLite database with plain `cp` or `tar` while `aetherflow-api` is running. Always use **Settings → Backups & Restore** or `sudo af backup create` (`af-host` WAL-safe snapshot + `PRAGMA quick_check` + `PRAGMA integrity_check` + `.manifest.json` + `.sha256`). Changing `AES_MASTER_KEY` without re-entering stored credentials renders existing encrypted secrets (AI keys, TOTP secrets, streaming API keys, notification credentials, `/var/lib/aetherflow/.master.creds`, and SQLite `system_config.master_credentials`) unreadable.

```bash
# Inspect live database status and verify backups via the unified Rust CLI
sudo af release status
sudo af backup list
```
