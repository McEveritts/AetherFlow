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
| `PORT` | TCP listen port for the `aetherflow-api` Rust HTTP/WebSocket server. If you change `PORT`, update Apache2's reverse-proxy upstream target away from `127.0.0.1:8080` and set `HEALTH_ENDPOINT` (e.g., `http://127.0.0.1:<port>/health/ready`) in `/etc/aetherflow/aetherflow.env` (and restart `aetherflow-runner`); both UI/runner-socket updates and standalone `af release ... --local` / `deploy/release-manager.sh` runs read `HEALTH_ENDPOINT` from `/etc/aetherflow/aetherflow.env` unless overridden via process env or `--config`. | `8080` |
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
| `AF_ALLOWED_FS_ROOTS` | Comma-separated roots accessible to administrator-only host path pickers (`GET /api/v1/auth/fs`). When unset, `af-api` allows `/mnt,/media,/srv,/data,/home` and `env::current_dir()` (when outside `/opt/AetherFlow` and `/var/lib/aetherflow`); `/tmp` (`env::temp_dir()`) is excluded by default. | `/mnt,/media,/srv,/data,/home` + non-service CWD |
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

### Cookie, Host, Proxy, Webhook & CSRF Hardening

| Variable | Description | Default |
| :--- | :--- | :--- |
| `ALLOWED_HOSTS` | Comma-separated list of permitted `Host` header values (hostnames, IP literals, or `host:port`; middleware strips ports/trailing dots and automatically permits canonical loopback IPs `127.0.0.0/8` / `::1`, `localhost`, `baseDomain`, `<app>.aether.local`, and enabled per-app public domains; non-loopback IPv4/IPv6 literals must be listed explicitly). | `(Auto-populated by Setup / af provision)` |
| `PUBLIC_URL` | Optional public HTTPS base URL (for example `https://node.example.com`) used for peer pairing strings, OIDC issuer/redirect URLs, and automatic acceptance by `host_validation_middleware` / `ALLOWED_HOSTS`. | `(Auto-detected / Optional)` |
| `ALLOWED_CORS_ORIGIN` | Comma-separated list of explicit frontend origin URLs for CORS and WebSocket `Origin` checks. | Localhost origins (`http://localhost:3000/8080/$PORT`, `http://127.0.0.1:3000/8080/$PORT`) |
| `TRUSTED_PROXIES` | Comma-separated list of trusted reverse-proxy IPs or CIDRs whose forwarded client IP and protocol headers (`X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`) are honored for rate limiting (including `/api/v1/peer-pairing/request`) and subdomain proxying. Takes precedence over `TRUST_PROXY_HEADERS` when non-empty. | Loopback (`127.0.0.1`, `::1`) |
| `TRUST_PROXY_HEADERS` | Controls whether forwarded headers from loopback proxies are trusted when `TRUSTED_PROXIES` is unset (set `false` or `0` to ignore loopback forwarded headers; set `true` behind a reverse proxy for OIDC origin detection). | Loopback trusted (`false` for OIDC unless set) |
| `COOKIE_SECURE` | Enforces `Secure` flag on `aetherflow_session` cookies. Set `false` only for local plain-HTTP testing. Note: both fresh `af provision` and fresh IP-only, `localhost`, or `*.local` `AetherFlow-Setup` runs write `COOKIE_SECURE=false` (unless `COOKIE_SECURE`, `AF_TLS_ENABLED=1`, or `SSL_ENABLED=1` is set in the setup environment), and `--repair` preserves that `false` value until changed — restore `true` behind HTTPS. | `true` (`false` in fresh `af provision` and IP/`*.local` Setup) |
| `CSRF_DISABLED` | Disables double-submit CSRF validation when `true` in non-production environments. **Ignored** whenever `AETHERFLOW_ENV` is `production` or `release`. | `false` |
| `AF_DISABLE_RATELIMIT` | Disables auth/OIDC/AI rate limiting when `1` or `true` in non-production/test environments. **Ignored** whenever `AETHERFLOW_ENV` is `production` or `release`. | `false` |
| `AF_ALLOW_UNAUTH_LOCAL_LAN` | Opt-in (`1` or case-insensitive `true`) allowing unauthenticated access to gateway-protected `*.aether.local` apps from RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`, `fe80::/10`), and IPv6 ULA (`fc00::/7`) LAN clients only — unconditionally excludes Tailscale/CGNAT (`100.64.0.0/10`) and loopback (`127.0.0.0/8`, `::1`). Note that `172.16.0.0/12` includes local Docker bridge subnets. | `false` |
| `AETHERFLOW_ALLOW_PRIVATE_WEBHOOKS` | Opt-in (`1`, `true`, `yes`) permitting outbound notification webhooks to target RFC1918/CGNAT/ULA private LAN addresses (loopback, link-local, metadata, unspecified, and multicast targets remain blocked). | `false` |
| `METRICS_BEARER_TOKEN` | Optional static bearer token authorizing `GET /metrics` (`Authorization: Bearer <token>`) for Prometheus scrapers without requiring an interactive admin session cookie. | `(Admin session required)` |
| `METRICS_PUBLIC` | Opt-in flag (`1` or case-insensitive `true`) allowing unauthenticated access to `GET /metrics` (by default `/metrics` requires `METRICS_BEARER_TOKEN` or an active admin session even on loopback). | `false` |

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
> Do **not** bind-mount shared host directories beneath `/var/lib/aetherflow/mcbrowser/user-<id>/` via `BindPaths=`. Although `af-files` enforces `RESOLVE_NO_XDEV` / `st_dev` mount-boundary guards during recursive account cleanup (preserving mounted paths and auditing any skipped mountpoints), shared media should be exposed via explicit `ReadWritePaths` / `AF_ALLOWED_FS_ROOTS` instead of per-user McBrowser roots.

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
| `AF_AI_ALLOW_USER_CLOUD_PROVIDERS` | Allow non-admin users to dispatch paid cloud AI providers (`openai`, `gemini`, cloud `anthropic`) via `/api/v1/auth/ai/chat` (`1` or case-insensitive `true`). By default only administrators may dispatch paid cloud providers (`403 AI_PROVIDER_ADMIN_ONLY`); local runtimes remain available to all authenticated users. | `false` |

Settings API payloads (`GET /api/v1/auth/settings` and `GET`/`PUT /api/v1/admin/settings` — mutations are admin-only) serialize local AI preferences in camelCase (`localProvider`: `lm-studio`, `ollama`, or `anthropic-local`; `localModel`, e.g., `qwen2.5:14b`; `aiModel` for the active model), backed by snake_case columns (`local_provider`, `local_model`, `ai_model`) in SQLite `settings`. `anthropic-local` defaults to `http://127.0.0.1:8081`, never attaches stored cloud API keys, and all AI endpoints targeting `aetherflow-api`'s own listener (`PORT` / `BIND_ADDR` / loopback / unspecified) are rejected with `400 AI_SELF_TARGET_REJECTED`. A remembered local runtime does not override a selected cloud model. Provider and runtime aliases (`lm-studio`, `ollama`, `anthropic-local`, `localai`, `local-test`, `local`, `gemini`, `openai`, `anthropic`) are rejected as inference model identifiers; legacy `<runtime>:<model>` settings remain readable. See [FlowAI Assistant](./flowai.md).

---

## Storage Quotas & Suspension

AetherFlow coordinates SQLite storage accounting with host Linux disk quotas:

- **Control-Plane Storage Quotas (UI & API)**: Managed per SQLite user ID via **Storage Quotas** (`GET /api/v1/admin/quotas`, `PUT /api/v1/admin/quotas/{id}`, and `POST /api/v1/admin/quotas/{id}/refresh`). Updating a quota via the API persists the limit in SQLite `user_quotas` **and** dispatches `af-runner` (AetherFlow's `setdisk` quota wrapper invoking Linux `setquota`), while **Scan Disk** / `POST .../refresh` invokes `af-runner` to scan both `/home/<username>` and `<AF_MCBROWSER_ROOT>/user-<id>`. A non-empty quota status other than `active` suspends storage access; quota inspection and refresh preserve that status. Both **Native McBrowser** (`/var/lib/aetherflow/mcbrowser/user-<id>`) and **FileShare** (built-in authenticated file storage under `/var/lib/aetherflow/uploads` / `AETHERFLOW_UPLOAD_DIR` via `/api/v1/auth/fileshare/*` and `/api/v1/admin/fileshare/*`, separate from McBrowser public share links) enforce suspension independently of available capacity, including empty uploads and replacements. Role changes and account deletion cannot remove the last active, non-plugin administrator.
- **Direct CLI POSIX Disk Quotas (`af quota` / `setdisk`)**: Running `sudo af quota set <user> <size>` directly applies Linux POSIX filesystem quotas via `aetherflow-runner` per POSIX username without modifying SQLite `user_quotas`.

---

## Release Engine & Package Executor

All runtime service variables below are read by `aetherflow-api.service` and `aetherflow-runner.service` from `/etc/aetherflow/aetherflow.env` (or a `systemd` drop-in via `sudo systemctl edit aetherflow-runner`). For peer-to-peer clustering, media storage, and distributed Jellyfin transcoding, see [Peer clustering and API logs](#peer-clustering-and-api-logs), [API Reference — Peer Clustering](./API.md#8-peer-clustering), and the [Peer clustering operator guide](./peer-clustering.md).

| Variable | Description | Default |
| :--- | :--- | :--- |
| `AF_GITHUB_TOKEN` | Optional GitHub token for higher rate limits during API update checks, transient self-updates, and `--local` / `deploy/release-manager.sh` runs (falls back to `GITHUB_TOKEN` / `GH_TOKEN`). `af-runner` never forwards tokens into `systemd-run --setenv` or `<unit>.conf`; instead, `af-release` and `deploy/release-manager.sh` read them directly from `/etc/aetherflow/aetherflow.env` into redacted memory (unless `AETHERFLOW_SKIP_ENV_FILES=1`). | `(Unauthenticated)` |
| `HEALTH_ENDPOINT` | Readiness URL polled by `af-release` / `deploy/release-manager.sh` after symlink swap. Loaded with unified precedence `process env > explicit --config > /etc/aetherflow/aetherflow.env > default-fallback --config > compiled default` (unless `AETHERFLOW_SKIP_ENV_FILES=1`). | `http://127.0.0.1:8080/health/ready` |
| `AETHERFLOW_RELEASE_CONF` | Optional path to an external `KEY=VALUE` release config file (matching `deploy/release-manager.conf`, e.g., `/etc/aetherflow/release-manager.conf`) read by `af-release` and `deploy/release-manager.sh`. Set inside `/etc/aetherflow/aetherflow.env` (+ restart `aetherflow-runner`) for runner-mediated updates, or pass via `sudo env AETHERFLOW_RELEASE_CONF=...` / `--config` for `--local` runs (runner-socket `af release deploy` rejects shell-exported `AETHERFLOW_RELEASE_CONF` without `--local`). | `/opt/AetherFlow/current/deploy/release-manager.conf` |
| `AETHERFLOW_BACKUP_DIR` | Directory where `af backup` and scheduled SQLite snapshots store archives, manifests, and `.sha256` sidecars. | `/var/lib/aetherflow/backups` |
| `AETHERFLOW_SKIP_PROVENANCE_VERIFY` | Break-glass override (`1`) bypassing Sigstore/SLSA v1 build provenance verification. Never forwarded by `af-runner` into `systemd-run --setenv` or `<unit>.conf`; honored only from the direct process environment (`sudo env AETHERFLOW_SKIP_PROVENANCE_VERIFY=1 af release ... --local`) or a trusted root-owned, non-group/world-writable `/etc/aetherflow/aetherflow.env`. | `0` |
| `AETHERFLOW_ENABLE_RUST_PACKAGES` | Opt-in flag (`1` / `true`) enabling `af-runner`'s 9 built-in declarative Rust package recipes before Bash fallback. | `false` |
| `AETHERFLOW_FORCE_BASH_PACKAGES` | Override flag (`1` / `true`) forcing `LegacyBashFallback` even if `AETHERFLOW_ENABLE_RUST_PACKAGES` is set. | `false` |
| `AETHERFLOW_FORCE_BASH_RELEASE` | Escape-hatch flag (`1` / `true`, or `AETHERFLOW_RELEASE_ENGINE=bash`) routing `runner.sock` IPC `/v1/self-update` through legacy `deploy/release-manager.sh` instead of the default native Rust `af-release` engine (`AETHERFLOW_ENABLE_RUST_RELEASE` / `AETHERFLOW_USE_RUST_RELEASE` remain accepted no-op compatibility flags). | `false` |
| `AF_HEAL_AUTO_APPROVE` | When `1` or `true`, `af-heal` (10-second poll loop) restarts failed managed systemd units automatically via `aetherflow-runner` with exponential backoff (`10s * 2^(attempt - 1)` = `10s`, `20s`, `40s`, up to 3 retries) instead of queueing an Approval Inbox action. | `false` |

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

## Peer clustering and API logs

| Variable | Description | Default |
| :--- | :--- | :--- |
| `AF_SERVER_NAME` | Optional operator peer display-name override for this server. Resolution falls back through `AF_SERVER_NAME` → `HOSTNAME` → `/etc/hostname` → `"aetherflow"`. | `(Hostname / "aetherflow")` |
| `PUBLIC_URL` | Optional public `https://` origin embedded in single-use pairing strings (also used by OIDC and `ALLOWED_HOSTS`). | `(Auto-detected)` |
| `AF_PEER_TUNNEL_CIDR` | Subnet for peer tunnel addresses on `afpeer0`. Configure a subnet that avoids existing routes. | `10.231.0.0/16` |
| `AF_PEER_WG_PORT` | UDP listen port for the dedicated WireGuard interface. | `51821` |
| `AF_PEER_LISTEN_PORT` | TCP port for the API peer listener on the local tunnel address. | `9443` |
| `AF_PEER_MAX_CONN` | Concurrent requests admitted per peer link at the listener and outbound management proxy. | `64` |
| `AF_PEER_MAX_WS` | Concurrent proxied WebSockets per peer link. | `16` |
| `AF_PEER_RTT_WARN_MS` | Link RTT threshold in milliseconds for the Cluster warning. | `25` |
| `AF_PEER_ALLOW_PRIVATE_PAIRING_URLS` | Opt-in flag (`1` / `true` / `yes` / `on`) permitting RFC 1918 private, CGNAT (`100.64.0.0/10`), and IPv6 unique-local (`fc00::/7`) targets in public pairing HTTPS URLs on private LANs. Loopback, link-local/cloud metadata, unspecified, multicast, broadcast/reserved, and the peer tunnel CIDR remain unconditionally blocked. | `false` |
| `AF_LOG_FORMAT` | Set to `json` for structured API logs. The API continues to honor `RUST_LOG`. | Text |

Malformed or out-of-range values for `AF_PEER_LISTEN_PORT`, `AF_PEER_MAX_CONN`, `AF_PEER_MAX_WS`, and `AF_PEER_RTT_WARN_MS` emit a `tracing::warn!` log entry and fall back to their defaults.

### Distributed Transcoding Environment File (`/etc/aetherflow/transcode.env`)

Distributed Jellyfin transcoding overrides live in a dedicated, secret-free environment file at `/etc/aetherflow/transcode.env` (mode `0640`, owned by `root:jellyfin`). It is loaded via `EnvironmentFile=-/etc/aetherflow/transcode.env` by all four consuming units: `aetherflow-api.service`, `aetherflow-runner.service`, `jellyfin.service`, and `af-transcode-worker.service`.

> [!CAUTION]
> Never place API keys, tokens, or secrets in `/etc/aetherflow/transcode.env`, and never load `/etc/aetherflow/aetherflow.env` in `af-transcode-worker.service` or `jellyfin.service`. `af-transcode` explicitly refuses to read any file named `aetherflow.env`.

| Variable | Description | Default |
| :--- | :--- | :--- |
| `AF_TRANSCODE_REAL_FFMPEG` | Absolute path to the real FFmpeg binary executed by the Jellyfin shim and worker. | `/usr/lib/jellyfin-ffmpeg/ffmpeg` |
| `AF_TRANSCODE_WORKER_MAX_JOBS` | Maximum concurrent transcode jobs permitted on a worker (`1..=64`, clamped automatically). Advertised over link-authenticated tunnel `GET /health` as `worker_max_jobs` so controllers auto-clamp per-worker concurrency (`effective_max_jobs = min(max_jobs, worker_max_jobs)`). | `8` |
| `AF_TRANSCODE_DISPATCH_POLICY` | Controller default dispatch policy (`remote_first`, `local_first`, or `balanced`) when not overridden in **Cluster → Jellyfin transcoding** (SQLite `transcode_dispatch_settings`). | `remote_first` |
| `AF_TRANSCODE_LOCAL_MAX_JOBS` | Maximum concurrent local Jellyfin transcode jobs (`1..=64`, clamped automatically) tracked via `SO_PEERCRED` under `local_first` and `balanced` dispatch policies. | `2` |
| `AF_TRANSCODE_FFMPEG_THREADS` | Optional per-job worker FFmpeg thread cap (`1..=128`, clamped automatically; unset or `0` disables capping) applied to `-threads`, `-filter_threads`, and `-filter_complex_threads`. | `(Unset / uncapped)` |
| `AF_TRANSCODE_ADAPT_BACKEND` | Opt-in worker cross-backend adaptation mode: `off` (strict), `gpu` (or `cross_gpu`, QSV → VA-API when no Intel node is available), `prefer_qsv` (promote VA-API → QSV on Intel workers + QSV → VA-API fallback), or `all` (or `gpu_and_cpu`, adds hardware → CPU software overflow). | `off` |
| `AF_TRANSCODE_VULKAN_COMPUTE` | Enables hardware Vulkan Compute probing and routing for `libplacebo` HDR tone-mapping and `*_vulkan` compute filters when a real integrated or discrete Vulkan GPU is present (software `llvmpipe` is rejected). Set to `false` (`0` / `no` / `off`) to disable Vulkan Compute on a node. | `true` |
| `AF_TRANSCODE_OPTIMIZE_VULKAN_TONEMAP` | Rewrites verified linear VA-API → Vulkan `libplacebo` HDR tone-mapping filtergraphs to pre-scale via `scale_vaapi` (preserving 10-bit `p010`) before Vulkan upload and tone-mapping on both remote workers and local shim execution. Set to `false` (`0` / `no` / `off`) to disable. | `true` |
| `AF_TRANSCODE_VULKAN_VIDEO` | Keeps experimental Vulkan Video hardware decode/encode (`-hwaccel vulkan`, `*_vulkan` video encoders) disabled by default and strips `*_vulkan` encoders from advertised capabilities so Vulkan Compute HDR tone-mapping stays enabled independently. Set to `true` (`1` / `yes` / `on`) to opt in on GPUs exposing verified `VK_KHR_video_decode_*` / `VK_KHR_video_encode_*` extensions. | `false` |
| `AF_TRANSCODE_DISPATCHER_SOCK` | Override for the controller dispatcher Unix socket shared between `aetherflow-api.service` and `jellyfin.service`. | `/run/aetherflow-transcode/transcode.sock` |
| `AF_TRANSCODE_WORKER_SOCK` | Override for the `af-transcode-worker.service` Unix socket path. | `/run/aetherflow-transcode-worker/worker.sock` |
| `AF_TRANSCODE_WORKER_SOCKET_MODE` | Octal permission mode for the worker Unix socket (fails closed on invalid or world-accessible modes). | `0660` |
| `AF_TRANSCODE_HANDSHAKE_TIMEOUT_MS` | End-to-end handshake timeout (ms) for the Jellyfin FFmpeg shim before falling back to local `ffmpeg`. | `2000` |
| `AETHERFLOW_TRANSCODE_BIN` | Runner-only (`aetherflow-runner.service`) explicit override path to the `af-transcode` binary (defaults to release bundle `bin/af-transcode`). | `<release-dir>/bin/af-transcode` |
| `MESA_SHADER_CACHE_DIR` / `MESA_SHADER_CACHE_MAX_SIZE` / `MESA_SHADER_CACHE_DISABLE` | Worker-local host Mesa shader cache overrides (never accepted from remote callers). `af-transcode-worker.service` sets `CacheDirectory=aetherflow-transcode-worker` and defaults cache path/size automatically. | `/var/cache/aetherflow-transcode-worker/mesa-cache` / `512M` |
| `RUSTICL_ENABLE` / `RADV_PERFTEST` / `ANV_VIDEO_DECODE` / `LIBVA_*` / `VK_*` / `OCL_ICD_VENDORS` / `AMD_VULKAN_ICD` / `ONEVPL_PRIORITY_PATH` / `MFX_HOME` | Optional worker-local GPU driver, Vulkan/OpenCL/Rusticl, VA-API, and oneVPL environment keys preserved strictly from the worker's own systemd environment and `/etc/aetherflow/transcode.env` (never accepted from remote callers). | `(Unset)` |

*(Internal guard variable `AF_TRANSCODE_SHIM_ACTIVE` is set automatically by the shim to prevent recursive invocation and must not be configured manually.)*

The Cluster tab guides pairing, endpoint selection, media storage, and distributed Jellyfin transcoding. [Peer clustering operator guide](peer-clustering.md)

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
