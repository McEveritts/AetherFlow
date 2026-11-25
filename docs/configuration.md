# Configuration Reference

AetherFlow v4.0.0 uses a protected FHS environment file (`/etc/aetherflow/aetherflow.env`, mode `0640`, owned by `root:aetherflow` when provisioned by `AetherFlow-Setup`) for runtime secrets and host-specific configuration, keeping mutable state strictly separated from immutable release directories (`/opt/AetherFlow/releases/<timestamp>`).

## Environment File (`/etc/aetherflow/aetherflow.env`)

In production deployments provisioned by `AetherFlow-Setup`, environment variables live in `/etc/aetherflow/aetherflow.env` (for local development, a `.env` file in the repository root is also supported). After modifying `/etc/aetherflow/aetherflow.env`, restart the control plane service:

```bash
sudo systemctl restart aetherflow-runner aetherflow-api
```

---

## Core Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `JWT_SECRET` | Cryptographically random secret ($\ge 32$ bytes) used to sign HS256 session tokens. | `(Required)` |
| `AES_MASTER_KEY` | 32-byte key (raw 32-char or Base64-encoded 32 bytes) for AES-256-GCM database secret encryption (`enc:v1:`). | `(Required)` |
| `PORT` | TCP listen port for the `aetherflow-api` Rust HTTP/WebSocket server. | `8080` |
| `BIND_ADDR` | Bind address for `aetherflow-api` (`AetherFlow-Setup` sets `127.0.0.1` behind Apache2; bare runtime falls back to `0.0.0.0` unless isolated E2E mode is active). | `127.0.0.1` (Setup) |
| `STATIC_DIR` | Optional explicit path to the built Rust WASM dashboard bundle; defaults to `web/dist` beside `aetherflow-api`. | `<exe-dir>/web/dist` |
| `AF_DB_PATH` / `DB_PATH` / `AETHERFLOW_DB_PATH` | Absolute path to the SQLite WAL database. Resolved in order: `AF_DB_PATH` $\to$ `DB_PATH` $\to$ `AETHERFLOW_DB_PATH` (in `aetherflow.env` / systemd `Environment`) $\to$ `/var/lib/aetherflow/aetherflow.sqlite`. | `/var/lib/aetherflow/aetherflow.sqlite` |
| `AETHERFLOW_RUNNER_SOCK` | UNIX domain socket path for the privileged `aetherflow-runner.service` daemon. | `/run/aetherflow/runner.sock` |
| `AETHERFLOW_BASE_DOMAIN` | Optional default `baseDomain` for automatic `<app>.<baseDomain>` subdomain ingress provisioning. | `(Configured in UI)` |

---

## Storage & Native McBrowser (`af-files`)

| Variable | Description | Default |
| :--- | :--- | :--- |
| `AF_MCBROWSER_ROOT` | Dedicated absolute directory owned by `aetherflow` (`0700`) for per-user McBrowser storage (`user-<id>`). | `/var/lib/aetherflow/mcbrowser` |
| `AF_MCBROWSER_MAX_UPLOAD_BYTES` | Maximum file size for resumable chunked uploads in Native McBrowser. | `68719476736` (`64 GiB`) |
| `AF_ALLOWED_FS_ROOTS` | Comma-separated roots accessible to administrator-only host path pickers (`/api/v1/auth/fs`). | `/mnt,/media,/srv,/data,/home` |

---

## Security, SSO & Ingress

### Google OAuth2 & OIDC Provider
Optional external OAuth2 login and built-in OIDC provider settings for downstream application SSO:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `ADMIN_EMAIL` | Email address granted automatic `admin` role on first OAuth login. | `(Optional)` |
| `GOOGLE_CLIENT_ID` | Google OAuth 2.0 Client ID. | `(Optional)` |
| `GOOGLE_CLIENT_SECRET` | Google OAuth 2.0 Client Secret. | `(Optional)` |
| `GOOGLE_REDIRECT_URI` | Typically `https://<YOUR_DOMAIN>/api/v1/public/auth/google/callback`. | `(Optional)` |
| `OIDC_ISSUER` | Issuer URL for the built-in AetherFlow OIDC provider. | `(Auto-detected)` |
| `OIDC_KEY_PATH` | Path to the persisted RSA 2048-bit PEM key used for OIDC JWKS signing. | `/var/lib/aetherflow/oidc_rsa.pem` |

### Cookie, Host, Proxy & CSRF Hardening
| Variable | Description | Default |
| :--- | :--- | :--- |
| `PUBLIC_URL` | Optional public HTTPS origin (for example `https://node.example.com`) used for peer pairing strings, OIDC issuer/redirect URLs, and automatic `ALLOWED_HOSTS` allowlisting. | `(Auto-detected)` |
| `ALLOWED_HOSTS` | Comma-separated list of permitted `Host` header values (prevents Host header poisoning). | `(Auto-populated by Setup)` |
| `ALLOWED_CORS_ORIGIN` | Comma-separated list of explicit frontend origin URLs for CORS and WebSocket `Origin` checks. | `(Auto-detected)` |
| `TRUSTED_PROXIES` | Comma-separated list of trusted reverse-proxy IPs or CIDRs whose forwarded client IP and protocol headers (`X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`) are honored for rate limiting (including `/api/v1/peer-pairing/request`) and subdomain proxying. Takes precedence over `TRUST_PROXY_HEADERS` when non-empty. | Loopback (`127.0.0.1`, `::1`) |
| `TRUST_PROXY_HEADERS` | Controls whether forwarded headers from loopback proxies are trusted when `TRUSTED_PROXIES` is unset (set `false` or `0` to ignore loopback forwarded headers; set `true` behind a reverse proxy for OIDC origin detection). | Loopback trusted (`false` for OIDC unless set) |
| `COOKIE_SECURE` | Enforces `Secure` flag on `aetherflow_session` cookies. Set `false` only for local HTTP testing. | `true` |
| `CSRF_DISABLED` | Disables CSRF validation when `true` (never enable in production). | `false` |

### Systemd Service Hardening & Operator Drop-ins
The packaged control plane unit (`aetherflow-api.service`) enforces portable, least-privilege zero-trust sandboxing (`ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp=yes`, standard `systemd-journal,adm` groups).

Host-specific overrides (custom supplementary groups, media directories, or extra storage bind mounts) must never be edited directly into the packaged unit file. Instead, define them using an operator-owned systemd drop-in configuration file at `/etc/systemd/system/aetherflow-api.service.d/local.conf` (or via `systemctl edit aetherflow-api`):

```ini
[Service]
# Add host-specific supplementary groups (e.g. for shared media file access)
SupplementaryGroups=media

# Grant read/write access to host storage directories outside standard FHS paths
ReadWritePaths=/mnt/storage

# Bind host storage paths into McBrowser user root
BindPaths=/mnt/storage/media:/var/lib/aetherflow/mcbrowser/user-1/Media
```
After creating or modifying a drop-in, apply the changes with:
```bash
systemctl daemon-reload
systemctl restart aetherflow-api
```

---

## FlowAI Multi-Provider Engine

Settings here act as fallback defaults; API keys configured in **Settings → FlowAI Engine** are encrypted at rest in SQLite (`AES-256-GCM`) and take precedence:

| Variable | Description |
| :--- | :--- |
| `GEMINI_API_KEY` | Google AI Studio API key (default model: `gemini-4-argon`). |
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude 5.1 / 5.5 models. |
| `OPENAI_API_KEY` | OpenAI API key for GPT-6 / GPT-6.1 models. |
| `OLLAMA_ENDPOINT` | Local Ollama endpoint (defaults to `http://localhost:11434`). |
| `LM_STUDIO_ENDPOINT` | Local LM Studio endpoint (defaults to `http://localhost:1234`). |

Local AI settings persist the runtime (`localProvider`: `lm-studio`, `ollama`, or `anthropic-local`) separately from the installed model identifier (`localModel`, for example `qwen2.5:14b`). `aiModel` selects the active model. A remembered local runtime does not override a selected cloud model. Provider and runtime aliases are not inference model identifiers. Legacy runtime-prefixed model settings remain readable.

## Storage Quotas And Suspension

Storage quotas are administrator-managed capacity limits, not billing subscriptions. A non-empty quota status other than `active` suspends storage access; quota inspection and refresh preserve that status. McBrowser and FileShare enforce suspension independently of available capacity, including empty uploads and replacements. Role changes and account deletion cannot remove the last active, non-plugin administrator.

Backup uploads accept between 1 and 4,096 chunks per upload. Invalid chunk counts are rejected before staging files, and progress inspection enumerates staged parts rather than probing every claimed chunk index.

---

## Release Engine & Package Executor

| Variable | Description | Default |
| :--- | :--- | :--- |
| `AF_GITHUB_TOKEN` | Optional GitHub token for higher rate limits during update checks (falls back to `GITHUB_TOKEN` / `GH_TOKEN`). | `(Unauthenticated)` |
| `AETHERFLOW_ENABLE_RUST_PACKAGES` | Opt-in flag (`1` / `true`) enabling `af-runner`'s 9 built-in declarative Rust package recipes before Bash fallback. | `false` |
| `AETHERFLOW_FORCE_BASH_RELEASE` | Escape-hatch flag (`1` / `true`, or `AETHERFLOW_RELEASE_ENGINE=bash`) routing `/v1/self-update` through legacy `deploy/release-manager.sh` instead of the default native Rust `af-release` engine (`AETHERFLOW_ENABLE_RUST_RELEASE` / `AETHERFLOW_USE_RUST_RELEASE` remain accepted no-op compatibility flags). | `false` |
| `AF_ENABLE_LEGACY_SEEDBOX_ALIASES` | Setup opt-in flag (`1`) enabling legacy MD5 Digest `/etc/htpasswd` and Apache `aliases-seedbox.conf` on fresh installations (existing upgraded hosts are preserved automatically). | `0` |
| `AF_HEAL_AUTO_APPROVE` | When `1` or `true`, `af-heal` (10-second poll loop) restarts failed managed systemd units automatically via `aetherflow-runner` with exponential backoff (`10s * 2^attempt`, up to 3 retries) instead of queueing an Approval Inbox action. | `false` |

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

The Cluster tab guides pairing, endpoint selection, media storage, and distributed Jellyfin transcoding. [Peer clustering operator guide](peer-clustering.md)

---

## Database & Backup Inspection

AetherFlow uses bundled **SQLite (`rusqlite`)** in `WAL` mode as its sole persistence engine (Redis is not required in v4.0.0).

Browser backup downloads prompt for the current administrator password. The dashboard sends it in `X-Reauth-Password` to `POST /api/v1/admin/backup/download/{filename}` with session and CSRF verification, then starts a native streaming GET. A short lived HttpOnly proof cookie authorizes one download of that filename for that session within 60 seconds. Request a new download after expiry or a server restart. Command line API clients may send `X-Reauth-Password` directly on the authenticated GET; the password never belongs in a URL.


> [!CAUTION]
> Never copy a live SQLite database with plain `cp` or `tar` while `aetherflow-api` is running. Always use **Settings → Backups** or `sudo af backup create` (`af-host` online backup API + `PRAGMA quick_check` + `.manifest.json` + `.sha256`). Changing `AES_MASTER_KEY` without re-entering stored credentials will render existing encrypted secrets unreadable.

```bash
# Inspect live database status and verify backups via the unified Rust CLI
sudo af release status
sudo af backup list
```
