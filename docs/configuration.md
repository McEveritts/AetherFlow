# Configuration Reference

AetherFlow v4.0.0 uses a protected FHS environment file (`/etc/aetherflow/aetherflow.env`, mode `0600`) for runtime secrets and host-specific configuration, keeping mutable state strictly separated from immutable release directories (`/opt/AetherFlow/releases/<timestamp>`).

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
| `PORT` | Loopback port for the `aetherflow-api` Rust HTTP/WebSocket server. | `8080` |
| `AF_DB_PATH` / `DB_PATH` | Absolute path to the SQLite WAL database. Resolved in order: `AF_DB_PATH` $\to$ `DB_PATH` in `aetherflow.env` $\to$ systemd unit `Environment` $\to$ `/var/lib/aetherflow/aetherflow.sqlite`. | `/var/lib/aetherflow/aetherflow.sqlite` |
| `AETHERFLOW_RUNNER_SOCK` | UNIX domain socket path for the privileged `aetherflow-runner.service` daemon. | `/run/aetherflow/runner.sock` |
| `AETHERFLOW_BASE_DOMAIN` | Optional default `baseDomain` for automatic `<app>.<baseDomain>` subdomain ingress provisioning. | `(Configured in UI)` |

---

## Storage & Native McBrowser (`af-files`)

| Variable | Description | Default |
| :--- | :--- | :--- |
| `AF_MCBROWSER_ROOT` | Dedicated absolute directory owned by `aetherflow` (`0700`) for per-user McBrowser storage (`user-<id>`). | `/var/lib/aetherflow/mcbrowser` |
| `AF_MCBROWSER_MAX_UPLOAD_BYTES` | Maximum file size for resumable chunked uploads in Native McBrowser. | `68719476736` (`64 GiB`) |
| `AF_ALLOWED_FS_ROOTS` | Comma-separated roots accessible to administrator-only host path pickers (`/api/v1/auth/fs`). | `/mnt,/media,/srv,/home` |

---

## Security, SSO & Ingress

### Google OAuth2 & OIDC Provider
Optional external OAuth2 login and built-in OIDC provider settings for downstream application SSO:

| Variable | Description | Default |
| :--- | :--- | :--- |
| `ADMIN_EMAIL` | Email address granted automatic `admin` role on first OAuth login. | `(Optional)` |
| `GOOGLE_CLIENT_ID` | Google OAuth 2.0 Client ID. | `(Optional)` |
| `GOOGLE_CLIENT_SECRET` | Google OAuth 2.0 Client Secret. | `(Optional)` |
| `GOOGLE_REDIRECT_URI` | Typically `https://<YOUR_DOMAIN>/api/auth/google/callback`. | `(Optional)` |
| `OIDC_ISSUER` | Issuer URL for the built-in AetherFlow OIDC provider. | `(Auto-detected)` |
| `OIDC_KEY_PATH` | Path to the persisted RSA 2048-bit PEM key used for OIDC JWKS signing. | `/var/lib/aetherflow/oidc_rsa.pem` |

### Cookie, Host & CSRF Hardening
| Variable | Description | Default |
| :--- | :--- | :--- |
| `ALLOWED_HOSTS` | Comma-separated list of permitted `Host` header values (prevents Host header poisoning). | `(Auto-populated by Setup)` |
| `ALLOWED_CORS_ORIGIN` | Comma-separated list of explicit frontend origin URLs for CORS and WebSocket `Origin` checks. | `(Auto-detected)` |
| `COOKIE_SECURE` | Enforces `Secure` flag on `aetherflow_session` cookies. Set `false` only for local HTTP testing. | `true` |
| `CSRF_DISABLED` | Disables CSRF validation when `true` (never enable in production). | `false` |

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

---

## Release Engine, Package Executor & Cluster Flags

| Variable | Description | Default |
| :--- | :--- | :--- |
| `AF_GITHUB_TOKEN` | Optional GitHub token for higher rate limits during update checks (falls back to `GITHUB_TOKEN` / `GH_TOKEN`). | `(Unauthenticated)` |
| `AETHERFLOW_ENABLE_RUST_PACKAGES` | Opt-in flag (`1` / `true`) enabling `af-runner`'s 15 built-in declarative Rust package recipes before Bash fallback. | `false` |
| `AETHERFLOW_USE_RUST_RELEASE` | Opt-in flag (`1` / `true`) routing `/v1/self-update` directly through `af-release`. | `false` |
| `AF_HEAL_AUTO_APPROVE` | When `true`, `af-heal` restarts crashed systemd units automatically (up to 10/hr) without waiting for Approval Inbox sign-off. | `false` |
| `CLUSTER_MODE` | Multi-node fleet topology (`standalone`, `master`, `worker`). | `standalone` |
| `CLUSTER_PSK` | Pre-shared key validated via `X-Cluster-PSK` for cluster heartbeat and metrics endpoints. | `(Optional)` |

---

## Database & Backup Inspection

AetherFlow uses bundled **SQLite (`rusqlite`)** in `WAL` mode as its sole persistence engine (Redis is not required in v4.0.0).

> [!CAUTION]
> Never copy a live SQLite database with plain `cp` or `tar` while `aetherflow-api` is running. Always use **Settings → Backups** or `sudo af backup create` (`af-host` online backup API + `PRAGMA quick_check` + `.manifest.json` + `.sha256`). Changing `AES_MASTER_KEY` without re-entering stored credentials will render existing encrypted secrets unreadable.

```bash
# Inspect live database status and verify backups via the unified Rust CLI
sudo af release status
sudo af backup list
```
