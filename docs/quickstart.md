# Quickstart Guide

Deploy AetherFlow v4.0.0 on a Debian or Ubuntu bare-metal host. Depending on host performance, OS package updates, and optional source builds, bootstrap typically completes in 10 to 45 minutes.

## Prerequisites

Before starting, verify that your host meets the following requirements:

- **Operating System**: Debian 12/13 (Bookworm/Trixie) or Ubuntu 22.04/24.04 LTS.
- **Privileges**: Root or `sudo` access.
- **Network, DNS & Firewall**: Ports `80/tcp` and `443/tcp` reachable if using Let's Encrypt TLS; a domain name with DNS records for the control-plane host (for example `node.example.com`) plus wildcard `*.example.com` (or per-app A/AAAA records matching the `baseDomain` you set in Step 4, such as `example.com`) for `<app>.<baseDomain>` HTTPS ingress. Accessing the host by raw IP uses a self-signed Apache2 certificate until a domain is configured.
- **Clean Host**: A freshly installed Linux server avoids port and Apache/service conflicts.

---

## 1. Bootstrap Installation

Clone the repository onto a clean **Debian 12/13** or **Ubuntu 22.04/24.04 LTS** server and run the bootstrap installer:

```bash
sudo apt-get update && sudo apt-get -y upgrade
sudo apt-get -y install git curl
sudo git clone https://github.com/McEveritts/AetherFlow.git /opt/AetherFlow
cd /opt/AetherFlow/setup
sudo bash AetherFlow-Setup
```

*(If already logged in as `root` on a minimal image without `sudo`, omit `sudo`.)*

For non-interactive / automated provisioning (`--username` creates the Linux host owner account and records it in `/root/information.info` alongside the onboarding URL and bootstrap token path `/var/lib/aetherflow/.setup-bootstrap-token`; `--domain` configures the control-plane hostname, and the first web admin account is created via web onboarding unless `AETHERFLOW_WEB_ADMIN_PASSWORD` is explicitly set):

```bash
sudo bash /opt/AetherFlow/setup/AetherFlow-Setup \
  --unattended \
  --username admin \
  --domain node.example.com
```

To repair a specific bootstrap step on an existing installation while preserving your SQLite database and configuration (run with `--list-steps` to list step IDs; `build_modern` reinstalls the control plane):

```bash
sudo bash /opt/AetherFlow/setup/AetherFlow-Setup --repair build_modern
```

`setup/AetherFlow-Setup` handles full initial host bootstrap (APT repos, Apache2, TLS, and control-plane installation). For repeatable Rust-native foundation steps and day-2 administration on an installed host, use `af provision` and `af` subcommands (see [Unified Rust Admin CLI](./rust-admin-cli.md)).

> [!NOTE]
> The installer provisions the Rust control plane (`aetherflow-api.service`) and external `web/dist` WASM dashboard, the privileged Unix socket daemon (`aetherflow-runner.service`, executing `aetherflow-api runner`), the unified `af` administrative CLI (`/usr/local/bin/af` — installed as a `0755` delegating wrapper script to `/opt/AetherFlow/current/bin/af` on `AetherFlow-Setup` hosts), Apache2 reverse-proxy ingress, and `/etc/aetherflow/aetherflow.env`.

---

## 2. Environment Configuration

Runtime secrets and environment variables are stored in `/etc/aetherflow/aetherflow.env` (mode `0640`, owned by `root:aetherflow`):

```bash
# Inspect or customize environment settings
sudo nano /etc/aetherflow/aetherflow.env
```

`AetherFlow-Setup` automatically generates `JWT_SECRET` and `AES_MASTER_KEY` during bootstrap. If generating `AES_MASTER_KEY` manually on a fresh host before storing secrets, produce a 32-byte Base64 key:

```bash
openssl rand -base64 32
```

> [!CAUTION]
> Changing `AES_MASTER_KEY` on an existing host invalidates all previously encrypted secrets (AI provider keys, enrolled 2FA TOTP secrets, streaming server API keys, notification channel credentials, `/var/lib/aetherflow/.master.creds`, and SQLite `system_config.master_credentials`). After any edit to `/etc/aetherflow/aetherflow.env`, restart the control plane with `sudo systemctl restart aetherflow-runner aetherflow-api`.

---

## 3. Verifying the Control Plane

Check the status of the AetherFlow systemd units or inspect release state via the `af` CLI:

```bash
sudo systemctl status aetherflow-runner aetherflow-api
sudo af release status
```

Navigate to your server's domain or IP in your browser via Apache2: `https://your-server-domain` (or `https://your-server-ip`). By default `AetherFlow-Setup` writes `BIND_ADDR=127.0.0.1` and `PORT=8080` as separate variables in `/etc/aetherflow/aetherflow.env` so `aetherflow-api` binds strictly to loopback behind Apache2. Direct `:8080` access is disabled by default; if you explicitly need plain-HTTP direct `:8080` testing (`AF_ALLOW_DIRECT_8080=1` during setup, or setting `BIND_ADDR=0.0.0.0` alongside `PORT=8080`), you must also add your server IP/host to `ALLOWED_HOSTS`, set `COOKIE_SECURE=false` (never over untrusted networks), open port `8080/tcp` in any host firewall, and restart `aetherflow-api`.

---

## 4. First Login & 2FA Setup

1. **Initial Setup & Sign In**: Log in with the local administrator account configured during setup (Google OAuth2 denies unknown emails by default, only auto-provisions standard `role = 'user'` accounts, and never auto-bootstraps an `admin`; see [Configuration Reference](./configuration.md#google-oauth2--oidc-provider)). If the database has no users yet and you access the setup form remotely or through Apache2 (`POST /api/v1/public/auth/setup`), supply the one-time setup bootstrap token written to `/var/lib/aetherflow/.setup-bootstrap-token` (mode `0600`) or configured via `AETHERFLOW_SETUP_TOKEN`.
2. **Configure Base Domain**: In the Onboarding Wizard or **Settings → General & Localization**, set your `baseDomain` (typically the apex or delegated wildcard zone such as `example.com` so enabled apps resolve at `<app>.example.com`).
3. **Register TOTP 2FA (Recommended)**: In account settings, scan the presented QR code with an authenticator app (Bitwarden, Authy, Google Authenticator, or 1Password) and enter the 6-digit verification code.

> [!IMPORTANT]
> **Store your recovery codes.** If you lose access to your TOTP device, you will need a recovery code to regain administrative access.

---

## 5. Installing Your First Application

1. Open the **Marketplace** tab (or use the CLI: `sudo af package install qbittorrent`).
2. Select any of the **77 bare-metal applications** (for example **Jellyfin**, **qBittorrent**, **Qui**, **Sonarr**, **Palate**, or **Tailscale**).
3. Click **Install** and monitor the live progress ring and streaming logs.
4. Once complete, the application runs natively under `systemd` (or shared Apache2 for PHP web apps). Look up the app's allocated `<port>` in the **Services** tab, complete initial setup over its internal loopback address via an SSH tunnel (`ssh -L <port>:127.0.0.1:<port> user@host`) — or `http://<app>.aether.local` if you sync LAN split-horizon DNS (`/etc/hosts`, `dnsmasq`, Pi-hole, or AdGuard Home via `af hosts`; see [Unified Rust Admin CLI](./rust-admin-cli.md)) — and then enable external HTTPS routing (`<app>.<baseDomain>`) per app in **Network → External Access** (`external_access_enabled=1`). Non-HTTP utilities such as Tailscale, WireGuard, Fail2ban, and XRDP operate without an HTTP subdomain route.

---

## Next Steps

- **Architecture**: Explore the 11-crate Rust workspace in [System Architecture](./architecture.md).
- **McBrowser**: Manage files and resumable uploads in [Native McBrowser](./mcbrowser.md).
- **Admin CLI**: Learn the `af` command suite in [Unified Rust Admin CLI](./rust-admin-cli.md).
- **Configuration**: Review environment variables in the [Configuration Reference](./configuration.md).
- **Security**: Review systemd sandboxing and encryption in [Security & Hardening](./security.md).
- **FlowAI**: Configure multi-provider AI diagnostics in [FlowAI Assistant](./flowai.md).

> [!TIP]
> If you encounter installation or service issues, inspect logs with `sudo journalctl -u aetherflow-api -u aetherflow-runner -f` or visit the [Troubleshooting Guide](./troubleshooting.md).
