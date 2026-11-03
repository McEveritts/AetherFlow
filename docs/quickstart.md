# Quickstart Guide

Get AetherFlow v4.0.0 running on your bare-metal infrastructure in under 5 minutes.

## Prerequisites

Before starting, ensure your system meets the following requirements:
- **Operating System**: Debian 12/13 (Bookworm/Trixie) or Ubuntu 22.04/24.04 LTS.
- **Privileges**: Root or `sudo` access.
- **Connectivity**: A public IP or domain name (recommended for automatic `<app>.<baseDomain>` TLS ingress and OIDC).
- **Clean Host**: A freshly installed Linux server is recommended to avoid port or service conflicts.

---

## 1. Bootstrap Installation

Clone the repository onto a clean **Debian 12/13** or **Ubuntu 22.04/24.04 LTS** server and run the bootstrap installer:

```bash
apt-get update && apt-get -y upgrade
apt-get -y install git curl
git clone https://github.com/McEveritts/AetherFlow.git /opt/AetherFlow
cd /opt/AetherFlow/setup
sudo bash AetherFlow-Setup
```

For non-interactive / automated provisioning:

```bash
sudo bash /opt/AetherFlow/setup/AetherFlow-Setup \
  --unattended \
  --username admin \
  --domain node.example.com
```

To repair an existing installation while preserving your SQLite database and configuration:

```bash
sudo bash /opt/AetherFlow/setup/AetherFlow-Setup --repair
```

> [!NOTE]
> The installer provisions the single-binary Rust control plane (`aetherflow-api.service`), the privileged UNIX socket daemon (`aetherflow-runner.service`), the unified `af` administrative CLI, Apache2 reverse proxy ingress, and `/etc/aetherflow/aetherflow.env` secrets.

---

## 2. Environment Configuration

Runtime secrets and environment variables are stored in `/etc/aetherflow/aetherflow.env` (mode `0600`):

```bash
# Inspect or customize environment settings
sudo nano /etc/aetherflow/aetherflow.env
```

`AetherFlow-Setup` automatically generates `JWT_SECRET` and `AES_MASTER_KEY` during bootstrap. If generating `AES_MASTER_KEY` manually, produce a 32-byte Base64 key:

```bash
openssl rand -base64 32
```

---

## 3. Verifying the Control Plane

Check the status of the AetherFlow systemd units or inspect release state via the `af` CLI:

```bash
sudo systemctl status aetherflow-runner aetherflow-api
sudo af release status
```

Navigate to your server's domain or IP in your browser:
`https://your-server-domain` (via Apache2 TLS proxy) or `http://your-server-ip:8080`

---

## 4. First Login & 2FA Setup

1. **Sign In**: Log in with the administrator credentials configured during setup (or via Google OAuth2 if configured).
2. **Configure Base Domain**: In the Onboarding Wizard or **Settings → General**, set your `baseDomain` to enable automatic `<app>.<baseDomain>` subdomain provisioning.
3. **Register TOTP 2FA**: Scan the presented QR code with an authenticator app (Bitwarden, Authy, Google Authenticator, or 1Password) and enter the 6-digit verification code.

> [!IMPORTANT]
> **Store your recovery codes.** If you lose access to your TOTP device, you will need a recovery code to regain administrative access.

---

## 5. Installing Your First Application

1. Open the **Marketplace** tab (or use the CLI: `sudo af package install qbittorrent`).
2. Select any of the **77 bare-metal applications** (e.g., **Jellyfin**, **qBittorrent**, **Qui**, **Sonarr**, **Palate**, or **Tailscale**).
3. Click **Install** and monitor the live progress ring and streaming logs.
4. Once complete, the application runs natively under `systemd` and is wired into the Subdomain Gateway automatically.

---

## Next Steps

- **Architecture**: Explore the 11-crate Rust workspace in [System Architecture](./architecture.md).
- **McBrowser**: Manage files and resumable uploads in [Native McBrowser](./mcbrowser.md).
- **Admin CLI**: Learn the `af` command suite in [Unified Rust Admin CLI](./rust-admin-cli.md).
- **Configuration**: Deep-dive into environment variables in the [Configuration Reference](./configuration.md).
- **Security**: Review systemd sandboxing and encryption in the [Security Guide](./security.md).
- **FlowAI**: Configure multi-provider AI diagnostics in the [FlowAI Documentation](./flowai.md).

> [!TIP]
> If you encounter any installation or service issues, inspect logs with `sudo journalctl -u aetherflow-api -u aetherflow-runner -f` or visit the [Troubleshooting Guide](./troubleshooting.md).
