# Quickstart Guide

Get AetherFlow v3.2.5 running on your infrastructure in under 5 minutes.

## Prerequisites

Before starting, ensure your system meets the following requirements:
- **Operating System**: Ubuntu 24.04 LTS (Recommended) or Debian 12.
- **Privileges**: Sudo/Root access.
- **Connectivity**: A public IP or domain name (if using OIDC/Google Auth).
- **Hardening**: Freshly installed OS is preferred to avoid service conflicts.

---

## 1. Bootstrap Installation

Clone the repository onto a clean **Debian 12/13 (Bookworm/Trixie)** or **Ubuntu 22.04/24.04 LTS** server and run the bootstrap installer:

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

> [!NOTE]
> The installer automatically configures the unprivileged `aetherflow-api.service` control plane, the `aetherflow-runner.service` privileged socket helper, Apache2 reverse proxy ingress, and `/etc/aetherflow/aetherflow.env` secrets.

---

## 2. Environment Configuration

Runtime secrets and environment variables are stored in `/etc/aetherflow/aetherflow.env` (mode `0600`):

```bash
# Inspect or customize environment settings
sudo nano /etc/aetherflow/aetherflow.env
```

`AetherFlow-Setup` automatically generates `JWT_SECRET` and `AES_MASTER_KEY` during bootstrap. If rotating `AES_MASTER_KEY` manually, generate a 32-byte key:

```bash
openssl rand -hex 32
```

---

## 3. Verifying the Control Plane

Restart or check the AetherFlow systemd units:

```bash
sudo systemctl status aetherflow-runner aetherflow-api
```

Navigate to your server's domain or IP in your browser:
`https://your-server-domain` (via Apache2 TLS proxy) or `http://your-server-ip:8080`

---

## 4. First Login & 2FA Setup

1. **Sign In**: Use the "Admin" login path.
2. **Authorize**: Authenticate via Google (if configured) or your local admin account.
3. **Register 2FA**: Upon first login, AetherFlow will present a QR code. 
   - Scan this with an authenticator app (Google Authenticator, Authy, or Bitwarden).
   - Enter your first 6-digit code to finalize enrollment.

> [!IMPORTANT]
> **Store your recovery codes.** If you lose access to your TOTP device, you will need these to regain administrative access to the platform.

---

## 5. Installing your first App

1. Navigate to the **Marketplace** tab.
2. Select an application (e.g., **qbittorrent-nox**).
3. Click **Install**.
4. Monitor the circular progress indicator. Once complete, your app will be active and managed by systemd automatically.

---

## Next Steps

- **Configuration**: Deep-dive into advanced settings in the [Configuration Reference](./configuration.md).
- **Security**: Learn about service hardening in the [Security Guide](./security.md).
- **FlowAI**: Start your first AI-assisted diagnostic session in the [FlowAI Documentation](./flowai.md).

> [!TIP]
> If you encounter any installation errors, check the logs with `journalctl -u aetherflow-api -f` or visit the [Troubleshooting Guide](./troubleshooting.md).
