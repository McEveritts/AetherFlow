# Quickstart Guide

Get AetherFlow v3.1.7 running on your infrastructure in under 5 minutes.

## Prerequisites

Before starting, ensure your system meets the following requirements:
- **Operating System**: Ubuntu 24.04 LTS (Recommended) or Debian 12.
- **Privileges**: Sudo/Root access.
- **Connectivity**: A public IP or domain name (if using OIDC/Google Auth).
- **Hardening**: Freshly installed OS is preferred to avoid service conflicts.

---

## 1. Automatic Installation

Run the following command to bootstrap the AetherFlow environment, including the Go backend, Next.js frontend, and all necessary systemd units.

```bash
# Sourcing the installer
curl -sSL https://install.aetherflow.io | sudo bash
```

> [!NOTE]
> The installer will automatically perform hardware discovery and configure optimal threading for the Go backend based on your CPU core count.

---

## 2. Initial Configuration

Once the installation completes, you must configure your environment to enable administrative access and security features.

### Set your Admin Email
Edit the `.env` file located in the root directory (typically `/opt/AetherFlow/.env`):

```bash
# Path to environment file
sudo nano /opt/AetherFlow/.env
```

Find the following line and change it to your primary email address:
```env
ADMIN_EMAIL=your-email@gmail.com
```

### Configure Security Keys
Generate a master encryption key for your database secrets:

```bash
# Generate a random 32-byte key
openssl rand -base64 32
```
Copy this value and paste it into the `AES_MASTER_KEY` field in your `.env`.

---

## 3. Launching the Dashboard

Restart the AetherFlow services to apply your configuration:

```bash
sudo systemctl restart aetherflow-api aetherflow-frontend
```

Now, navigate to your server's IP or domain in your browser:
`https://your-server-ip:3000` (Default Port)

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
