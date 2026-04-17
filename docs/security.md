# Security Guide

AetherFlow v3.1.x implement a deep-security posture designed to protect your infrastructure from unauthorized access while maintaining operational fluidity.

## Authentication Layer

### 1. TOTP Two-Factor Authentication
Mandatory 2FA is the standard for all AetherFlow administrator accounts.
- **Enrollment**: On first login, the platform forces a TOTP registration flow using a QR code.
- **Verification**: All subsequent login attempts require a valid 6-digit code from a registered authenticator app (e.g., Google Authenticator, Bitwarden).
- **Session Duration**: Sessions are capped and can be remotely invalidated via the dashboard or Redis.

### 2. JWT Session Security
AetherFlow uses encrypted JSON Web Tokens (`aetherflow_session`) for stateless authentication.
- **HTTP-Only Cookies**: Tokens are stored in `HttpOnly` and `Secure` cookies to prevent XSS-based theft.
- **CSRF Protection**: All state-changing requests (POST/PUT/DELETE) require a valid CSRF token matched against the session state.

### 3. Perimeter Gateway (True SSO)
AetherFlow acts as a lightweight Identity Provider (IdP) for all hosted applications across the platform.
- **Forward\_Auth intercept**: Caddy intercepts all traffic meant for internal applications (e.g., Radarr, Jellyseerr) and first routes it to AetherFlow's `/api/v1/auth/verify` endpoint.
- **Identity Proxy Header Injection**: Upon confirming a valid session, AetherFlow passes an authenticated `X-Aetherflow-User` context header downstream to the underlying application.
- **Double-login Prevention**: Thanks to AetherFlow's native "Config Mutators," target applications are pre-configured locally to trust Proxied Authentication. An authenticated AetherFlow user drops directly into their media application interfaces seamlessly.

---

## Data Security

### 1. AES-256 Encryption at Rest
All sensitive provider API keys, OIDC secrets, and SSH credentials stored in the SQLite database are encrypted at rest.
- **Algorithm**: AES-256-GCM.
- **Key Storage**: The master encryption key is never stored in the database; it must be provided via the `AES_MASTER_KEY` environment variable.

> [!CAUTION]
> **Key Fragility**: If you lose your `AES_MASTER_KEY`, you will lose access to all encrypted secrets in the database. There is no recovery path for an encrypted database without the original key.

### 2. Secret Rotation
To rotate your master key:
1. Export current secrets in an unencrypted state (requires admin privilege).
2. Update the `AES_MASTER_KEY` in `.env`.
3. Re-import or re-run the encryption sync utility.

---

## Infrastructure Hardening

### 1. Least-Privilege Sudoers
AetherFlow requires certain root privileges to manage systemd units and install marketplace applications. To ensure security, we use a targeted sudoers policy rather than running the whole process as root.

**Recommended Configuration (`/etc/sudoers.d/aetherflow`):**
```bash
# Allow the aetherflow user to manage specific services without a password
aetherflow ALL=(ALL) NOPASSWD: /usr/bin/systemctl restart af-*
aetherflow ALL=(ALL) NOPASSWD: /usr/bin/systemctl status af-*
aetherflow ALL=(ALL) NOPASSWD: /opt/AetherFlow/packages/common.sh
```

### 2. Service Isolation
By migrating to **systemd**, AetherFlow leverages standard Linux security features:
- **PrivateTmp**: Most managed app units are configured with isolated `/tmp` directories.
- **User Namespacing**: Each marketplace application can be configured to run as a non-privileged system user.

---

## Network Security

### 1. CORS & Host Validation
To prevent cross-site request forgery and host-header injection (CWE-601), AetherFlow enforces strict origin validation.
- **Allowed Hosts**: Only requests with `Host` headers matching your `ALLOWED_HOSTS` configuration are accepted.
- **CORS**: APIs are restricted to your frontend origin by default.

### 2. Reverse Proxy Recommendation
AetherFlow should always be deployed behind a modern reverse proxy (Nginx, Caddy, or Traefik) for:
- **TLS Termination**: Ensuring all traffic is encrypted via HTTPS.
- **Rate Limiting**: Protecting the API from brute-force attempts.
- **Access Logs**: Standardizing audit trails at the edge.

> [!TIP]
> Use **Tailscale Funnel** or a similar overlay network if you need to access your AetherFlow dashboard without exposing ports directly to the public internet.

---

## Security Audit Logs
All critical administrative actions (app installation, user creation, 2FA reset) are logged in the `System Logs` tab.
- **Location**: Inspect via the UI or `journalctl -u aetherflow-api`.
- **Retention**: Configurable in the database settings table.
