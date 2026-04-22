# Upgrading Guide

This guide covers the migration paths for AetherFlow, with a specific focus on the transition from legacy QuickBox setups and the major architectural shift to `systemd` in the v3.1.x line.

## Upgrade Channels

AetherFlow maintains two primary release tracks:

| Channel | Source | Stability | Use Case |
| :--- | :--- | :--- | :--- |
| **Stable** | GitHub Releases | High | Production servers, standard users. |
| **Beta** | Git Tags | Medium | Early access to new Marketplace apps and UI features. |

To switch channels, visit the **System Settings** tab in your dashboard and select the desired `Updater Track`.

---

## Migration: v3.0.x to v3.1.x

The v3.1.x release represents a turning point in platform stability and performance.

### 1. The systemd Migration
In v3.1.2+, AetherFlow has officially migrated from **PM2** to **systemd** for service management. This change is handled automatically by the updater, but requires a one-time reboot of the dashboard services.

> [!WARNING]
> **PM2 Zombie Processes**: The automated migration does not guarantee that pre-existing PM2 daemons are fully terminated. If leftover `next-server` or `node` processes continue to hold port 3000, the new systemd units will crash with `EADDRINUSE`. After upgrading, verify no orphaned processes remain:
> ```bash
> sudo ss -tulpn | grep ':3000'
> pm2 kill 2>/dev/null   # Safe to run even if pm2 is not installed
> ```
> See [Troubleshooting §5](./troubleshooting.md) for the full resolution procedure.

**Post-Update verification:**
```bash
# Verify the new systemd units are active
sudo systemctl status aetherflow-api aetherflow-frontend
```

### 2. Legacy PHP Removal
Starting with v3.1.0, support for legacy PHP-based dashboard components has been entirely removed.
- **Action Required**: If you have custom PHP scripts in the webroot, they will no longer function via the AetherFlow proxy. Migrate these to external services or port them to the new Go API.

---

## Technical Migration Steps

If you are performing a manual upgrade:

1. **Backup State**: Copy your SQLite database and `.env` file to a safe location.
2. **Fetch Source**:
   ```bash
   git fetch --all
   git checkout tags/v3.1.7
   ```
3. **Rebuild Backend**:
   ```bash
   cd backend
   go build -o aetherflow-api
   ```
4. **Rebuild Frontend**:
   ```bash
   cd frontend
   npm install && npm run build
   ```
5. **Update Services**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart aetherflow-api aetherflow-frontend
   ```

---

## Rollback Procedure

In the event of a catastrophic upgrade failure:

### 1. Database Rollback
AetherFlow creates a schema snapshot (`aetherflow.sqlite.bak`) before applying migrations. To restore:
```bash
cp /opt/AetherFlow/backend/aetherflow.sqlite.bak /opt/AetherFlow/backend/aetherflow.sqlite
```

### 2. Service Rollback
If the new binaries fail to start, you can revert to the previous Git tag and restart services.

---

## FAQ: Upgrading

**Q: Will my installed marketplace apps be deleted during an update?**  
**A:** No. AetherFlow updates only affect the core dashboard and API. Your marketplace applications (Plex, qBittorrent, etc.) are managed by independent systemd units and will remain untouched.

**Q: Do I need to re-scan my 2FA QR code after updating?**  
**A:** No. Your TOTP secrets are stored in the persistent database. As long as your `AES_MASTER_KEY` remains the same, your 2FA will continue to work.

> [!WARNING]
> Always ensure your server has at least **1GB of free disk space** before initiating an update to allow for binary compilation and database backups.
