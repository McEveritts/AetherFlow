# Troubleshooting & FAQ

This guide covers diagnosing and resolving common operational issues in **AetherFlow v4.0.0**.

---

## Where to Look First

### 1. Systemd Service Journals
AetherFlow runs as two core `systemd` units (`aetherflow-api.service` and `aetherflow-runner.service`), plus transient `aetherflow-self-update.service` units during upgrades:

```bash
sudo systemctl status aetherflow-runner aetherflow-api
sudo journalctl -u aetherflow-api -u aetherflow-runner -n 100 --no-pager
```

> [!TIP]
> Pass `-f` to `journalctl` to stream logs in real time while reproducing an issue.

### 2. Application & Package Logs
Marketplace installation and self-update logs are written to `/var/log/aetherflow/`:

```bash
ls -la /var/log/aetherflow/
# Inspect a specific package installation log:
sudo tail -n 100 /var/log/aetherflow/install-<package>.log
```

### 3. Release & Recovery State (`af release status`)
Inspect the active `/opt/AetherFlow/current` symlink, live SQLite database path, and `.recovery_state.json` journal:

```bash
sudo af release status
curl -s http://127.0.0.1:8080/health/ready | jq
```

---

## Common Issues

### 1. Dashboard Displays "System Offline" or WebSocket Reconnect Loops
**Symptom**: The web UI loads, but telemetry widgets pause or display offline indicators.
**Cause**: `aetherflow-api.service` is stopped, Apache2 WebSocket proxy modules (`proxy_wstunnel`) are disabled, or the `Host` header is rejected by `ALLOWED_HOSTS`.
**Resolution**:
1. Verify `aetherflow-api` is listening on `127.0.0.1:8080`:
   ```bash
   sudo ss -tulpn | grep 8080
   ```
2. Check `/etc/aetherflow/aetherflow.env` and verify `ALLOWED_HOSTS` includes the domain or IP you are visiting, then restart:
   ```bash
   sudo systemctl restart aetherflow-api
   ```

### 2. Service Control or Package Installation Fails with Runner IPC Error
**Symptom**: Starting/restarting a service or installing an app from the Marketplace returns a runner socket error (`ExitCode = 3` in `af`).
**Cause**: `aetherflow-runner.service` is stopped or `/run/aetherflow/runner.sock` permissions do not match `0660 root:aetherflow`.
**Resolution**:
```bash
sudo systemctl restart aetherflow-runner
ls -l /run/aetherflow/runner.sock
# Expected: srw-rw---- 1 root aetherflow ... /run/aetherflow/runner.sock
```

### 3. Self-Update Blocked by Unfinished Recovery Journal
**Symptom**: Starting a system update reports that a previous post-swap deployment was interrupted and requires rollback.
**Cause**: The native `af-release` guard intentionally refuses to overwrite `.previous_release` if an earlier update stopped after swapping `/opt/AetherFlow/current`.
**Resolution**:
Run a rollback to restore the previous known-good release and verify database integrity before deploying again:
```bash
sudo af release rollback --local
sudo af release status
```

### 4. `AES_MASTER_KEY` Validation Error on Startup
**Symptom**: `aetherflow-api.service` fails to start with an invalid `AES_MASTER_KEY` length error.
**Cause**: `AES_MASTER_KEY` in `/etc/aetherflow/aetherflow.env` must be either a raw 32-byte string or a Base64-encoded 32-byte key (not a 64-character hex string).
**Resolution**:
```bash
openssl rand -base64 32
```
Set `AES_MASTER_KEY=<base64-value>` in `/etc/aetherflow/aetherflow.env` and restart `aetherflow-api`.

> [!CAUTION]
> Rotating `AES_MASTER_KEY` invalidates previously encrypted secrets (`enc:v1:`) in SQLite. Re-enter AI provider keys in **Settings → FlowAI Engine** after rotating.

### 5. `readonly database` or McBrowser Storage Permission Errors
**Symptom**: Authenticated writes or McBrowser uploads fail with permission or read-only filesystem errors.
**Cause**: `aetherflow-api.service` runs under `ProtectSystem=strict`. Any custom database path (`AF_DB_PATH`) or custom McBrowser storage root (`AF_MCBROWSER_ROOT`) outside `/var/lib/aetherflow` must be owned by `aetherflow:aetherflow` and listed in the unit's `ReadWritePaths`.
**Resolution**:
1. Keep data in the standard `/var/lib/aetherflow` directory (`StateDirectory=aetherflow`), or add custom paths via `sudo systemctl edit aetherflow-api.service`:
   ```ini
   [Service]
   ReadWritePaths=/var/lib/aetherflow /your/custom/path
   ```
2. Reload and restart:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart aetherflow-api
   ```

### 6. APT / `dpkg` Lock Contention During Package Installation
**Symptom**: A Marketplace installation waits or fails because another package manager process holds `/var/lib/dpkg/lock-frontend`.
**Cause**: Unattended OS upgrades or a concurrent manual `apt` command is running.
**Resolution**:
AetherFlow serializes Marketplace operations behind `/install/.af-package-executor.flock` and waits up to 120 seconds (`DPkg::Lock::Timeout=120`). If an orphaned `apt` process is stuck, inspect with `ps aux | grep apt` and run `sudo dpkg --configure -a` once it finishes.

---

## Frequently Asked Questions

**Q: Why is there no `aetherflow-frontend.service` or `redis-server` required in v4.0.0?**  
**A:** AetherFlow v4.0.0 embeds the compiled Next.js 16 (Obsidian V2) static export directly inside the `aetherflow-api` Rust binary (`rust-embed`) and persists JWT revocation and session state directly in bundled SQLite WAL (`af-db`). Separate Node.js and Redis daemons are no longer needed.

**Q: How do I recover if I lose my 2FA authenticator device?**  
**A:** Sign in using one of the one-time recovery codes generated during 2FA enrollment, or reset TOTP from the host with root access to `/var/lib/aetherflow/aetherflow.sqlite`.

**Q: Does uninstalling a Marketplace app delete my media or databases?**  
**A:** No. By default, Marketplace removal stops and removes the `systemd` unit and application binaries while preserving configuration and databases. Data is only purged if you explicitly confirm **Delete Data** (`DELETE_DATA=true`).
