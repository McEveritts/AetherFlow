# Troubleshooting

This guide covers the most common ways to diagnose and resolve issues in AetherFlow. Because AetherFlow acts as an orchestrator sitting above your Linux host, troubleshooting often spans multiple layers.

The goal is to help you move from a visible symptom to the root cause quickly and predictably.

---

## Where to Look First

When something breaks, do not guess. Look at the raw output.

### 1. Application Logs
AetherFlow writes application-specific output to its dedicated log directory:
```bash
/var/log/aetherflow/
```
Check `error.log` for backend panics, routing failures, or failed database initialization. For marketplace components, look for `install.log`.

### 2. The `systemd` Journal
AetherFlow processes are native `systemd` units. To see what the operating system believes is happening, check the journal:
```bash
sudo journalctl -u aetherflow-api -n 100 --no-pager
sudo journalctl -u aetherflow-web -n 100 --no-pager
```

> [!TIP]
> Use `-f` instead of `-n 100` to stream real-time logs across your terminal if reproducing a bug.

---

## Common Issues

### 1. Dashboard Stuck on "System Offline"
**Symptom**: The React frontend loads, but the dashboard displays restricted layouts and "System Offline" text.
**Cause**: The UI has lost its WebSocket / REST connection to the Go backend.
**Resolution**:
1. Check if the API service is loaded: `systemctl status aetherflow-api`.
2. Inspect the port: `ss -tulpn | grep 8080`.
3. Check the browser console. If you see CORS errors or 401s, ensure your `aetherflow_session` cookie is not expired and `AF_DOMAIN` in your `.env` matches the domain you are visiting.

### 2. Marketplace "Command Not Found"
**Symptom**: A marketplace installation fails rapidly, and logs show syntax errors or `command not found`.
**Cause**: The script failed to source the `common.sh` helper library correctly, which supplies required functions like `print_error` and `require_root`.
**Resolution**:
Ensure the top of the package script uses:
```bash
source "$(dirname "$0")/../../common.sh"
```

### 3. Permission Errors / Action Pre-flight Fails
**Symptom**: Installing an app or attempting to restart a service from the UI triggers an immediate "unauthorized" or "permission denied" error.
**Cause**: The backend process is attempting an action that requires `sudo`, but the user `aetherflow` does not have sufficient NOPASSWD privileges.
**Resolution**:
Verify the sudoers drop-in file:
```bash
cat /etc/sudoers.d/aetherflow
# Should contain:
# aetherflow ALL=(ALL) NOPASSWD: ALL
```

---

## Frequently Asked Questions

**Q: I updated the code via git, but nothing changed. Why?**  
A: AetherFlow uses compiled assets. If you pulled new Go code, you must `go build` and restart `aetherflow-api.service`. If you pulled React code, you must `npm run build` and restart `aetherflow-web.service`.

**Q: I got locked out of 2FA. How do I regain access?**  
A: AetherFlow stores account data in SQLite. If you are locked out locally, use the CLI recovery tool, or (if strictly necessary) connect to `aetherflow.db` and delete the offending row in the `users` table, then force a re-registration flow.

**Q: Why is my root disk filling up quickly?**  
A: Check two areas: Docker (if you use Portainer/Marketplace containers) via `docker system df`, and `journald` size via `journalctl --disk-usage`. AetherFlow logs rotate automatically, but application data (like Plex metadata) can grow unbounded if unmonitored.
