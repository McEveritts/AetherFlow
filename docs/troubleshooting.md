# Troubleshooting & FAQ

This guide covers diagnosing and resolving common operational issues in **AetherFlow v4.0.0**.

---

## Where to Look First

### 1. Systemd Service Journals

AetherFlow runs two core `systemd` units (`aetherflow-api.service` and `aetherflow-runner.service`), plus dynamic transient units named `aetherflow-self-update-<command>-<channel>-<8hex>.service` during self-updates and `af-transcode-worker.service` on hosts enabled as distributed Jellyfin transcode workers:

```bash
sudo systemctl status aetherflow-runner aetherflow-api
sudo journalctl -u aetherflow-api -u aetherflow-runner -n 100 --no-pager
sudo journalctl -u 'aetherflow-self-update-*' -n 100 --no-pager
# Optional (Peer Clustering transcode workers only):
sudo systemctl status af-transcode-worker.service
```

> [!TIP]
> Pass `-f` to `journalctl` to stream logs in real time while reproducing an issue.

### 2. Application, Package & Deployment Logs

Marketplace installation/removal logs, self-healing logs, and release deployment logs live under `/var/log/aetherflow/`:

```bash
ls -la /var/log/aetherflow/
# Inspect package installation, removal, or deployment logs:
sudo tail -n 100 /var/log/aetherflow/install-<package>.log
sudo tail -n 100 /var/log/aetherflow/remove-<package>.log
sudo tail -n 100 /var/log/aetherflow/deploy.log
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

**Cause**: `aetherflow-api.service` is stopped, Apache2 WebSocket proxy modules (`proxy_wstunnel`) are disabled, `BIND_ADDR` does not match the Apache reverse proxy target, or the `Host` header is rejected by `ALLOWED_HOSTS`.

**Resolution**:

1. Verify `aetherflow-api` is listening (bare `aetherflow-api` defaults to `0.0.0.0:8080`; `AetherFlow-Setup` configures `BIND_ADDR=127.0.0.1` and `PORT=8080` behind Apache2):
   ```bash
   sudo ss -tulpn | grep 8080
   ```
2. Check `/etc/aetherflow/aetherflow.env` and verify `ALLOWED_HOSTS` includes the domain or non-loopback LAN/public IP you are visiting (`host_validation_middleware` rejects unlisted non-loopback IP literals with `400 INVALID_HOST`), then restart:
   ```bash
   sudo systemctl restart aetherflow-api
   ```

### 2. Service Control or Package Installation Fails with Runner IPC Error

**Symptom**: Starting/restarting a service or installing an app from Marketplace returns a runner socket error (`ExitCode = 3` in `af`).

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

**Cause**: `AES_MASTER_KEY` in `/etc/aetherflow/aetherflow.env` must represent 32 bytes (256 bits) of key material encoded as a 64-character hexadecimal string, a Base64-encoded 32-byte key, or a raw 32-byte ASCII string.

**Resolution**:

```bash
openssl rand -hex 32
```

Set `AES_MASTER_KEY=<64-hex-value>` (or a 32-byte `openssl rand -base64 32` value) in `/etc/aetherflow/aetherflow.env` and restart `aetherflow-api`.

> [!CAUTION]
> Rotating `AES_MASTER_KEY` invalidates **all** `enc:v1:` secrets, including AI provider keys (**Settings → FlowAI Providers**), enrolled 2FA secrets (`users.totp_secret` — which can lock out TOTP-enrolled accounts until reset), streaming server API keys (`streaming_servers.api_key`), notification channel configurations (`notification_channels.config`), `/var/lib/aetherflow/.master.creds`, and SQLite `system_config.master_credentials`. Back up the previous key before rotating and re-enter affected credentials afterward.

### 5. `readonly database` or McBrowser Storage Permission Errors

**Symptom**: Authenticated writes or McBrowser uploads fail with permission or read-only filesystem errors.

**Cause**: `aetherflow-api.service` runs under `ProtectSystem=strict`. The unit pre-configures `ReadWritePaths` for `/var/lib/aetherflow`, `/var/log/aetherflow`, `/run/aetherflow`, and optional mounts `-/srv`, `-/mnt`, `-/media`, `-/data`, and `-/opt/AetherFlow/backend/data`. Any custom `AF_DB_PATH` or `AF_MCBROWSER_ROOT` outside those paths must be owned by `aetherflow:aetherflow` and added to `ReadWritePaths`.

**Resolution**:

1. Keep data in `/var/lib/aetherflow` (`StateDirectory=aetherflow`) or under one of the pre-configured paths, or add custom paths via `sudo systemctl edit aetherflow-api.service`:
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

AetherFlow serializes concurrent Marketplace operations behind `/install/.af-package-executor.flock` across both executors, and both the 9 opt-in declarative Rust recipes (`AETHERFLOW_ENABLE_RUST_PACKAGES=1`) and the default Bash `apt-get()` / `rollback_apt_packages()` wrappers (`packages/lib/versions_apt.sh`) inject `-o DPkg::Lock::Timeout=<N>` (default `120` seconds) to wait for transient external `apt`/`dpkg` locks. If an external unattended upgrade exceeds the timeout or an orphaned `apt` process is stuck, inspect it with `ps aux | grep apt` and run `sudo dpkg --configure -a` once it finishes.

### 7. Peer Clustering, `afpeer0` WireGuard & Distributed Transcoding Issues

**Symptom**: Pairing fails with `INVALID_REQUEST` / `ENDPOINT_UNREACHABLE` / `KEY_MISMATCH`, peer NFS mounts stall, or Jellyfin transcode jobs fall back locally instead of running on a paired worker.

**Resolution**:

1. Inspect the full redacted link, WireGuard handshake, grant, mount, transcode worker, and audit snapshot with the read-only CLI diagnostic command:
   ```bash
   sudo af cluster diagnose <link>
   sudo wg show afpeer0
   sudo systemctl status af-transcode-worker.service
   ```
2. **Private LAN/VLAN Pairing (`INVALID_REQUEST`)**: Pairing blocks RFC 1918, CGNAT (`100.64.0.0/10`), and IPv6 ULA (`fc00::/7`) HTTPS origins by default. Set `AF_PEER_ALLOW_PRIVATE_PAIRING_URLS=true` in `/etc/aetherflow/aetherflow.env` on the initiating server and restart `aetherflow-api.service`.
3. **Request Correlation**: Every peer error banner in **Cluster** includes `request_id` (`X-Request-ID`); grep that ID across both `sudo journalctl -u aetherflow-api` and `sudo journalctl -u aetherflow-runner`.
4. **Upgraded Jellyfin Controller Sandbox**: If Jellyfin was installed before v4.0.0 Peer Clustering, refresh its sandbox drop-in once (`sudo af sandbox apply jellyfin && sudo systemctl restart jellyfin.service`) so `-/run/aetherflow-transcode` is mounted.

For the full error-code reference and recovery runbooks (including `afpeer0` identity reset, orphaned peer cleanup, and post-backup-restore reconciliation), see [Peer Clustering — Troubleshooting](./peer-clustering.md#troubleshooting).

---

## Frequently Asked Questions

**Q: Why is there no `aetherflow-frontend.service` or `redis-server` required in v4.0.0?**  
**A:** AetherFlow v4.0.0 serves the compiled **Leptos Rust WebAssembly (`frontend-rs`)** UI directly from external `web/dist` (`STATIC_DIR`) via `aetherflow-api`, and persists JWT revocation and session state directly in bundled SQLite WAL (`af-db`). Separate Node.js and Redis daemons are no longer needed for the core control plane.

**Q: How do I recover if I lose my 2FA authenticator device?**  
**A:** Sign in using one of the one-time recovery codes generated during 2FA enrollment, or reset TOTP on the host with root access to `/var/lib/aetherflow/aetherflow.sqlite` (stopping `aetherflow-api.service` or running `sqlite3` as `sudo -u aetherflow` so WAL/SHM files stay owned by `aetherflow`).

**Q: Does uninstalling a Marketplace app delete my media or databases?**  
**A:** No. By default, Marketplace removal stops and removes the `systemd` unit and application binaries while preserving configuration and databases. Data is purged only when you explicitly request purge: check **"Permanently purge application data (?purge=true)"** and type the package ID in the Marketplace UI, pass `?purge=true` on the uninstall HTTP endpoint (ambient `DELETE_DATA` environment variables are ignored by the HTTP API), or run `sudo af package remove <package> --purge`.
