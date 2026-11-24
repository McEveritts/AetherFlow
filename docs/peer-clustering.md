# Peer clustering

Use **Cluster** on each server to establish a WireGuard link, check peer health, edit the remote endpoint, manage access, and share media folders with linked servers. The dashboard URL is `/?tab=cluster`. Migration 26 removes legacy master/worker enrollment and command tables. Pair previously enrolled servers again through the Cluster tab.

## Before pairing

- Sign in as an administrator on both servers. Use the receiving server's trusted HTTPS address for the pairing request. Synchronize both clocks.
- Verify UDP 51821 between the two WireGuard endpoints, or the configured `AF_PEER_WG_PORT`. Restrict any firewall rule to the intended peers. Prefer their VLAN addresses when both servers can reach them.
- Choose a peer tunnel subnet that avoids existing host and VPN routes. The default is `10.231.0.0/16`. The peer listener uses TCP 9443 on the local tunnel address by default.
- A standalone server keeps the peer listener dormant. The privileged runner initializes peer networking on `afpeer0` when needed for pairing. The Network tab continues to manage `wg0` independently.

## Pair two servers

1. On the receiving server, open **Cluster** and choose **Allow a server to manage this one**. Review the advertised HTTPS address and select the WireGuard endpoint the other server can reach.
2. Open the window and copy its pairing string. Share it only with the intended administrator. It is single-use and expires after ten minutes.
3. On the initiating server, choose **Pair with a server**. Paste the pairing string and select the local WireGuard endpoint that the receiver can reach.
4. Compare the six-digit codes on both dashboards. On the receiving server, select **Approve & link** when the codes match. Cancel the attempt if they differ.
5. Check the link state on both servers. The Cluster tab reports status, software version, peer protocol compatibility, and RTT when available.

You can close an unused pairing window or cancel a pending attempt from Cluster. The pairing uses the endpoint selected on each server. Use **Edit endpoint** if the peer moves to another address. Confirm the change and check that link health recovers.

## Revoke a link

Choose **Revoke link** and confirm. This disables authorization for the link, clears its credentials, and removes the WireGuard peer that AetherFlow created for it. The other server will report revocation when it receives the notice. If the notice cannot be delivered, the other server reports the link down after health checks fail.

## Grant access to a linked peer

Open the peer's grant editor in **Cluster** on the server whose resources you want to share. Select none, read-only, or read-write for each area. The **Read-only (everything)** and **Read and write (everything)** presets fill all eight areas. Review the selection before saving.

The editor shows access in both directions. To set up reciprocal access, send a grant offer from the editor. This prompts the administrator on the other server to choose and save their own grant there.

You can revoke the access you granted from the same editor. The link continues reporting health, and any access the peer granted to this server stays in effect.

## Manage another server

The other server must grant this server access. When the link is healthy and supports remote management, select that server in the dashboard header or open it from Cluster. The identity bar shows which server the dashboard is managing. Use **Exit to this server** to return to your local dashboard.

A remote dashboard uses the access that the selected server granted to this server. Read access lets you inspect the corresponding area. Changes require write access to every affected area. The selected server's name appears in destructive confirmations.

Sign-in, session management, pairing, and grant administration stay on the local server. Third-party app links open on the selected server's own host. If the selected server stops responding, check its Cluster link or return to the local dashboard. A long-running job started on a peer runs on that peer and continues if the dashboard disconnects. Reopen the job status on the same peer before retrying an operation with an uncertain outcome.

Revoking the grant blocks remote management on the receiving server and closes its peer management WebSockets. Link health remains available.

## Share a media folder through a peer link

1. On the server that holds the media, open **Cluster**, select the peer, and export the folder containing the library subfolder. AetherFlow limits the export to that peer's tunnel address. Read-only is the default. With read-write enabled, remote writes run as the folder owner.
2. On the server that will read the media, open the same link's storage controls and choose the export to mount. Request a writable mount only when the export permits writes and the receiving app needs them.
3. Configure the media app with a folder **inside** the mount, such as `/mnt/af-peers/<link>/<export>/library`. Use the path shown in Cluster. The interior folder disappears when the mount stops, so the app can distinguish a missing library from an empty one.

Cluster shows the mount state, the last error, and a latency warning when link RTT exceeds the configured threshold. AetherFlow checks both the WireGuard peer and a sentinel file on the mount. It stops the mount after two consecutive sentinel failures or on the first health check that detects the WireGuard peer has been removed. Health checks restore the mount when the link becomes usable again.

For a Plex library on a peer mount, turn off automatic trash emptying after scans. For Emby and the *arr apps, turn off automatic removal of missing items for peer-backed libraries. Jellyfin 12.4 uses the missing library path as the safeguard. The live Jellyfin scan and recovery check requires both servers.

## Distributed Jellyfin transcoding

AetherFlow offloads Jellyfin `ffmpeg` jobs across linked peers over the WireGuard tunnel without SSH keys or external wrappers, while falling back locally whenever no remote worker is eligible or reachable.

### Socket & user isolation

- **Jellyfin server (dispatcher)**: `aetherflow-api` binds `/run/aetherflow-transcode/transcode.sock` (`0660`, `aetherflow:jellyfin`) inside `/run/aetherflow-transcode` (`0750`, provisioned via `/etc/tmpfiles.d/aetherflow-transcode.conf`). Jellyfin's sandbox includes `-/run/aetherflow-transcode/transcode.sock` in `ReadWritePaths`.
- **Worker server**: `af-transcode-worker.service` runs as `User=jellyfin`, `Group=jellyfin`, `SupplementaryGroups=render video` and binds `/run/aetherflow-transcode-worker/worker.sock` (`0660`) inside `/run/aetherflow-transcode-worker` (`0750`).
- **API access without privilege escalation**: `/etc/systemd/system/aetherflow-api.service.d/20-aetherflow-transcode.conf` adds `SupplementaryGroups=jellyfin` and `ReadWritePaths=-/run/aetherflow-transcode -/run/aetherflow-transcode-worker` to `aetherflow-api.service`. `jellyfin` is never added to the privileged `aetherflow` group.

### Enable distributed transcoding

1. Install matching Jellyfin 12.4 and `jellyfin-ffmpeg` packages on both the Jellyfin server and each worker server.
2. On the **worker server**, grant the Jellyfin server `transcoding: write` (and optionally `updates: write` to allow one-click `jellyfin-ffmpeg` version alignment). Open **Cluster → Transcoding** and enable the local **Transcode worker service** (`af-transcode-worker.service`).
3. Ensure shared media and Jellyfin's transcode/temp/cache folders (`/var/cache/jellyfin/transcodes`, `/var/cache/jellyfin/af-tmp`, `/var/cache/jellyfin`) are visible at identical paths on the worker.
4. On the **Jellyfin server**, open **Cluster → Transcoding** and enable **Use paired servers for Jellyfin transcoding**. AetherFlow installs `/usr/lib/aetherflow/transcode/ffmpeg` (and symlinks `ffprobe` to `/usr/lib/jellyfin-ffmpeg/ffprobe`), writes `/etc/systemd/system/jellyfin.service.d/20-aetherflow-transcode.conf` (never editing the sandbox drop-in), restarts Jellyfin, verifies Jellyfin reports the shim path (rolling back automatically if not), and starts the dispatcher socket.
5. Enable each worker with its weight (`1..=100`) and max concurrent jobs (`1..=64`), and run the **2-second parity test**. The test encodes a generated test pattern on the worker into the shared transcode folder and reads it back locally before marking `parity_ok = true`.

### Eligibility, version alignment, and failure behavior

- **Eligibility**: A worker receives jobs only when it is enabled, its link is active with the `transcode` capability, its held grant includes `transcoding: write`, `parity_ok` is true, it is not in a 60-second unhealthy cooldown, its `jellyfin-ffmpeg` version matches the Jellyfin server, it advertises the required encoder and compatible DRM render node (rewritten automatically on the worker), and `active_jobs < max_jobs`.
- **Keeping `jellyfin-ffmpeg` aligned**: Both `/health` and tunnel `/health` report cached non-blocking `jellyfin-ffmpeg` package and encoder capabilities. When versions differ (including after automatic package updates), the worker becomes ineligible, jobs fall back locally, a notification is sent, and **Update to match** updates whichever server is older.
- **No duplicate encodes & hard-kill cleanup**: Probes (`-version`, `-encoders`, `-hwaccels`, etc.) always `exec` local `ffmpeg` directly. Before a complete `Start` frame reaches a worker, failures mark that worker unhealthy for 60 seconds and try another worker or return `RunLocal`. After a complete `Start` is sent, timeouts or mid-job drops exit non-zero without starting a duplicate local encode. Closing the shim socket without `Exit` (such as Jellyfin `SIGKILL`) or revoking the link/grant immediately sends `Signal(Kill)` and terminates the worker's `ffmpeg` process group. Job records are pruned automatically after 7 days.

## CLI diagnostics (`af cluster diagnose`)

Run `af cluster diagnose <link>` (matching link ID or name; add `--json` for structured output) to inspect a single peer end-to-end without exposing tokens or keys:

```bash
af cluster diagnose media-2
af cluster diagnose media-2 --json
```

The report prints link health and compatibility, live `afpeer0` WireGuard handshake age and byte counters, inbound and outbound grant summaries, NFS exports, NFS mounts with live unit status and `.af-peer-sentinel` probe results, transcode worker configuration and recent jobs, and the last 20 redacted audit entries for the link.

## Troubleshooting

Use the reported recovery action alongside the code. JSON API logs can include the request ID when `AF_LOG_FORMAT=json` is enabled.

| Code | Recovery |
| :--- | :--- |
| `CODE_EXPIRED`, `CODE_USED`, `WINDOW_CLOSED` | Open a new pairing window on the receiving server and use its new pairing string. |
| `CLOCK_SKEW` | Synchronize both server clocks, then retry. |
| `KEY_MISMATCH` | Compare the configured peer identity and both comparison codes. Cancel the pending attempt and begin a new pairing when the identity is verified. |
| `TUNNEL_IP_CONFLICT` | Check both peer CIDR settings and existing link addresses for overlap before pairing. |
| `ENDPOINT_UNREACHABLE`, `HANDSHAKE_TIMEOUT` | Verify each selected endpoint, UDP port, VLAN path, and tunnel listener readiness. |
| `VERSION_INCOMPATIBLE` | Verify that both servers support a common peer protocol and upgrade the older server as needed. |
| `RATE_LIMITED` | Wait for the `Retry-After` interval before submitting another request. |
| `PEER_BUSY` | Wait for the current peer operation to finish, then retry. |
| `PEER_SCOPE_DENIED` | Check the grant on the server receiving the request. A change requires write access to its area (for example, `transcoding: write` for remote transcode jobs and `updates: write` or `marketplace: write` to align `jellyfin-ffmpeg`). |
| `PEER_ROUTE_UNCLASSIFIED` | Use a supported peer management operation or perform the task on the server directly. |
| `LINK_DOWN`, `LINK_REVOKED` | Check the selected endpoint and the other server's Cluster page. Revoke any stale link before pairing again. |

If the receiving server reports an expired confirmation while the initiating server already shows an active or down link, revoke that link on the initiating server before opening a new window. If the runner reports an uncertain WireGuard outcome, use the request ID to inspect the logs and reconcile `afpeer0` before re-pairing. If transcode parity tests fail or remote jobs fall back locally, run `af cluster diagnose <link>`, verify `af-transcode-worker.service` is active on `/run/aetherflow-transcode-worker/worker.sock`, confirm `/run/aetherflow-transcode/transcode.sock` is reachable by `jellyfin`, and verify both servers run the exact same `jellyfin-ffmpeg` package version.

[Peer API reference](API.md#8-peer-clustering) · [Configuration settings](configuration.md)
