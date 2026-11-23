# Peer clustering

Use **Cluster** on each server to establish a WireGuard link, check peer health, edit the remote endpoint, and manage access between linked servers. The dashboard URL is `/?tab=cluster`. Migration 26 removes legacy master/worker enrollment and command tables. Pair previously enrolled servers again through the Cluster tab.

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

## Planned storage and transcoding controls

- **Exports and mounts (P7).** Select the folder and peer tunnel address for each NFS export. Read-only is the default. Select read-write only for folders where the remote server must make changes. Configure media libraries to use a subfolder inside the peer mount. AetherFlow checks the WireGuard handshake and the mount's sentinel to decide when to stop or restore the mount.
- **Jellyfin transcoding (P8 and P9).** Install matching Jellyfin 12.4 and `jellyfin-ffmpeg` packages on the controller and worker. Enable the worker and run the parity test before trying remote jobs. Worker eligibility checks the grant, link health, FFmpeg version, encoder support, and available job slots. The shim uses the local FFmpeg binary for probes and when remote work cannot start.

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
| `PEER_SCOPE_DENIED` | Check the grant on the server receiving the request. A change requires write access to its area. |
| `PEER_ROUTE_UNCLASSIFIED` | Use a supported peer management operation or perform the task on the server directly. |
| `LINK_DOWN`, `LINK_REVOKED` | Check the selected endpoint and the other server's Cluster page. Revoke any stale link before pairing again. |

If the receiving server reports an expired confirmation while the initiating server already shows an active or down link, revoke that link on the initiating server before opening a new window. If the runner reports an uncertain WireGuard outcome, use the request ID to inspect the logs and reconcile `afpeer0` before re-pairing.

[Peer API reference](API.md#8-peer-clustering) · [Configuration settings](configuration.md)
