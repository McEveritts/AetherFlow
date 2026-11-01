# Network: WireGuard and Tailscale

The Network page manages the host's native WireGuard server and Tailscale node.
Install either package in Marketplace first. AetherFlow keeps the web API
unprivileged; VPN commands run through aetherflow-runner's local UNIX socket.
Installers preserve existing identities and start services without restarting an
already active tunnel.

## WireGuard clients

The managed interface is wg0, backed by /etc/wireguard/wg0.conf. Status reflects
the interface's real UP flag. A peer is active when its last handshake is within
180 seconds. Transfer rates use successive byte counters; a reset does not
produce negative traffic.

Choose Add Peer and generate a one-time client keypair, or paste a public key
generated on the client. Leave Tunnel Address blank to allocate an unused IPv4
host address in wg0's configured subnet. Names, addresses, endpoints and keepalive
are editable; public keys are immutable.

For generated keys, save the client configuration or scan its QR code after
enrollment. Set an endpoint reachable by the client, including the server's UDP
port. The page defaults to IPv4 full tunnel; split tunnel uses the selected
networks. The generated client private key is returned once, held in browser
memory for the handoff, and never persisted by the Network API. Closing the
handoff discards that copy. Editing a peer created elsewhere cannot recover its
client private key.

Peer changes are written atomically with mode 0600 and applied to the running
interface. Failed runtime changes restore the previous configuration. A stopped
interface can be edited; start it to activate those changes. Existing interface
hooks, pre-shared keys, administrator comments and other runtime peers are
preserved. Existing runtime-only peers are marked in the table; edit and save
them to make them persistent. SaveConfig=true must be disabled before using this persistent manager.

The installer initially uses 10.66.66.0/24 and creates a bootstrap client at
10.66.66.2. Its original root-only client/key files remain on the host for backward
compatibility. New page-generated clients use unused addresses and the one-time
handoff. Installer retries preserve both identities and administrator settings.

## Tailscale

Choose Connect / Login, then follow the authorization link. Reauthenticate starts
a new authorization flow. Disconnect stops Tailscale networking while retaining
the login; Logout removes the node's local login. If approval is required, use the
Tailscale Admin Console.

Advertised subnet routes are read back from the daemon. Routes can be added,
removed individually, or cleared with Clear All Routes. Advertising a route does
not approve it: approve routes and exit-node advertisements in the Tailscale
Admin Console or through your tailnet policy.

The page also controls accepting subnet routes, advertising the host as an exit
node, selecting an online exit-node device, and permitting local LAN access when
using one. Updating one preference preserves the others. Clearing subnet routes
preserves exit-node advertisements.

## Recovery and API

Provider state distinguishes missing packages, stopped services, missing
configuration, pending login/approval and operational errors. A missing runner
is reported explicitly. Diagnostics show bounded, sanitized service logs,
forwarding status and Tailscale connectivity checks. Start, Stop and Restart
operate only on wg-quick@wg0.service or tailscaled.service.

All endpoints live under /api/v1/admin/network and require an administrator
session; mutations require CSRF protection. Errors contain code and message.
Responses use Cache-Control: no-store. The unified status response is shared for
three seconds to avoid repeated CLI calls from compatibility endpoints.

| Endpoint | Methods | Purpose |
| --- | --- | --- |
| /status | GET | Both providers and their peers |
| /wireguard/peers | GET, POST | List or enroll a persistent peer |
| /wireguard/peers/:key | PUT, DELETE | Edit or remove a persistent peer |
| /wireguard/keygen | POST | One-time client keypair |
| /tailscale/status, /tailscale/peers | GET | Compatibility inventory endpoints |
| /tailscale/connect | POST | Connect or reauthenticate |
| /tailscale/disconnect, /tailscale/logout | POST | Disconnect or logout |
| /tailscale/routes | GET, POST | Read preferences or replace subnet routes; [] clears |
| /tailscale/settings | POST | Accept routes and manage exit-node preferences |
| /:provider/service | POST | Start, stop or restart an allowlisted VPN unit |
| /diagnostics?provider=wireguard\|tailscale | GET | Bounded operational diagnostics |

This manages incoming WireGuard clients. Importing a commercial VPN provider's
configuration, routing individual applications through an outbound tunnel, and
a kill switch are separate features.
