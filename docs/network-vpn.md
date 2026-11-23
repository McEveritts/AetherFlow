# Network: WireGuard and Tailscale

The **Network** tab manages the host's native WireGuard server, Tailscale node, external subdomain ingress settings, and host network hardware inventory. Install `wireguard` or `tailscale` from Marketplace first. AetherFlow keeps the web API (`af-api`) unprivileged; privileged VPN and ingress operations execute through `aetherflow-runner.service` over `/run/aetherflow/runner.sock`. Installers preserve existing node identities and start services without restarting an already active tunnel.

## WireGuard Clients

The managed interface is `wg0`, backed by `/etc/wireguard/wg0.conf`. Interface status reflects the kernel `UP` flag, and a peer is considered active when its latest handshake is within 180 seconds. The API and UI report cumulative `transfer_rx` and `transfer_tx` byte counters only (per-interval transfer rates are not computed).

This panel manages incoming WireGuard client peers. Importing a commercial VPN provider configuration, routing individual applications through an outbound tunnel, and operating a kill switch are separate features outside this panel's scope.

### Enrolling and Managing Peers

> [!IMPORTANT]
> Disable `SaveConfig=true` in `/etc/wireguard/wg0.conf` before managing peers through AetherFlow; otherwise `wg-quick` can overwrite AetherFlow's edits when the interface stops.

- Select **Create Peer** to generate a one-time client keypair or paste a public key generated on the client. Leave **Assigned client address** blank to allocate an unused IPv4 host address within `wg0`'s configured subnet (the Edit modal labels this field **Client addresses** and the table column is **Client IPs**). Peer names, tunnel addresses, endpoints, and keepalive intervals are editable; public keys are immutable.
- For generated keys, download the client configuration or scan its QR code immediately after enrollment. Specify a server endpoint reachable by the client, including the WireGuard UDP port. The form defaults to an IPv4 full tunnel (`0.0.0.0/0`); split-tunnel mode uses the configured networks. The generated client private key is returned once, held in browser memory for the handoff modal, and never persisted by the Network API. Closing the handoff discards it, and editing an existing peer cannot recover its private key.
- Peer changes sync to the running interface (`wg syncconf`) first (rolling back runtime state while leaving `/etc/wireguard/wg0.conf` untouched if sync fails), then atomically write `/etc/wireguard/wg0.conf` with mode `0600` (rolling back both disk and runtime if writing fails).
- **Stopped-interface behavior**: The `af-runner` API allows editing `/etc/wireguard/wg0.conf` while `wg0` is stopped (changes take effect when the interface starts), whereas the dashboard UI disables the **Create Peer** button until `wg0` reports status `"running"`.
- Existing interface hooks, pre-shared keys, administrator comments, and runtime-only peers are preserved. The API tags runtime-only peers with `"persistent": false` so callers can detect them and persist them via an edit/save call, though the current UI table does not render a separate persistence column.

### Installer Defaults

The WireGuard installer defaults to UDP port `51820` (overridable via `AF_APP_PORT`), configures subnet `10.66.66.0/24`, and creates a bootstrap client at `10.66.66.2` whose root-only client/key files remain on the host for compatibility. New dashboard-enrolled clients allocate unused addresses with the one-time handoff flow. Re-running the installer preserves existing keys and administrator settings.

## Tailscale

Install `tailscale` from Marketplace (`AF_TAILSCALE_AUTHKEY` / `TAILSCALE_AUTHKEY` is honored only when invoking `/opt/AetherFlow/current/packages/package/install/installpackage-tailscale` directly as root via `sudo env` or when configured in `aetherflow-runner.service`'s environment; Marketplace UI and `af package install tailscale` do not forward caller shell authkeys across `runner.sock`).

- Choose **Up / Interactive login** and follow the authorization URL, or use reauthentication to start a new authorization flow. **Down** stops Tailscale networking while retaining the local node login; **Logout** removes the local node login. If device approval is enabled on your tailnet, approve the node in the Tailscale Admin Console.
- **Advertised subnet routes**: Current advertised routes are read back from `tailscaled`. Enter a comma- or newline-separated CIDR list and click **Save advertised routes** to replace the advertised route set; submit an empty input (or `{"routes": []}` to `POST /api/v1/admin/network/tailscale/routes`) to clear all advertised routes. Advertising a route does not approve it—approve subnet routes and exit-node advertisements in the Tailscale Admin Console or tailnet ACL policy.
- **Exit node and routing preferences**: Toggle accepting subnet routes, advertising this host as an exit node, permitting local LAN access while using an exit node, or specifying an exit node in the free-text input. The runner validates the exit-node value strictly as an IP address (`IpAddr`) and rejects hostnames. Updating one preference preserves the others, and clearing subnet routes preserves exit-node advertisements.

## External Access & Host Network Inventory

In addition to VPN controls, the **Network** tab mounts:

- **External Access Settings (`<ExternalAccessSettings />`)**: Manages per-app subdomain ingress and TLS routing via `GET /api/v1/admin/ingress/configs` and `PUT /api/v1/admin/ingress/apps/:appName`, updating SQLite `app_ingress_configs` and triggering Apache2 Subdomain Gateway and Certbot SAN synchronization.
- **Host Network Hardware Inventory**: Displays host NIC/link inventory fetched from `GET /api/v1/auth/system/hardware`.

## Recovery and API

Provider status distinguishes missing packages, stopped services, missing configuration, pending login/approval, and operational errors; an unreachable `aetherflow-runner.service` is reported explicitly. Diagnostics return bounded, sanitized service logs, IP forwarding status, and Tailscale connectivity checks. Service lifecycle actions (`start`, `stop`, `restart`) operate strictly on `wg-quick@wg0.service` and `tailscaled.service`.

All VPN endpoints live under `/api/v1/admin/network`, require an active administrator session, enforce CSRF validation on mutations, return structured `{ code, message }` errors, and set `Cache-Control: no-store`. The unified status response is cached for 3 seconds to avoid repeated runner/CLI calls across compatibility endpoints.

| Endpoint | Methods | Purpose |
| :--- | :--- | :--- |
| `/api/v1/admin/network/status` | `GET` | Both VPN providers and their peers |
| `/api/v1/admin/network/wireguard/peers` | `GET`, `POST` | List or enroll a persistent WireGuard peer |
| `/api/v1/admin/network/wireguard/peers/:key` | `PUT`, `DELETE` | Edit or remove a persistent WireGuard peer |
| `/api/v1/admin/network/wireguard/keygen` | `POST` | Generate a one-time client keypair |
| `/api/v1/admin/network/tailscale/status`, `/tailscale/peers` | `GET` | Compatibility inventory endpoints |
| `/api/v1/admin/network/tailscale/connect` | `POST` | Connect (`Up / Interactive login`) or reauthenticate |
| `/api/v1/admin/network/tailscale/disconnect`, `/tailscale/logout` | `POST` | Disconnect (`Down`) or log out |
| `/api/v1/admin/network/tailscale/routes` | `GET`, `POST` | Read preferences or replace advertised subnet routes (`{"routes": []}` clears) |
| `/api/v1/admin/network/tailscale/settings` | `POST` | Configure route acceptance, exit-node IP, and LAN access |
| `/api/v1/admin/network/:provider/service` | `POST` | Start, stop, or restart `wg-quick@wg0.service` or `tailscaled.service` |
| `/api/v1/admin/network/diagnostics?provider=wireguard\|tailscale` | `GET` | Bounded operational diagnostics |
