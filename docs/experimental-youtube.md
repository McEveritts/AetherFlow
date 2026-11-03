# Experimental YouTube frontends

Piped and Invidious are available in the `nightly` marketplace as experimental
packages. These are native bare-metal systemd installations, not containers.
They are not promoted to stable by this change.

| App | Marketplace port | Managed services | Persistent configuration |
| --- | --- | --- | --- |
| Piped | 8280 | `af-piped`, `af-piped-api`, `af-piped-proxy` | `/etc/piped` |
| Invidious | 8281 | `af-invidious`, `af-invidious-companion` | `/etc/invidious` |

Both apps bind to loopback behind AetherFlow's existing Apache/subdomain ingress.
Configure the AetherFlow base domain and HTTPS before installation. Direct script
users may set `AF_APP_DOMAIN` to the app's public hostname. `AF_APP_PORT` overrides
the marketplace port. Private companion ports are allocated separately and saved
under `/etc/<app>` so reinstall does not randomly change them.

## Requirements

- A Debian/Ubuntu server with systemd and PostgreSQL. Installation uses APT and
  requires root, internet access, and enough free disk/RAM to compile upstream code.
- Piped requires an APT source providing Java 21 and a sufficiently recent Rust
  compiler. Its frontend uses Node 24 or newer and pnpm, installed/built on the
  Linux server only. It runs a dedicated unprivileged Apache instance for static
  assets, SPA routing, `/api/` and `/proxy/`; it does not modify the main vhosts.
- Invidious supports Linux x86_64/aarch64 here. Its local Crystal 1.22.2 toolchain
  and companion executable are downloaded from upstream releases with mandatory
  SHA-256 verification. Invidious itself is built from source.

The first installation can take several minutes. Builds run as dedicated service
users. PostgreSQL roles, databases and random credentials are created idempotently;
credentials survive reinstall and are not included in installer output.

The Invidious companion uses a dedicated 16-character alphanumeric secret,
separate from the database password and HMAC key. An incompatible saved
`/etc/invidious/companion-key` stops installation rather than being silently
rotated; back up and remove that invalid key before retrying installation.

## Operations and limitations

Registration is disabled by default. Use AetherFlow's authenticated ingress and
do not expose the internal API/proxy/companion ports to the internet. These
installers do not create or synchronize an upstream application account.

Configuration and data live under `/etc/<app>` and `/var/lib/<app>` respectively.
Sources and binaries live under `/opt/<app>`. Logs are in
`/var/log/aetherflow/install-<app>.log` and the corresponding systemd journals.
The install lock is written only after HTTP readiness and companion unit checks.

Removal stops/disables the complete app stack and deletes its unit/drop-in files.
It deliberately retains configuration, sources, service users, PostgreSQL databases
and user data. It never purges the shared PostgreSQL, Apache or language runtimes.

Marketplace update tracking follows each frontend's Git HEAD. Reinstall refreshes
and rebuilds the complete stack, including companions; the frontend update badge
does not independently track every companion/toolchain release.

YouTube anti-bot checks, IP reputation and upstream changes can break playback
even when the local services are healthy. Local readiness is not a guarantee of
successful video playback. Review upstream Piped/Invidious documentation for
additional proxy, token or network configuration. Treat both packages as
experimental until clean-server installation and real playback have been tested.

Upstream references:
- Piped: https://github.com/TeamPiped/Piped
- Piped backend: https://github.com/TeamPiped/Piped-Backend
- Piped proxy: https://github.com/TeamPiped/Piped-Proxy
- Invidious: https://invidious.io/
- Native Invidious installation: https://docs.invidious.io/installation/
- Invidious companion: https://github.com/iv-org/invidious-companion
