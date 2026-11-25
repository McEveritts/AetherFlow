# Experimental YouTube Frontends

Piped and Invidious are experimental entries included in AetherFlow's 77-package bare-metal Marketplace catalog (no automatic `stable`-channel exclusion is applied). Both run as native bare-metal systemd installations rather than containers.

| App | Marketplace Port | Managed Services | Persistent Configuration |
| :--- | :--- | :--- | :--- |
| Piped | `8280` | `af-piped`, `af-piped-api`, `af-piped-proxy` | `/etc/piped` |
| Invidious | `8281` | `af-invidious`, `af-invidious-companion` | `/etc/invidious` |

Both apps bind to loopback behind AetherFlow's existing Apache/subdomain ingress. Configure the AetherFlow base domain and HTTPS before installation. Direct script users may set `AF_APP_DOMAIN` to the app's public hostname. `AF_APP_PORT` overrides the Marketplace port. Private companion ports are allocated separately and saved under `/etc/<app>` so reinstalls keep them stable.

## Requirements

- A Debian/Ubuntu server with `systemd` and PostgreSQL. Installation uses APT and requires `root`, internet access, and sufficient scratch disk/inodes (`af_prepare_job_scratch` preflight checks free space and inodes across the scratch root, `/opt`, `/var/lib`, and `/var/backups`, requiring at least `2048 MiB` and `16384` inodes for both Piped and Invidious) and RAM to compile upstream code.
- **Piped**: Requires an APT source providing Java 21, **Rust >= 1.89** (`installpackage-piped` installs APT `cargo`/`rustc` and checks root-owned `cargo`/`rustc` on `PATH` first, falling back to scanning root-owned rustup/cargo toolchains under `/root/.rustup/toolchains/*`, `/usr/local/rustup/toolchains/*`, `/opt/rust/toolchains/*`, `/root/.cargo/bin`, and `/usr/local/cargo/bin`, failing closed otherwise), Node 24+, and `pnpm@10.11.0`, built on the Linux host only. It runs a dedicated unprivileged Apache instance for static assets, SPA routing, `/api/`, and `/proxy/` without modifying main host vhosts.
- **Invidious**: Supports Linux `x86_64` and `aarch64`. Its local Crystal `1.22.2` toolchain and companion executable are downloaded from upstream releases with mandatory SHA-256 verification; Invidious itself is compiled from source.

The first installation can take several minutes. Builds run as dedicated service users. PostgreSQL roles, databases, and random credentials are created idempotently; credentials survive reinstall and are omitted from installer logs.

The Invidious companion uses a dedicated 16-character alphanumeric secret, separate from the database password and HMAC key. An incompatible saved `/etc/invidious/companion-key` halts installation rather than silently rotating; back up and remove that invalid key before retrying installation.

## Operations and Limitations

Registration is disabled by default. Use AetherFlow's authenticated ingress and do not expose internal API, proxy, or companion ports directly to the internet. These installers do not create or synchronize upstream application accounts.

Configuration and data live under `/etc/<app>` and `/var/lib/<app>` respectively; sources and binaries live under `/opt/<app>`. Logs are written to `/var/log/aetherflow/install-<app>.log` and the corresponding systemd journals. The install lock is written only after HTTP readiness, companion unit checks, and (for Piped) `certify_piped` verification of all three git HEADs, published JAR/binary SHA-256 digests, and `/proc/<pid>/exe` identity for `piped-proxy`.

- **Ordinary Uninstall (`DELETE_DATA=false`)**: Stops and disables the complete app stack and deletes its systemd unit/drop-in files while retaining `/opt/<app>`, `/etc/<app>`, `/var/lib/<app>`, service users, and PostgreSQL databases.
- **Explicit Purge (`DELETE_DATA=true` / `--purge` / `?purge=true`)**: Ensures `postgresql.service` is active, drops the app's PostgreSQL database and role (verifying removal), deletes `/opt/<app>`, `/etc/<app>`, and `/var/lib/<app>`, and purges the `<app>` system user via `purge_system_user`. Shared PostgreSQL, Apache, and language runtimes are never purged.
- **Update Tracking**:
  - **Invidious** tracks `iv-org/invidious` Git HEAD.
  - **Piped** tracks all three repositories (`TeamPiped/Piped`, `TeamPiped/Piped-Backend`, `TeamPiped/Piped-Proxy`) using a composite manifest `frontend:<sha>,backend:<sha>,proxy:<sha>` persisted in `/opt/piped/.af-version` and `/opt/piped/.af-components.json`. Any commit change in any of the three repositories flags an update, and exact-target installs (`PIPED_TARGET_VERSION` / `AF_TARGET_VERSION`) require all three component pins.

YouTube anti-bot checks, IP reputation, and upstream changes can break playback even when local services pass HTTP readiness checks. Local readiness does not establish working video playback. Review upstream Piped and Invidious documentation for additional proxy, token, or network settings, and treat both packages as experimental until validated on your host.

Upstream references:

- [Piped](https://github.com/TeamPiped/Piped)
- [Piped Backend](https://github.com/TeamPiped/Piped-Backend)
- [Piped Proxy](https://github.com/TeamPiped/Piped-Proxy)
- [Invidious](https://invidious.io/)
- [Native Invidious Installation](https://docs.invidious.io/installation/)
- [Invidious Companion](https://github.com/iv-org/invidious-companion)
