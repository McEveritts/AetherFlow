AetherFlow Application Installer and Removal Packages

## Remote bootstrap integrity

`fetch_and_run` executes downloaded Bash scripts only after a matching, pinned
64-hex SHA-256 digest is verified. Empty, malformed, and `SKIP` checksums are
rejected. Verified URLs and digests are written to the lifecycle log as
`[BOOTSTRAP-PROVENANCE]` entries before execution.

Pi-hole uses `AF_PIHOLE_BOOTSTRAP_SHA256` (defaulting to the reviewed upstream
Pi-hole v6.5 `basic-install.sh` SHA-256 digest `0c67c8f8358fede4b4dd8d51b429114461c9bb90ad56ff00ef05637f664bf3ac`);
the NodeSource fallback uses `AF_NODESOURCE_BOOTSTRAP_SHA256` (defaulting to the
reviewed upstream NodeSource 20.x setup SHA-256 digest `2c4c6683a17b6f4128898a7b521e3c8bb725a99ffaf1b5e32ac97c6fa7d381be`).
Changed upstream content fails closed until its reviewed pin is updated. The
Netdata fallback requires `NETDATA_KICKSTART_SHA256` explicitly.

## Package artifact verification

`verify_download_sha256` rejects empty downloads and HTML error pages. It verifies
configured `AF_DOWNLOAD_SHA256`, `AF_<APP>_SHA256`, `AETHERFLOW_<APP>_SHA256`, and
local checksum manifests, and attempts upstream `.sha256` / `.sha256sum` files.
Set `AF_REQUIRE_DOWNLOAD_SHA256=1` to reject downloads without a matching digest.
Without that policy, digest-less downloads must pass archive, Debian package,
ELF, script, or OpenPGP-key validation; the log explicitly distinguishes format checks
from cryptographic verification. A locally computed digest is not upstream proof.

Bootstrap passwords and API keys travel through environment variables, stdin, or
private configuration files, never external command arguments. Servarr instances
with no authentication are initialized even when retaining existing credentials;
already configured accounts are preserved. Duplicati reads its password directly
from its protected environment file rather than interpolating it into `ExecStart`.

## Application state

Ordinary uninstall retains application configuration and operator data. Explicit
`DELETE_DATA=true` removes the application's canonical state, including its
`/var/lib/<catalog-name>` directory, without removing unrelated operator files.
The catalog lifecycle matrix seeds application-specific state before installation
and checks preservation through update, reinstall, ordinary uninstall, and
reinstallation, then checks deletion only on explicit purge.

Explicit purge also removes installer transaction backups named
`/var/backups/aetherflow-<catalog-name>` and
`/var/backups/aetherflow-<catalog-name>.*`, including known legacy aliases.
Ordinary uninstall retains these backups; similarly prefixed backups belonging
to another application are not selected.

The application's system user and group are retained with its data. Account
deletion is gated by `DELETE_DATA=true` both in the removers and in the shared
`purge_system_user` helper; an explicit `--force` argument to that helper is the
only account-only override. Remote desktop updates preserve operator startup
scripts, and Audiobookshelf keeps its vendor defaults and systemd port aligned.

## Migration rollback

Managed PostgreSQL installers save a logical dump of the application database
before migration. Failed activation restores only that database before restarting
the old application; it does not stop or restore the shared PostgreSQL cluster.
Keep application database writers quiesced throughout migration and recovery.
Failed restoration leaves the application stopped and retains the private
recovery directory for operator intervention instead of discarding its only backup.

For retained Nextcloud and Gitea PostgreSQL databases, recovery uses the configured
database owner and one transaction inside the existing database, without requiring
global `CREATEDB` privileges. Recovery is rehearsed before migration and fails
closed for unsupported ownership, privileges, extensions, or other database
features. This is in-process recovery, not a crash-durable database transaction
coordinator; external roles and extension availability must remain stable.

SQLite-backed archive and custom rollback-capable installers snapshot application
state after stopping the service, including database sidecars, and restore it
before restarting the prior runtime on failed activation. Temporary custom
transaction backups are discarded after success. Maintainerr and Jellyseerr keep
the current and one preceding completed-success backup, with private completion
markers written only after readiness, receipts, and installation locks succeed.
Failed, interrupted, unmarked legacy, or otherwise untrusted backups are never
automatically pruned; operators must reconcile these separately. A retention
failure emits a warning and preserves recovery copies. Paperless snapshots its
complete application data directory. Nextcloud and Gitea inspect their retained
database configuration before migration: MySQL/MariaDB and PostgreSQL require a
successful, nonempty dump of the configured database, while SQLite files and
their journal sidecars are snapshotted, including files outside application state.
Navidrome safely parses the retained TOML `DataFolder` (including paths relative
to its managed `/var/lib/navidrome` working directory) and snapshots that SQLite
database and its sidecars after stopping the service. Invalid TOML, ambiguous
case-insensitive `DataFolder` keys, and symlink or hardlink aliases fail before
runtime or service mutations. The dependency step installs distribution
`python3-toml` for older Python versions; Python 3.11+ uses standard `tomllib`.
Unknown database backends, unsafe names, and failed backups abort migration.
Rollback restores that database before restarting the old runtime and never
substitutes a hardcoded database name. Apache-backed installers
stop the shared web service while snapshotting and activating their runtime, so
schedule these operations during a maintenance window. Config metadata writes validate
single-link regular files; recursive ownership changes never follow symlinks.

HTTP applications verify their effective listener before publishing version or
install receipts. Servarr checks and authentication bootstrap retain `UrlBase`;
Bazarr, Tautulli, and SABnzbd checks also honor retained URL prefixes and bind
addresses. Removers route recursive tree deletion through `safe_rm_rf`, which
unlinks top-level symlinks without following them and refuses mount points and
symlinked parents. The legacy shell CLI requires an install lock for updates;
`remove`/`uninstall` retain data unless `--purge` is explicit.

Local Debian package installation retries `dpkg -i` after dependency repair and
requires an installed dpkg status and the payload's exact package version before
publishing a receipt. Git checkouts without tags use their commit identifier, or
the retained version receipt if Git cannot identify HEAD. Empty managed version
receipts are rejected. Servarr and Jackett receipts prefer the newly installed
executable's reported version over moving-release metadata. Jellyfin and KasmVNC
also publish persistent receipts only after readiness, and remove them on uninstall.
APT/DEB rollback snapshots include application runtime trees and entrypoints as well
as state/configuration; this restores those files, not the global dpkg database.
Nextcloud retains operator extensions missing from the new bundled `apps` tree,
including through retained-data uninstall.

## Legacy CLI

`packages/system/af` delegates to an executable `AETHERFLOW_CLI_BIN`,
`/usr/local/bin/af-cli`, or `/opt/AetherFlow/bin/af-cli`, in that order. Set
`AETHERFLOW_USE_RUNNER=1` to reject the legacy fallback when no compiled CLI is
available. Minimal installations without the compiled CLI serialize their Bash
fallback with `/opt/AetherFlow/logs/maintenance.lock`.
