# AetherFlow Application Installer and Removal Packages

## Package Layout & Shared Helper Architecture

Marketplace Bash lifecycle scripts under `packages/package/{install,remove}/` source `packages/common.sh`, which loads seven modular libraries under `packages/lib/` in order:

- `packages/lib/logging_archives.sh` — flock-coordinated `$LOGFILE` logging, `af_github_curl`, safe tar/zip validation/extraction, and `safe_rm_rf`.
- `packages/lib/versions_apt.sh` — APT transaction helpers, `node_build`, and `.af-version` receipt management.
- `packages/lib/state_downloads.sh` — hardened downloads, fail-closed SHA-256/SHA-512 verification, `begin_state_transaction`, `retain_successful_app_backups`, and `purge_app_backups`.
- `packages/lib/config_database.sh` — `stage_app_archive` / `finish_app_archive_update`, private `0600` config writers, path validation, and MySQL/PostgreSQL/SQLite migration backup/restore helpers.
- `packages/lib/apache_dns_locks.sh` — per-app Apache `503` maintenance vhosts, port-53 conflict checks, `/etc/resolv.conf` backup/write/restore, local DNS lookup verification, base-domain resolution (excluding `*.local`), `backup_file_once`, `fetch_and_run`, `write_lock`, and `remove_lock` (`.aether.local` hosts/DNS provider sync lives in `backend-rs/crates/af-runner/src/hosts_dns.rs`).
- `packages/lib/redaction_receipts.sh` — credential redaction, `report_progress` markers, `ensure_node`, `af_prepare_job_scratch`, and structured failure receipts (`af_write_failure_receipt`).
- `packages/lib/systemd_credentials.sh` — readiness probing (`wait_for_service_ready`), credential seeding/rotation, and systemd unit/account teardown.

Additional shared components:

- `packages/lib/cli_shim.sh` & `packages/system/*` — host compatibility shims forwarding to the compiled `af` CLI (`af`, `af-backup`, `af-sentinel.py`, `af-tune`, `clean_log`, `showspace`) plus retained host scripts (`af-certbot-sync`, `af-systemd-sandbox`, `setdisk`, `updateAetherFlow`).
- `packages/youtube-common.sh` — shared lifecycle and purge helpers for Piped and Invidious.
- [`docs/installpackage-template.sh`](../docs/installpackage-template.sh) — starter template for new installers (customize unit naming, `write_config_file`, loopback binding, and `af_github_curl` per [Marketplace Developer Guide](../docs/marketplace-developer-guide.md)).

---

## Remote Bootstrap Integrity

`fetch_and_run` executes downloaded Bash scripts only after a matching, pinned 64-hex SHA-256 digest is verified. Empty, malformed, and `SKIP` checksums are rejected. Verified URLs and digests are written to the lifecycle log as `[BOOTSTRAP-PROVENANCE]` entries before execution.

- **Pi-hole**: Uses `AF_PIHOLE_BOOTSTRAP_SHA256` and defaults to the reviewed upstream Pi-hole v6.6 `basic-install.sh` at commit `f7c0220e63e753c664a1ec08d42d6b647b86005d` (`SHA-256: 4627fc5209064039a3b2ee615119db93b2c9ca8f9d69dea7967b7fdf67df71c8`). Because upstream `basic-install.sh` advances Core, Web, and FTL together to their latest `master` release tags, Pi-hole is tracked as `update_source: "vendor"` and fails closed before state mutation if an exact `AF_TARGET_VERSION` pin is supplied.
- **Threadfin**: Pinned to exact release `1.2.37` with per-architecture SHA-256 digests (`Threadfin_linux_amd64_glibc_2.31_compat`, `Threadfin_linux_arm64`, and `Threadfin_linux_arm`) across both the Bash installer and the Rust declarative runner, failing closed before state mutation on unsupported or mismatched targets.
- **Listenarr (`Listenarrs/Listenarr`)**:
  - **Release Policy & Architecture**: Uses a Listenarr-scoped `prerelease` update channel because upstream currently publishes public GitHub prereleases only (zero stable releases) and Linux x64 (`amd64`) ZIP archives only (zero Linux ARM64 assets). Unsupported architectures or unavailable targets fail early before state mutation.
  - **Verification & Version Inspection**: Install, update discovery, and exact-target dispatch bind each selected release tag to its official `Listenarrs/Listenarr` `linux-x64.zip` URL and SHA-256 digest, inspecting installed versions via `/opt/Listenarr/.af-version` without executing `Listenarr.Api`.
  - **Config Storage**: Persists runtime configuration and SQLite data in `/var/lib/listenarr/config`, bind-mounted onto `/opt/Listenarr/config` via systemd `BindPaths=/var/lib/listenarr/config:/opt/Listenarr/config` (with safe legacy migration and rollback for pre-existing `/opt/Listenarr/config` directories).
- **NodeSource & Netdata**: NodeSource defaults to the scripts for Node 20, 22, and 24 at `nodesource/distributions` commit `42da07fa46a3e9649f47416743a5563f9f19028f`, each with its own SHA-256 pin (`AF_NODESOURCE_BOOTSTRAP_SHA256` selects `https://deb.nodesource.com/setup_<major>.x` and enforces the supplied digest). The Netdata kickstart fallback requires `NETDATA_KICKSTART_SHA256` explicitly.

---

## Package Artifact Verification

`verify_download_sha256` (`packages/lib/state_downloads.sh`) rejects empty downloads and HTML error pages and fails closed unconditionally when no cryptographic digest is available (`AF_REQUIRE_DOWNLOAD_SHA256` defaults to `1` in `packages/common.sh`, and there is no digest-less format-validation fallback):

- Verifies configured `AF_DOWNLOAD_SHA256`, `AF_<APP>_SHA256`, `AETHERFLOW_<APP>_SHA256`, pinned GPG key SHA-256 digests, local checksum manifests, GitHub release API `asset.digest`, upstream `.sha256`/`.sha256sum` files, and SHA-512 `checksums.txt` (used by Autoscan).
- Rejects missing digests (`Missing required SHA-256 digest for ...`). A locally computed digest is never treated as upstream proof.
- Passes bootstrap passwords and API keys through environment variables, stdin, or private `0600` configuration files, never external command arguments. Servarr instances with no authentication are initialized even when retaining existing credentials; already-configured accounts are preserved. Duplicati reads its password directly from its protected environment file rather than interpolating it into `ExecStart`.

---

## Application State & Retention

- **Retained Default vs. Explicit Purge**: Ordinary uninstall retains application configuration and operator data. Explicit `DELETE_DATA=true` removes the application's canonical state, including `/var/lib/<catalog-name>`, without removing unrelated operator files.
- **Transaction Backups**: Explicit purge also calls `purge_app_backups` via `remove_lock`, deleting `/var/backups/aetherflow-<catalog-name>` and `/var/backups/aetherflow-<catalog-name>.*` (including known legacy aliases). Ordinary uninstall retains these backups; similarly prefixed backups belonging to another application are untouched.
- **Service Accounts & Desktop Configs**: System users and groups are retained with application data. Account deletion is gated by `DELETE_DATA=true` in both removers and `purge_system_user` (`--force` is the only account-only override). Remote desktop updates preserve operator startup scripts, and Audiobookshelf keeps its vendor defaults and systemd port aligned.

---

## Migration Rollback & Operational Contracts

- **PostgreSQL Applications**: Managed PostgreSQL installers save a logical dump of the application database before migration. Failed activation restores only that database before restarting the prior runtime without stopping the shared PostgreSQL cluster. Keep database writers quiesced during migration/recovery; failed restoration leaves the app stopped and retains the private recovery directory. For retained Nextcloud and Gitea PostgreSQL databases, recovery runs in one transaction as the configured database owner (no global `CREATEDB` required) and fails closed on unsupported ownership, privileges, or extensions.
- **SQLite, Archive & Database-Backed Apps**:
  - SQLite-backed archive and custom rollback-capable installers stop the service, snapshot state including `-wal`/`-shm` sidecars, and restore it on failed activation. Temporary custom transaction backups (such as Palate's) are removed after success; Maintainerr and Jellyseerr call `retain_successful_app_backups` to retain the current and one preceding explicitly marked successful backup while never pruning unmarked/failed recovery copies.
  - Paperless snapshots its complete application data directory.
  - Nextcloud and Gitea derive retained database configuration (MySQL/MariaDB, PostgreSQL, or SQLite + sidecars) before migration, abort on unknown backends or failed backups, and never substitute hardcoded database names. Nextcloud also retains operator extensions missing from a new bundled `apps` tree across updates and retained-data uninstalls.
  - Navidrome parses its retained TOML `DataFolder` (including relative paths under `/var/lib/navidrome`) using `tomllib` (Python 3.11+) or `python3-toml`, rejecting invalid TOML, ambiguous case-insensitive keys, or symlink/hardlink aliases before snapshotting SQLite + sidecars.
- **Apache-Backed Installers**: Installers such as Nextcloud, Organizr, and ruTorrent call `apache_app_enter_maintenance` to swap only that application's vhost to a temporary `503` maintenance vhost, validate with `apache2ctl configtest`, and **reload** `apache2` without stopping unrelated Apache apps (falling back to stopping `apache2` only when per-app maintenance isolation is unavailable).
- **Config Safety & Readiness**: Config metadata writes validate single-link regular files; recursive ownership changes never follow symlinks. HTTP apps verify their effective listener before publishing receipts (Servarr retains `UrlBase`; Bazarr, Tautulli, and SABnzbd honor retained URL prefixes and bind addresses). `safe_rm_rf` unlinks top-level symlinks without following them and refuses mountpoints and symlinked parents.
- **Version Receipts & APT/DEB Rollback**:
  - Local `.deb` installs retry `dpkg -i` after dependency repair and require installed dpkg status matching the payload version before writing receipts.
  - Git checkouts without tags record their commit ID (or retained receipt if HEAD is unavailable); empty managed receipts are rejected.
  - Servarr receipts prefer the newly installed binary's reported version; Jackett parses `/opt/Jackett/jackett.deps.json` with `jq` and verifies it matches `$JACKETT_VERSION` without executing the binary. Jellyfin and KasmVNC publish persistent receipts only after readiness and remove them on uninstall.
  - APT/DEB rollback snapshots restore application runtime trees, entrypoints, and state/configuration, not the global dpkg database.

---

## Legacy CLI

`packages/system/af` delegates to an executable `AETHERFLOW_CLI_BIN`, `/opt/AetherFlow/current/bin/af`, `/opt/AetherFlow/current/af`, `/usr/local/bin/af-cli`, or `/opt/AetherFlow/bin/af-cli`, in that order. Set `AETHERFLOW_USE_RUNNER=1` to reject the legacy Bash fallback when no compiled CLI is available. Minimal installations without the compiled CLI require an install lock for updates, retain data on `remove`/`uninstall` unless `--purge` is passed, and serialize their Bash fallback with `/opt/AetherFlow/logs/maintenance.lock`.
