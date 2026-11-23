# Jellyseerr / Seerr Upgrades

The Jellyseerr Marketplace entry installs stable releases from `seerr-team/seerr`. The service name (`jellyseerr`), port `5055`, and data directory `/var/lib/jellyseerr` remain unchanged so existing integrations continue to work.

The installer resolves GitHub's latest stable release, builds it in a temporary directory, and uses a checksum-verified private Node.js 22 runtime (`22.19` or newer) and the `pnpm 10` version declared by the release without changing host-wide Node.js or `pnpm` installations. Engine checks and the frozen lockfile remain enabled; unsupported future runtime requirements fail before stopping the app.

Upgrade cutover and rollback sequence:

1. **Pre-Cutover Backup**: After the build succeeds, the installer stops `jellyseerr.service` and saves the prior application bundle, service unit, a `data.tar.gz` archive, and a `state/` directory snapshot (`snapshot_app_state`) inside a root-only directory matching `/var/backups/aetherflow-jellyseerr.*`.
2. **Activation & Version Gate**: The installer explicitly restarts `jellyseerr.service` and verifies that `/api/v1/status` reports the selected release before writing `.af-version` and `/install/.jellyseerr.lock`.
3. **Backup Retention**: After `write_lock` succeeds, `retain_successful_app_backups` writes `.af-successful-backup` and prunes older completed backups, retaining the current and one preceding successful backup (unmarked or failed recovery backups are never auto-pruned).
4. **Failure Recovery**: Build failures leave the running installation untouched. Startup failures and version mismatches attempt automatic restoration of the previous application, `state/` snapshot, and service unit.

Backups include credentials and remain root-only. Ordinary uninstall retains `/var/lib/jellyseerr` and existing upgrade backups; explicit purge (`DELETE_DATA=true` / `?purge=true`) calls `remove_lock jellyseerr` -> `purge_app_backups`, deleting `/var/backups/aetherflow-jellyseerr.*` along with application state.

To manually roll back after verifying an issue, stop `jellyseerr`, preserve the failed `/opt/jellyseerr` directory, restore `app` from the chosen backup to `/opt/jellyseerr`, restore `/var/lib/jellyseerr` from `data.tar.gz` (or the backup's `state/` snapshot), and restore `jellyseerr.service` to `/etc/systemd/system/`. Then run `sudo systemctl daemon-reload` and `sudo systemctl start jellyseerr`. Restore application code and data together because the newer release may have migrated the database.

Run the installer regression tests on Linux with:

```bash
python3 -m unittest discover -s tests -p 'test_jellyseerr_installer.py' -v
```

These tests execute the installer against temporary directories with mocked host commands, covering successful migration, pre-cutover failures, checksum rejection, rollback after startup/version failures, and failed first installations.
