# Jellyseerr / Seerr upgrades

The Jellyseerr marketplace entry now installs stable releases from
`seerr-team/seerr`. The service name, port 5055, and data directory
`/var/lib/jellyseerr` remain unchanged so existing integrations continue to work.

The installer resolves GitHub's latest stable release, builds it in a temporary
directory, and uses a checksum-verified private Node.js 22 runtime (22.19 or newer)
and the pnpm 10 version declared by the release. It does not change the shared
Node.js or pnpm installations. Engine checks and the frozen lockfile remain
enabled; unsupported future runtime requirements fail before stopping the app.

After the build succeeds, the installer stops the service, archives its complete
data directory, and retains the old app and service unit in a root-only directory
matching `/var/backups/aetherflow-jellyseerr.*`. The service is explicitly restarted
and `/api/v1/status` must report the selected release before `.af-version` and
the installation lock are written. Startup failures and version mismatches restore
the previous application, data, and service unit automatically. Build failures
leave the running installation untouched.

Backups include credentials and should remain root-only. Keep the backup until
you have verified users, requests, and integrations after migration. To manually
roll back, stop `jellyseerr`, preserve the failed `/opt/jellyseerr` directory,
restore `app` from the chosen backup to `/opt/jellyseerr`, replace the data directory
from `data.tar.gz`, and restore `jellyseerr.service` to `/etc/systemd/system/`.
Then run `systemctl daemon-reload` and start `jellyseerr`. Restore application
and data together: the new release may have migrated the database.

Run the installer regression tests on Linux with:

```sh
python3 -m unittest discover -s tests -p 'test_jellyseerr_installer.py' -v
```

These tests execute the installer against temporary directories and mock external
commands, covering successful migration, pre-cutover failures, checksum rejection,
rollback after startup/version failures, and failed first installations.
