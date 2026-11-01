# Marketplace lifecycle repair

This change repairs the Rust V4 Marketplace paths identified in the November 1,
2026 diagnostic report. It keeps the native systemd deployment model.

## Lifecycle coordination

- API jobs register atomically, then hold a lifecycle mutex through service
  preparation, execution, and ingress synchronization. Health recovery uses that
  mutex and resets its retry state while package work is queued or running.
- The privileged runner's recovery operation shares the package execution mutex
  and persistent advisory flock. A busy executor skips recovery without spending
  a retry or posting a recovery notification. A leftover flock file is harmless.
- Inactive or failed `Type=oneshot` jobs are excluded from automatic restarts;
  their timer units can still be monitored.
- Unit resolution uses catalog service names and companion units. Update
  preparation queries and controls each concrete unit separately, stops timers
  first, and aborts if an active service cannot be stopped.
- Updates keep the native configured port, existing ingress port, or catalog port
  in that order. They never probe the running application's port to allocate a new
  one. Blueprint synchronization also reuses an installed application's port.
- Direct execution uses the runner's stream supervisor and locking, including
  `AF_PACKAGE_ACTION` and allocated port propagation.

## Installer and removal behavior

Gitea, Prometheus/Node Exporter, Rclone, Autobrr, File Browser, Unpackerr,
Autoscan, and Recyclarr install binaries through a temporary file on the
destination filesystem followed by `rename`. Gitea verifies the ELF header,
preserves its INI settings, runs migrations, and records the installed version.

Nextcloud preserves its database, configuration, application data, custom apps,
and themes and runs `occ upgrade` for an existing installation. Missing
configuration on an update fails before database provisioning. An existing
database without configuration is never reinitialized by a fresh install.
Uptime Kuma stages its build and copies its `data` directory into the new tree.
ruTorrent preserves `share`, `conf`, and plugins; Organizr preserves `api/config`
and `api/db`. Kavita preserves its `config` directory. File Browser retains its
database and initializes administrator accounts only for a new database.

Tree replacements retain the previous installation under
`<application-directory>.af-backup.*/app`, inside a private directory. These
copies support manual recovery of application files. Database migrations are
not automatically reversed. Operators should retain normal database backups and
remove old application copies after verifying an upgrade.

Legacy listen templates and readiness requests honor `AF_APP_PORT` (with
`AETHERFLOW_APP_PORT` as fallback). Native XML, JSON, INI, and YAML port settings
are updated without replacing unrelated settings. Plex keeps port 32400.
Calibre-Web uses its built-in port or an existing port already recorded in its
settings database; fresh installations do not receive an unsupported override.

The 57 older removal scripts now preserve persistent directories by default.
APT removals retain configuration, service accounts are retained with their
data, and Nextcloud's database is kept. An administrator can explicitly purge
through `DELETE_DATA=true` when invoking a removal script. The Marketplace's
existing uninstall request uses the data-preserving default. Mixed application
and data directories may remain after uninstall so reinstalling can reuse them.
Native Rust removal follows the same configuration/account retention policy.

The Lounge installs its required `npm-run-all` preparation tool before the
application. Kavita readiness has a bounded wait and concise registration errors;
Seerr checks a successful HTTP response before parsing its version JSON.

Scripts prefer the helpers shipped alongside the selected release. Config
loaders already prefer relative/current-release configuration ahead of the
legacy `/opt/AetherFlow/backend/config` fallback. Explicit config overrides
continue to take precedence.

## Versions and declarative recipes

Version checks prefer the existing `.af-version` markers for the eleven packages
listed in the report, plus Gitea. Autobrr's fallback uses `autobrr version`.
Every registered APT recipe captures the installed Debian package version, and
unresolved versions use `unknown` rather than a fabricated `1.0.0`.

The incomplete Scrutiny Rust recipe is no longer selected; Scrutiny uses its
existing Bash installer, which downloads its application assets and collector.
ClamAV and Mosquitto are not in the Marketplace catalog and no longer register
as Marketplace recipes. Twelve native recipes remain available behind the
existing opt-in feature flag.

## Validation and rollout

`tests/test_marketplace_lifecycle.py` runs installers against temporary directory
trees with mocked host commands. It verifies a real running executable can be
replaced without truncating its inode, Gitea failure handling and port settings,
data-preserving updates, a failed Uptime Kuma build, retained Nextcloud data on
uninstall, explicit Gitea purging, and configuration changes that retain secrets
and unrelated ports. The existing Seerr suite checks build failures, cutover,
runtime verification, and recovery.

Rust regressions cover recovery during package execution, scheduled oneshot
exclusion, duplicate API jobs, companion unit resolution, catalog/recipe parity,
actual installed versions, and default retention versus explicit purge.

Validation passed:

- `cargo test --workspace --no-fail-fast -- --test-threads=1`.
- Eleven isolated Marketplace installer/removal regressions and eight existing
  Seerr installer regressions.
- Syntax and shell hygiene checks for all 305 shell scripts, embedded Python
  parsing, and catalog/automation/install/remove parity for 74 packages.

The initial parallel Rust run failed an existing proxy test; that test passed
alone and in the serial workspace run. The API test suites change process-wide
database configuration, so the validated full-workspace command uses one test
thread.

Deploy the API, runner, configuration, package scripts, and shared helpers from
the same forward V4 release. Once deployed, retry the Gitea update and verify its
running version, existing repositories, configured port, and Marketplace update
status. These source-level tests do not update production applications.
