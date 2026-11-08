# Marketplace lifecycle log retention

The shipped `aetherflow-log-retention.timer` runs the dependency-free Python 3
helper in `deploy/log-retention.py`. No logrotate package, cron installation,
application restart, or writer cooperation is required. Setup and the release
manager install both units, run an initial sweep, and enable the timer. Release
tarballs and local source builds already copy the whole `deploy/` directory.

## Scope and actual bounds

The policy covers only immediate children of `/var/log/aetherflow` named
`install.log`, `install-<package>.log`, or `remove-<package>.log`, where the package
is 1–64 characters, begins with an ASCII letter/digit, and otherwise contains
ASCII letters, digits, dots, underscores, or hyphens (but never `..`). These include native
runner operation logs and Bash `log()` and external `>> "$LOGFILE"` appends to
the same paths. Update/reinstall actions use the `install-` filename. Custom
`LOGFILE`/native log directories, application runtime logs (including Quassel's
own log), journals, release-manager/setup logs, and other filenames are outside
this policy. The helper does not recurse or remove active logs.

Defaults: rotate when the active file **exceeds 10 MiB**, retain three archives
per active log, and check one minute after boot and one minute after the previous
sweep finishes (plus systemd scheduling delays). Each archive stores only the
last at most 10 MiB of the sampled file, even for an already enormous log.
Archives use the reserved suffix `.af-retention.1` (newest) through
`.af-retention.3` (oldest); only this namespace is managed. Existing `.1`, `.gz`,
other logs, subdirectories, and unknown files are untouched. Lowering limits
also trims old managed archives and prunes excess generations on the next sweep.

After a successful sweep **without concurrent writes**, each covered filename
has at most 10 MiB active plus 30 MiB archived (40 MiB total). A rotated active
file is truncated to zero, not left at the threshold. These bounds describe
named files' logical contents, not filesystem metadata or blocks pinned by
readers of superseded archives. During a rotation one
bounded `.af-retention.pending` staging file adds at most another 10 MiB per
log; an interrupted sweep may leave that file, which is reclaimed on the next
successful sweep. This is a **periodic retention policy, not an instantaneous
size cap or filesystem quota**: active output between checks, during a sweep,
while the timer is disabled/failing, or while the machine is overloaded has no
fixed byte bound. Aggregate usage also depends on the number of covered log
names; there is no directory-wide quota or expiry of inactive log names.

The copy/truncate operation preserves the active inode, so already-open native
or Bash `O_APPEND` writers continue writing to the same visible file. It never
renames or unlinks that file. A bounded tail deliberately discards earlier
oversized output, and uncoordinated writes between the tail snapshot and truncate
can be lost, as with logrotate's copytruncate. Retention is not a lossless audit
trail; non-append writers and external rotation of these files are unsupported.

## Safety, configuration, and operation

The helper walks every log-directory component using directory descriptors and
`O_NOFOLLOW`, pins the directory, uses a nonblocking exclusive retention lock,
and opens files with `O_NOFOLLOW`/`O_NONBLOCK`. Symlinks, non-regular files,
hardlinks, group/world-writable entries, and unexpected owners are rejected
without following their targets. Each affected log's existing archives are
validated before its active file can be truncated. Rejections produce a failed
oneshot and a journal diagnostic; other safe logs can still be rotated.

The directory becomes `root:aetherflow` mode `0750`, covered active files and
managed archives become `root:aetherflow` mode `0640`, and the internal lock is
`0600`. Legacy `aetherflow`-owned logs/directories are accepted for migration;
other owners are not. Newly created writer files acquire these permissions on
the next sweep. Unrelated files' ownership/permissions are not changed. The
directory is intentionally no longer writable by the API service account; the
privileged runner and root Bash installers remain able to append. Existing
untrusted open writable descriptors cannot be revoked by a retention sweep.

An optional root-owned `/etc/aetherflow/log-retention.env` may override
`AF_LOG_RETENTION_MAX_BYTES` (1 through 67108864) and
`AF_LOG_RETENTION_KEEP` (1 through 20). Invalid settings fail before touching
the directory. Change timing through a systemd timer drop-in. Do not deploy a
second rotator against the same active files. Rollback to a release predating
this helper cannot run this policy from `current`; restore a supporting release
or explicitly maintain the policy separately.

On a deployed host, inspect `systemctl list-timers aetherflow-log-retention.timer`
and `journalctl -u aetherflow-log-retention.service`; a disabled or failing timer
does not enforce periodic retention. Run
`systemctl start aetherflow-log-retention.service` for a manual sweep. No host service operations
are needed by the repository's fixture-only tests.
