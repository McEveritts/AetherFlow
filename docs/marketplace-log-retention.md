# Marketplace Lifecycle Log Retention

The shipped [`aetherflow-log-retention.timer`](../deploy/systemd/aetherflow-log-retention.timer) triggers [`aetherflow-log-retention.service`](../deploy/systemd/aetherflow-log-retention.service), which runs the dependency-free Python 3 helper in [`deploy/log-retention.py`](../deploy/log-retention.py). No `logrotate` package, `cron` daemon, or application restart is required. Setup and the release manager install both systemd units, run an initial sweep, and enable the timer. Release tarballs and local source builds stage the complete `deploy/` directory.

The packaged unit runs with `TimeoutStartSec=120s`, `Nice=10`, `UMask=0027`, `PrivateNetwork=yes`, `ProtectSystem=strict`, `ReadWritePaths=/var/log`, and `CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER` (`aetherflow-log-retention.timer` sets `AccuracySec=1s`).

## Scope and Actual Bounds

The policy covers immediate children of `/var/log/aetherflow` matching `LOG_NAME` in `deploy/log-retention.py`:

- `install.log`
- `self_healing.log`
- `install-<package>.log` (also used by update and reinstall operations)
- `remove-<package>.log`

`<package>` must be 1–64 characters, begin with an ASCII letter or digit, and contain only ASCII letters, digits, dots, underscores, or hyphens (never `..`). Covered files include native `af-runner` operation logs, Bash `log()` appends, and `af_logged` output to those paths. Custom `LOGFILE` locations, application runtime logs (such as Quassel's own log), systemd journals, release-manager `deploy.log` / setup logs, and other filenames are outside this policy. The helper does not recurse or remove active logs.

Defaults: rotate when an active file **exceeds 10 MiB**, retain three archives per active log, and check one minute after boot and one minute after the previous sweep finishes (plus systemd scheduling delays). Each archive stores at most the last 10 MiB of the sampled file, even for an already oversized log. Archives use the reserved suffix `.af-retention.1` (newest) through `.af-retention.3` (oldest); only this namespace is managed. Existing `.1`, `.gz`, other logs, subdirectories, and unknown files are untouched. Lowering limits also trims old managed archives and prunes excess generations on the next sweep.

- **Steady-State & Staging Overhead**: After a successful sweep without concurrent writes, each covered filename holds at most 10 MiB active plus 30 MiB archived (40 MiB total). During a rotation, one bounded `.af-retention.pending` staging file adds at most another 10 MiB per log; an interrupted sweep may leave that file, which is reclaimed on the next successful sweep.
- **Periodic Policy (Not an Instantaneous Cap)**: Output written between checks, while the timer is disabled or failing, or under host overload has no fixed byte bound.
- **Aggregate Scaling**: Total disk usage scales with the number of covered log filenames; there is no directory-wide quota or automatic expiry of inactive log names.

## Writer Locking & Tail Preservation

The copy/truncate operation preserves the active inode (never renaming or unlinking the active log), so open `O_APPEND` writers continue appending to the same visible file:

- **Cooperative `flock` Serialization**: `deploy/log-retention.py` acquires a blocking exclusive lock (`fcntl.flock(fd, fcntl.LOCK_EX)`) on each active log file during rotation, coordinating directly with shared-lock (`LOCK_SH`) writers in Bash (`packages/lib/logging_archives.sh`: `af_prepare_logfile_path`, `log`, `af_logged`, `af_logged_stderr`) and `af-runner` (`package_executor/helpers.rs::append_log_line`).
- **Bounded Live-Tail Retention**: Rather than unconditionally truncating an active file to zero, `deploy/log-retention.py` captures any trailing bytes appended after the archive copy via `_read_bounded_live_tail` (up to `max_bytes`, across two 8-iteration drain loops), rewrites those retained bytes from offset `0` (`_rewrite_retained_from_start`), and calls `os.ftruncate(descriptor, len(retained))`. If no concurrent bytes arrived, the active file truncates cleanly to `0`.
- **Limitations**: A bounded tail intentionally discards earlier oversized output, and non-`flock` writers or external rotators on these files are unsupported. Retention is not a lossless audit trail.

## Safety, Configuration, and Operation

The helper walks every log-directory component using directory descriptors and `O_NOFOLLOW`, pins the directory, acquires a nonblocking exclusive retention lock, and opens files with `O_NOFOLLOW`/`O_NONBLOCK`. Symlinks, non-regular files, hardlinks, group/world-writable entries, and unexpected owners are rejected without following their targets. Each affected log's existing archives are validated before its active file is truncated. Rejections produce a failed oneshot run and a journal diagnostic; other valid logs still rotate.

The directory is normalized to `root:aetherflow` mode `0750`, covered active files and managed archives to `root:aetherflow` mode `0640`, and the internal lock to `0600`. Legacy `aetherflow`-owned logs and directories are accepted for migration; other owners are rejected. Newly created writer files acquire these permissions on the next sweep. Unrelated files' ownership and permissions are untouched. `/var/log/aetherflow` is intentionally not writable by the unprivileged API service account; `aetherflow-runner` and root Bash installers remain able to append.

An optional root-owned `/etc/aetherflow/log-retention.env` may override `AF_LOG_RETENTION_MAX_BYTES` (`1` through `67108864`) and `AF_LOG_RETENTION_KEEP` (`1` through `20`). Invalid settings fail before touching the directory. Change timing through a systemd timer drop-in. Do not deploy a second rotator against the same active files. Rollback to a release predating this helper cannot run this policy from `current`.

On a deployed host, inspect `systemctl list-timers aetherflow-log-retention.timer` and `journalctl -u aetherflow-log-retention.service`; a disabled or failing timer does not enforce periodic retention. Run `sudo systemctl start aetherflow-log-retention.service` for an immediate manual sweep.
