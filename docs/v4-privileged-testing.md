# AetherFlow v4 Privileged Guest Drills Runbook

## Overview & Safety Boundaries

`scripts/v4_privileged_guest_drills.py` is a stdlib-only Python verification harness that exercises the shipped `aetherflow-api` (`aetherflow-api runner` over Unix domain sockets) and `af` (`af-cli`) binaries inside a **disposable QEMU/systemd Linux guest VM**.

It imports six fail-closed disposable-guest guardrails (`verify_guest_execution_guardrails`) from `scripts/lib/vm_guest_common.py` before creating any directory or spawning any process:

1. **OS & Effective Identity**: Requires `sys.platform.startswith("linux")` and `os.geteuid() == 0`.
2. **Explicit CLI Confirmation**: Requires `--confirm-disposable-guest`.
3. **Environment Marker**: Requires `AETHERFLOW_DISPOSABLE_GUEST=1`.
4. **Ephemeral `/run` Guest Marker File**: Requires `/run/aetherflow-disposable-guest` (or `--guest-marker-file` under `/run/`) containing `AETHERFLOW_DISPOSABLE_GUEST_V4`.
5. **QEMU/KVM Virtualization Probe**: Verifies `systemd-detect-virt --vm`, `/sys/class/dmi/id/*`, or `/sys/hypervisor/type` matches `qemu`, `kvm`, `bochs`, or `standard pc`. Bare-metal hosts fail closed with exit code `2`.
6. **Isolated Work Root & Binary Path Guard**: Requires `--work-root` under `/var/tmp/aetherflow-v4-guest-drills*` (rejected against `FORBIDDEN_HOST_PATHS`, including `/opt/AetherFlow`, `/var/lib/aetherflow`, `/etc/aetherflow`, and `/run/aetherflow/runner.sock`) and rejects `--api-bin` / `--af-bin` inside `/opt/AetherFlow` or `/opt/aetherflow` (`validate_binary_not_in_live_host_tree`).

---

## Mandatory Drill Phases (`MANDATORY_DRILL_PHASES`)

`evaluate_drill_suite_status` evaluates all 6 phases fail-closed. Any missing phase, unexecuted phase (`real_execution=False`), `pending_contract` status, or failed assertion forces `overall_passed=False` and exit code `1`:

| Phase ID | Exercised Surface | Required Checks |
| :--- | :--- | :--- |
| `binary_and_environment_provenance` | `aetherflow-api`, `af --json version` | Records SHA-256, byte size, mode, UID/GID of both binaries, runner EUID/EGID, unprivileged test identity (`nobody`/`65534`), and CLI `status`/`domain`/`action`/`exit_code` envelope. |
| `authorized_backup_roundtrip_with_live_wal` | `POST /v1/backup` (`create_sqlite`, `create_archive`, `list`, `verify`, `delete`) + `af --json backup` | Holds a live SQLite database open in `WAL` mode (`wal_autocheckpoint=0`, active `-wal`/`-shm` sidecars, open reader + uncommitted writer) while creating, listing, verifying, tamper-checking (`.sha256` corruption fails with HTTP `400`), and deleting backups. |
| `arbitrary_root_and_sentinel_deletion_rejection` | `POST /v1/backup` + `af --json backup delete` | Rejects request-selected `backup_dir`, `db_path`, and `target_root` overrides (`HTTP 403`), traversal `..` (`HTTP 400`), and uninventoried filenames (`root_sentinel_keep.conf`, `untracked_sentinel.sqlite`), confirming root sentinels retain exact SHA-256, size, UID/GID, mode `0600`, and inode. |
| `unprivileged_user_and_socket_authorization_denial` | UDS DAC (`0660`), `SO_PEERCRED` (`0666`), `af --socket ... health`, `af backup create` | Verifies unprivileged UID is blocked by `0660` (`EACCES`), rejected by `authorize_runner_peer_credentials` (`SO_PEERCRED`) even under `0666` (`af` exits `3` `runner_ipc_failure`), and rejected by `af backup create` without privilege (`exit 5` `privilege_required`). |
| `restore_integrity_uid_gid_mode_and_quiescence` | `POST /v1/backup` (`restore_execute`) + `af --json backup restore` + `CommandQuiescenceController` | Verifies unconfirmed restore fails closed (`HTTP 400` / `af` exit `6` `unsupported_operation`); confirmed restore stops/restarts an active systemd service (`MainPID` rotated), restores golden SHA-256, preserves manifest UID/GID and `0600`/`0640` modes, unlinks stale `-wal`/`-shm`, and aborts without mutating live targets when service stop fails (`HTTP 500`). |
| `held_open_wal_snapshot_recovery` | `POST /v1/backup` (`create_archive`, `restore_execute`) + `af --json backup restore` + `sqlite3` | Captures an online backup while committed rows live in uncheckpointed `-wal` frames alongside an uncommitted transaction, restores into clean roots, and verifies `PRAGMA integrity_check = ok`, `PRAGMA quick_check = ok`, `PRAGMA user_version = 404`, all committed rows present, and zero uncommitted leakage. |

---

## Latest Executed Guest Run (November 3, 2026)

The November 3, 2026 six-phase run in a disposable Debian 13 guest confirmed real backup roundtrips, sentinel protection, peer rejection, systemd stop/start, and committed-only held-open WAL recovery, while flagging restore metadata drift on SQLite source ownership and legacy `/etc/AetherFlow/.Lock` file mode. A fresh guest run against current release binaries is required to certify this suite green.

The harness consumes the canonical flat `BackupRunnerResponse` inside `RunnerResponse.output` (only the outer envelope carries `success`), reads CLI error envelopes (`error_kind`) from stderr, checks restored SQLite bytes against the manifest's verified snapshot digest plus read-only integrity/row assertions, and requires unchanged target bytes, UID/GID, mode, and inode when service stop fails (`HTTP 500`).

---

## Controller Selection: `AETHERFLOW_BACKUP_ISOLATED_ROOT` vs. `CommandQuiescenceController`

In `backend-rs/crates/af-runner/src/backup_ops.rs` and `backend-rs/crates/af-cli/src/commands/backup.rs`:

- When `AETHERFLOW_BACKUP_ISOLATED_ROOT` is set on `aetherflow-api runner` (or `--root` is passed to `af`), `dry_quiesce` defaults to enabled (`NoopQuiescenceController`).
- To exercise the real `CommandQuiescenceController` (`/bin/systemctl stop`, `start`, `is-active --quiet`) during Phase 5 while confining all file mutations to `/var/tmp/aetherflow-v4-guest-drills*`, Phase 5 launches a dedicated runner with `AETHERFLOW_BACKUP_ISOLATED_ROOT` unset and explicit server-owned environment paths:
  - `AETHERFLOW_BACKUP_DIR=<work_root>/phase5_restore_iso/var/lib/aetherflow/backups`
  - `AETHERFLOW_DB_PATH=<work_root>/phase5_restore_iso/var/lib/aetherflow/aetherflow.sqlite`
  - `AETHERFLOW_RESTORE_STAGING_ROOT=<work_root>/phase5_restore_iso`
  - `AETHERFLOW_BACKUP_DRY_RUN_QUIESCENCE=0`

---

## Running Unit Tests (Any Host / CI)

Run the 12 harness validation and evaluation unit tests from the repository root:

```bash
python3 -m unittest discover -s tests -p "test_v4_privileged_guest_drills.py" -v
```

---

## Disposable QEMU/systemd Guest Execution Runbook

Stage the candidate `aetherflow-api` and `af` binaries, `scripts/v4_privileged_guest_drills.py`, and its shared library dependency `scripts/lib/vm_guest_common.py` under `/var/tmp/aetherflow-v4-stage`:

```bash
# 1. Verify required script library is staged
ls -la /var/tmp/aetherflow-v4-stage/scripts/v4_privileged_guest_drills.py \
  /var/tmp/aetherflow-v4-stage/scripts/lib/vm_guest_common.py

# 2. Write the ephemeral disposable-guest marker in /run tmpfs
printf 'AETHERFLOW_DISPOSABLE_GUEST_V4\n' | sudo tee /run/aetherflow-disposable-guest >/dev/null

# 3. Execute the privileged guest drill suite as root inside the disposable guest
sudo env AETHERFLOW_DISPOSABLE_GUEST=1 \
  python3 /var/tmp/aetherflow-v4-stage/scripts/v4_privileged_guest_drills.py \
  --confirm-disposable-guest \
  --work-root /var/tmp/aetherflow-v4-guest-drills-run \
  --api-bin /var/tmp/aetherflow-v4-stage/bin/aetherflow-api \
  --af-bin /var/tmp/aetherflow-v4-stage/bin/af \
  --json-out /var/tmp/aetherflow-v4-stage/guest-drills-report.json
```

### Exit Codes

- `0`: All 6 mandatory privileged drill phases executed against real binaries and passed every assertion.
- `1`: One or more drill assertions failed, or a phase reported `pending_contract` / `real_execution=False`.
- `2`: Blocked by `GuestSafetyError` before touching the filesystem.

---

## Trusted Recovery Context, Provenance, and Maintenance Lock Contracts (`af-host`)

### 1. Trusted `RecoveryContext` and Protected Provenance Directory

- **No Unauthenticated Journal Trust**: Calling `recover_interrupted_restore` without an explicit `RecoveryContext` fails closed with `HostBackupError::InvalidConfig`. Privileged callers (`af-runner` and `af-cli`) call `recover_interrupted_restore_with_context(backup_dir, &RecoveryContext, quiescence)` with server-owned `expected_target_root` (`/` or validated isolated root), `trusted_sqlite_db_path`, `trusted_sqlite_uid`, `trusted_sqlite_gid`, and optional `provenance_dir`.
- **Protected Provenance Directory (`resolve_recovery_provenance_dir`) & Overlap Rejection**:
  - Canonical host (`target_root == "/"`): `/etc/AetherFlow/.restore-provenance` (`0700`, owned by effective UID `euid`, opened via `open_or_create_provenance_dir_nofollow` requiring `root`/`euid` ownership on every ancestor).
  - Isolated staging root (`target_root != "/"`): `<target_root>/.restore-provenance` (`0700`, owned by `euid`).
  - `validate_destination_not_provenance` rejects any restore destination whose lexical path overlaps or nests within canonical, target-root, or custom provenance authority directories or whose ancestors contain `.rollback-restore.*.journal.json` markers (symlink-free equivalence is enforced separately via `reject_symlink_chain`; custom `provenance_dir` validation is enforced on the `*_for_execution` planning/preflight entrypoints, `execute_staged_restore`, and `validate_recovery_journal`).
- **Authenticated Candidate Journal Selection & Interrupted Publication Tolerance**:
  - Each `RollbackFailureJournal` checkpoint increments `generation` and writes an `O_NOFOLLOW` `.sha256` sidecar validated via `read_verified_text_file_nofollow` and `load_validated_journal_checkpoint`.
  - If a crash interrupts publication after provenance writes `generation = N` before its sidecar or local recovery journal completes, recovery selects the highest-generation authenticated valid checkpoint and never prefers an unauthenticated or corrupted candidate.

### 2. Descriptor-Bound Staging/Rollback Installation, Authority Commit & Cleanup Ordering

- **Descriptor/Inode/Digest Binding Across Staging & Rollback**:
  - In-memory staged and rollback structs (`StagedRestoreEntry`, `RollbackRecord`) bind expected `(st_dev, st_ino, size_bytes, sha256)`; persisted `RollbackFailureJournalEntry` records store SHA-256 digests (`rollback_copy_sha256`, `wal_copy_sha256`, `shm_copy_sha256`), and crash recovery (`validate_recovery_copy_path`) validates those digests while dynamically computing `(st_dev, st_ino)` and `size_bytes` from disk.
  - Before installing or rolling back, `atomic_install_file_at_destination_with_verification` opens absolute sources via `open_existing_regular_file_nofollow` (`O_RDONLY | O_CLOEXEC | O_NOFOLLOW`; relative sources via `OpenOptions`), checks `fstat` `(st_dev, st_ino)`/`euid` identity, and streams + re-verifies SHA-256 into a descriptor-locked private installation directory via `atomic_install_verified_reader_at_destination`.
- **Irreversible Durable Authority Commit & Rollback Precedence**:
  - Once all staged files are installed and verified, `persist_committed_journal_snapshot` (`backend-rs/crates/af-host/src/restore/journal.rs`) publishes `JOURNAL_STATE_COMMITTED` (`"committed"`) to the protected provenance directory **first**. Once provenance is durably committed, commit is irreversible even if the subsequent local recovery-directory write fails.
  - `execute_staged_restore` transitions through `JOURNAL_STATE_QUIESCING`, `JOURNAL_STATE_ABORTED_CLEAN`, `JOURNAL_STATE_IN_PROGRESS`, `JOURNAL_STATE_COMMITTED`, `JOURNAL_STATE_ROLLED_BACK`, and `JOURNAL_STATE_ROLLBACK_FAILED` (with `recover_interrupted_restore_with_context` completing to `JOURNAL_STATE_RECOVERED`). When provenance indicates incomplete rollback (`file_rollback_incomplete = true` or non-committed state), recovery refuses a stale local `"committed"` journal and forces rollback completion.
- **Recovery Stop Failure Quiescence Boundary**:
  - Initial pre-mutation stop failures (`stop_services_with_compensation`) compensate by restarting services stopped during that preflight step.
  - During `recover_interrupted_restore_with_context`, `stop_services_for_recovery` never restarts writers over partially restored state; services remain quiesced until rollback completes.
- **Authority-Last Cleanup & Error Surfacing**:
  - `remove_recovery_dir_and_provenance_with_fault` removes the unprivileged recovery directory **before** removing the protected provenance journal and sidecar, propagating cleanup errors (`HostBackupError::Io` / `HostBackupError::RestoreRollbackFailed`) rather than silently orphaning an unauthenticated recovery directory.

### 3. Deterministic Maintenance Lock, Non-Root Metadata Enforcement & SQLite Contracts

- **Stable Maintenance Lock Resolution & Parent Preservation**:
  - `resolve_maintenance_lock_path` defaults to `/run/aetherflow/.snapshot.lock` (or the contained isolated runtime path), with explicit `AETHERFLOW_MAINTENANCE_LOCK_PATH` supported. `HostMaintenanceLockGuard::try_acquire_once` rejects replaceable non-root-owned or unsticky group-writable lock ancestors (including service-owned data parents) without mutating them, while `open_or_create_lock_parent_dir_nofollow` normalizes an existing root-owned `.../run/aetherflow` parent directory to `0:target_gid` mode `0750` when `euid == 0`.
  - `HostMaintenanceLockGuard` opens existing lockfiles with `openat(..., O_RDWR | O_CLOEXEC | O_NOFOLLOW)` (or, on `ENOENT`, creates with `openat(..., O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o660)`), checks `fstat(fd)`, acquires `flock`, verifies post-lock `fstatat` `(st_dev, st_ino)` identity, and enforces `fchown`/`fchmod` (failing closed under non-root `euid != 0` on ownership mismatch).
- **SQLite Non-Follow Descriptor Verification & WAL-Free Snapshot Contract**:
  - `SqliteVerifiedSourceGuard` (`open_and_pin`, `bind_opened_connection`, `verify_sqlite_connection_identity`, `verify_unchanged_and_consistent` in `af-host/src/snapshot.rs`) validates that the main DB and present `-wal`/`-shm` sidecars are regular files in a root/trusted-owned parent directory and verifies `(st_dev, st_ino)` identity across connection open and snapshot capture.
  - Online snapshots convert the staged file to `journal_mode = DELETE` and truncate any WAL; `verify_sqlite_snapshot_integrity_with_trusted_uid` rejects snapshots accompanied by `-wal`/`-shm` sidecars, opens read-only (`SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_NO_MUTEX | SQLITE_OPEN_NOFOLLOW`), checks `(st_dev, st_ino)`, metadata, and sidecar absence (`verify_unchanged_and_consistent`) before and after running both `PRAGMA quick_check` and `PRAGMA integrity_check`, and honors explicit configured `trusted_sqlite_uid` (post-restore SHA-256 verification runs separately in `af-host/src/restore/execution.rs` via `verify_file_sha256_with_trusted_uid`).
  - Checksum sidecar verification (`verify_file_with_sidecar` / `verify_file_with_sidecar_and_trusted_uid` / `parse_sha256_sidecar_str`) uses `O_NOFOLLOW` bounded reads via `read_verified_text_file_nofollow` and returns structured `HostBackupError::{MissingChecksumSidecar, InvalidManifest, ChecksumMismatch}` errors.
  - Public planning/preflight APIs expose matching `sqlite_target_rel_path` + `trusted_sqlite_uid` parity (`plan_restore_from_manifest_with_sqlite_overrides`, `preflight_restore_directory_with_sqlite_overrides_and_trusted_uid`, `preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid`, `verify_backup_artifact_with_trusted_uid`).

### 4. Evidence Boundary: Crate Fixture Tests vs. Live Disposable VM Drills

- **Deterministic Host & Non-Root Crate Tests (`cargo test -p af-host`)**: Exercise partial provenance publication, recovery stop failure quiescence, inode-swap rejection, maintenance lock parent preservation, custom `AETHERFLOW_TRUSTED_SQLITE_UID`/`AETHERFLOW_TRUSTED_SQLITE_GID`, preflight/plan parity, and non-root `setpriv --reuid=65534 --regid=65534` execution with mocked `ServiceQuiescenceController` implementations.
- **What Crate Tests Do Not Replace**: Live `systemd` unit stop/start transitions, kernel UDS `SO_PEERCRED` enforcement on `aetherflow-api runner`, and CLI-to-runner IPC require executing `scripts/v4_privileged_guest_drills.py` inside a disposable QEMU/systemd guest VM.

---

## Disposable Real-Systemd Guest Validation: Managed Plugin Isolation

Non-root crate tests cover runner manifest/path validation, `systemd-run` property assembly, token redaction/atomic staging, fail-closed `503 PLUGIN_ISOLATION_UNAVAILABLE`, and IPC using fixture shims. To validate live kernel and `systemd` enforcement in a disposable guest:

1. **Stage isolated roots & runner** under `/var/tmp/aetherflow-v4-guest-drills*`:
   - Run `aetherflow-api runner` as `root` with `AETHERFLOW_RUNNER_SOCK`, `AETHERFLOW_PLUGINS_DIR`, `DATA_DIR`, and `AETHERFLOW_PLUGIN_TOKENS_ROOT=/run/aetherflow-runner-plugin-tokens`.
   - Run `aetherflow-api` as `aetherflow` with `PRIVILEGED_RUNNER_ENABLED=true`, matching socket/plugins paths, and a `0600 aetherflow:aetherflow` sentinel file inside `DATA_DIR`.
2. **Start a managed plugin fixture** (e.g., `telemetry-inspector` or a probe fixture) via `POST /api/v1/admin/plugins/:id/control` `{"action":"start"}`.
3. **Assert kernel & systemd isolation invariants**:
   - `systemctl show -p ActiveState -p MainPID -p UID -p GID aetherflow-plugin-<id>.service` reports `ActiveState=active`, `UID != 0`, `UID != id -u aetherflow`, and `GID != id -g aetherflow`.
   - Loopback `/healthz`, `/api/v1/auth/plugins/:id/proxy/...`, and scoped `GET /api/v1/auth/system/metrics` succeed using `AETHERFLOW_PLUGIN_TOKEN_FILE=/run/aetherflow-plugin-token/runtime.token`, while `/proc/<MainPID>/cmdline` and `/proc/<MainPID>/environ` never contain the raw JWT.
   - Reads/writes to `DATA_DIR`, `/var/lib/aetherflow`, `/etc/aetherflow`, `/run/aetherflow/runner.sock`, and writes to `/run/aetherflow-plugin-app` fail with `EACCES`/`ENOENT`/`EROFS`, while reads from `/run/aetherflow-plugin-app` and writes to `$PLUGIN_STATE_DIR` (`/var/lib/aetherflow-plugin-<id>`) succeed.
   - `{"action":"revoke_tokens"}` rotates `/run/aetherflow-plugin-token/runtime.token` and invalidates prior tokens; `{"action":"stop"}` runs `on_stop` inside the unit, tears down the cgroup (`KillMode=control-group`), removes `/run/aetherflow-runner-plugin-tokens/<id>`, and revokes tokens.
   - Stopping `aetherflow-api runner` and invoking `start` fails closed with HTTP `503` (`PLUGIN_ISOLATION_UNAVAILABLE`) without spawning any process as `aetherflow`.
