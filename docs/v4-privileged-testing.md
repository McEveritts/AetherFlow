# AetherFlow v4 Privileged Guest Drills Runbook (`scripts/v4_privileged_guest_drills.py`)

## Overview & Safety Boundaries

`scripts/v4_privileged_guest_drills.py` is a stdlib-only Python verification harness that exercises the real shipped `aetherflow-api` (including `aetherflow-api runner` over Unix domain sockets) and `af` (`af-cli`) binaries inside a **disposable QEMU/systemd Linux guest VM**.

To isolate these tests from live host state, the harness enforces six fail-closed guardrails (`verify_guest_execution_guardrails`) before creating any directory or spawning any process:

1. **OS & Effective Identity:** Requires `sys.platform.startswith("linux")` and `os.geteuid() == 0`.
2. **Explicit CLI Confirmation:** Requires `--confirm-disposable-guest`.
3. **Environment Marker:** Requires `AETHERFLOW_DISPOSABLE_GUEST=1`.
4. **Ephemeral `/run` Guest Marker File:** Requires `/run/aetherflow-disposable-guest` (or `--guest-marker-file` under `/run/`) containing the token `AETHERFLOW_DISPOSABLE_GUEST_V4`.
5. **QEMU/KVM Virtualization Probe:** Verifies `systemd-detect-virt --vm` and `/sys/class/dmi/id/*` match `qemu`, `kvm`, `bochs`, or `standard pc`. Bare-metal hosts fail closed with exit code `2`.
6. **Isolated Work Root & Binary Path Guard:** Requires `--work-root` under `/var/tmp/aetherflow-v4-guest-drills*` and rejects any binary or target path inside `/opt/AetherFlow`, `/var/lib/aetherflow`, `/etc/aetherflow`, or `/run/aetherflow/runner.sock`.

---

## Mandatory Drill Phases (`MANDATORY_DRILL_PHASES`)

The harness evaluates all 6 phases fail-closed (`evaluate_drill_suite_status`). Any missing phase, unexecuted phase (`real_execution=False`), pending contract (`status="pending_contract"`), or failed assertion forces `overall_passed=False` and exit code `1`.

| Phase ID | Exercised Surface | Required Checks |
| --- | --- | --- |
| `binary_and_environment_provenance` | `aetherflow-api`, `af --json version` | Records SHA-256, byte size, mode, UID/GID of both binaries, runner EUID/EGID, unprivileged test identity (`nobody`/`65534`), and the actual CLI `status`/`domain`/`action`/`exit_code` envelope. |
| `authorized_backup_roundtrip_with_live_wal` | `aetherflow-api runner` (`POST /v1/backup`: `create_sqlite`, `create_archive`, `list`, `verify`, `delete`) + `af --json backup create\|list\|verify\|delete` | Holds a live SQLite database open in `WAL` mode (`wal_autocheckpoint=0`, active `-wal` and `-shm` sidecars, open reader snapshot + active uncommitted write lock) while creating, listing, verifying, tampering (`.sha256` corruption fails with HTTP 400), and deleting backups. |
| `arbitrary_root_and_sentinel_deletion_rejection` | `POST /v1/backup` + `af --json backup delete` | Rejects request-selected arbitrary `backup_dir`, `db_path`, and `target_root` overrides (`HTTP 403 Forbidden`), parent traversal `..` (`HTTP 400`), and unknown/uninventoried filenames (`root_sentinel_keep.conf`, `untracked_sentinel.sqlite`). Verifies root-owned sentinel files remain 100% intact (SHA-256, size, UID/GID, mode `0600`, inode). |
| `unprivileged_user_and_socket_authorization_denial` | UDS DAC (`0660`), Kernel `SO_PEERCRED` (`0666`), `af --socket <sock> --json health`, `af --json backup create` | Verifies unprivileged UID is blocked by `0660` socket permissions (`EACCES`), rejected by `authorize_runner_peer_credentials` (`SO_PEERCRED`) even when socket mode is `0666` (`af` exits `3` `runner_ipc_failure`), and rejected by `af backup create` without privilege (`exit 5` `privilege_required`). |
| `restore_integrity_uid_gid_mode_and_quiescence` | `POST /v1/backup` (`restore_execute`) + `af --json backup restore` + guest `systemd` (`CommandQuiescenceController`) | Verifies unconfirmed restore fails closed (`HTTP 400` / `af` exit `6` `unsupported_operation`); confirmed restore stops and restarts a real active systemd service (`MainPID` rotated and verified active), restores exact golden SHA-256, preserves manifest UID/GID and `0600`/`0640` file modes, unlinks stale `-wal`/`-shm` sidecars, and aborts without mutating live targets when a required service fails to stop. |
| `held_open_wal_snapshot_recovery` | `POST /v1/backup` (`create_archive`, `restore_execute`) + `af --json backup restore` + `sqlite3` | Captures an online backup while committed rows reside in uncheckpointed `-wal` frames alongside an uncommitted in-flight transaction, restores into clean recovery roots, and verifies `PRAGMA integrity_check = ok`, `PRAGMA quick_check = ok`, `PRAGMA user_version = 404`, all committed WAL rows present, and zero leakage of uncommitted frames. |

---

## Contract Nuance Note: `AETHERFLOW_BACKUP_ISOLATED_ROOT` vs `CommandQuiescenceController`

### Executed guest result: November 3, 2026

The six-phase suite has now executed in a real disposable Debian 13 guest using
the source-20261103-071256 binaries. It is **not yet passing**. Evidence under
`/var/tmp/aetherflow-v4-validation-20261103-052723/logs/privileged-guest-20261103-132517`
shows real backup roundtrips, sentinel protection, peer rejection, systemd
stop/start, and committed-only held-open WAL recovery. Restore metadata remains
incorrect for the SQLite source owner and legacy `.Lock` mode. A new converged
binary run is required after those defects are repaired.

The harness consumes the canonical flat `BackupRunnerResponse` inside
`RunnerResponse.output`; only the outer envelope has `success`. CLI failure
envelopes use `error_kind` and are emitted on stderr. Restored SQLite bytes are
checked against the manifest's verified snapshot checksum, followed by a
read-only integrity and expected-row check. Pre-VACUUM source bytes are not a
valid expected snapshot hash. A service stop failure is HTTP 500, and the
harness requires unchanged target bytes, UID/GID, mode, and inode.

### Controller selection

Inspection of `backend-rs/crates/af-runner/src/lib.rs` (lines 881–887) and `backend-rs/crates/af-cli/src/lib.rs` (lines 1277–1291) shows:

- When `AETHERFLOW_BACKUP_ISOLATED_ROOT` is set on `aetherflow-api runner` (or `--root` is passed to `af`), `dry_quiesce` is automatically enabled (`NoopQuiescenceController`).
- To exercise the real `CommandQuiescenceController` (`/bin/systemctl stop`, `/bin/systemctl start`, `/bin/systemctl is-active --quiet`) during Phase 5 (`restore_integrity_uid_gid_mode_and_quiescence`) while keeping all file operations confined to the `/var/tmp/aetherflow-v4-guest-drills*` work root, Phase 5 launches a dedicated runner instance with `AETHERFLOW_BACKUP_ISOLATED_ROOT` **unset** and explicit server-owned environment variables configured:
  - `AETHERFLOW_BACKUP_DIR=<work_root>/phase5_restore_iso/var/lib/aetherflow/backups`
  - `AETHERFLOW_DB_PATH=<work_root>/phase5_restore_iso/var/lib/aetherflow/aetherflow.sqlite`
  - `AETHERFLOW_RESTORE_STAGING_ROOT=<work_root>/phase5_restore_iso`
  - `AETHERFLOW_BACKUP_DRY_RUN_QUIESCENCE=0`

---

## Running Unit Tests (Any Host / CI)

Run the pure validation and evaluation unit tests from the repository root:

```bash
python3 -m unittest discover -s tests -p "test_v4_privileged_guest_drills.py" -v
```

---

## Exact Disposable QEMU/systemd Guest Execution Runbook

Inside a disposable QEMU/systemd guest VM where the candidate binaries and harness are staged under `/var/tmp/aetherflow-v4-stage`:

```bash
# 1. Write the ephemeral disposable-guest marker in /run tmpfs
printf 'AETHERFLOW_DISPOSABLE_GUEST_V4\n' | sudo tee /run/aetherflow-disposable-guest >/dev/null

# 2. Execute the privileged guest drill suite as root inside the disposable QEMU guest
sudo env AETHERFLOW_DISPOSABLE_GUEST=1 \
  python3 /var/tmp/aetherflow-v4-stage/scripts/v4_privileged_guest_drills.py \
  --confirm-disposable-guest \
  --work-root /var/tmp/aetherflow-v4-guest-drills-run \
  --api-bin /var/tmp/aetherflow-v4-stage/bin/aetherflow-api \
  --af-bin /var/tmp/aetherflow-v4-stage/bin/af \
  --json-out /var/tmp/aetherflow-v4-stage/guest-drills-report.json
```

### Exit Codes

- `0`: All 6 mandatory privileged drill phases executed against the real binaries and passed every assertion.
- `1`: One or more drill assertions failed, or a phase reported `pending_contract` / `real_execution=False`.
- `2`: Blocked by `GuestSafetyError` before touching the filesystem (e.g., missing marker, bare-metal host, non-root, or forbidden path).

---

## Trusted Recovery Context, Provenance, and Maintenance Lock Contracts (`af-host`)

### 1. Trusted `RecoveryContext` and Protected Provenance Directory
- **No Unauthenticated Journal Trust:** `recover_interrupted_restore` without an explicit [`RecoveryContext`] fails closed with `HostBackupError::InvalidConfig`. Privileged callers (`af-runner` and `af-cli`) must call `recover_interrupted_restore_with_context(backup_dir, &RecoveryContext, quiescence)` supplying their server-owned `expected_target_root` (`/` or validated isolated root), `trusted_sqlite_db_path`, `trusted_sqlite_uid`, `trusted_sqlite_gid`, and optional `provenance_dir`.
- **Protected Provenance Directory (`resolve_recovery_provenance_dir_with_override`) & Overlap Rejection (P1-1):**
  - Canonical host (`target_root == "/"`): `/etc/AetherFlow/.restore-provenance` (`0700`, owned by effective UID `euid`, created via `open_or_create_provenance_dir_nofollow` which requires `root`/`euid` ownership on every ancestor and never trusts the service account UID when `service_uid != euid`).
  - Isolated staging root (`target_root != "/"`): `<target_root>/.restore-provenance` (`0700`, owned by `euid`).
  - Restore planning and execution explicitly reject any restore destination whose lexical or canonical path overlaps or nests within canonical (`/etc/AetherFlow/.restore-provenance`), target-root (`<target_root>/.restore-provenance`), or custom provenance authority directories, including pending recovery provenance state.
- **Authenticated Candidate Journal Selection & Interrupted Publication Tolerance (P2-8):**
  - Each checkpoint transition increments `generation` and embeds a canonical payload digest (`journal_sha256`).
  - `load_authenticated_recovery_journal` evaluates both the protected provenance journal and the recovery-directory journal, authenticating each against its `O_NOFOLLOW` descriptor-read sidecar (`read_expected_digest_file_nofollow`) and internal `journal_sha256`.
  - If a crash interrupts publication after the provenance journal writes `generation = N` before its `.sha256` sidecar or local recovery journal finishes updating, recovery selects the highest-generation authenticated valid checkpoint and never prefers an unauthenticated or corrupted higher generation over a valid lower generation.

### 2. Descriptor-Bound Staging/Rollback Installation, Irreversible Authority Commit, and Cleanup Ordering (P1-2, P1-3, P1-4, P2-9)
- **Descriptor/Inode/Digest Binding Across Staging & Rollback (P1-2):**
  - Staged and rollback files record `(st_dev, st_ino, size_bytes, sha256)` at capture/hash time (`VerifiedFileHandle` / `RollbackFileEntry`).
  - Before any install or rollback copy, `open_regular_file_verified` re-opens the file via `open_dir_chain_nofollow` + `openat(..., O_RDONLY | O_CLOEXEC | O_NOFOLLOW)`, asserts exact `(st_dev, st_ino, size_bytes)` identity when required, and streams + re-verifies the full SHA-256 from that exact file descriptor before installing into a descriptor-locked parent directory (`atomic_install_from_verified_fd`).
- **Irreversible Durable Authority Commit & Rollback Precedence (P1-3):**
  - Once all staged files are atomically installed and verified, `persist_recovery_checkpoint` publishes `journal_state = "committed"` to the protected provenance directory **first**. As soon as the provenance journal + sidecar are durably synced (`ProvenanceCommitted`), commit is irreversible (`CheckpointPersistenceOutcome::ProvenanceCommitted { local_sync_error }`), even if the subsequent local recovery-directory journal write fails.
  - Before entering rollback, `execute_staged_restore` transitions provenance authority to `journal_state = "rolling_back"` (`file_rollback_incomplete = true`). During recovery, if provenance is `rolling_back`, recovery never accepts a stale local `committed` journal and forces full rollback completion.
- **Recovery Stop Failure Quiescence Boundary (P1-4):**
  - Initial pre-mutation stop failure (`stop_and_verify_services` before any target file or recovery journal mutation) compensates by restarting any services stopped during that pre-flight stop attempt.
  - During `recover_interrupted_restore_with_context`, `stop_and_verify_services_for_recovery` **never** runs stop-failure compensation that would restart writers over partially restored state; services remain quiesced until terminal rollback completes.
- **Authority-Last Cleanup & Error Surfacing (P2-9):**
  - `cleanup_recovery_dir` removes the unprivileged recovery directory contents and directory **before** unlinking the protected provenance journal and sidecar (`remove_provenance_files_strict`), surfacing any unlink or removal errors (`HostBackupError::RecoveryCleanupFailed`) rather than silently ignoring them or orphaning an unauthenticated recovery directory.

### 3. Deterministic Maintenance Lock, Non-Root Metadata Enforcement, & SQLite Source/Snapshot Contracts (P1-5, P1-6, P1-7, P2-10, P2-11, P2-12)
- **Stable Maintenance Lock Resolution & Parent Preservation (P1-5, P2-11):**
  - The packaged shared maintenance lock defaults to `/run/aetherflow/.snapshot.lock`, with the corresponding contained runtime path for isolated roots. An explicit server-owned `AETHERFLOW_MAINTENANCE_LOCK_PATH` remains supported. Root acquisition rejects replaceable lock ancestors, including service-owned data parents; it does not chown or clobber existing data-directory permissions. The root-owned runtime anchor and sticky directory mode allow the packaged service group to share the root-owned lock inode without unlinking it.
  - `HostMaintenanceLockGuard` opens the lockfile with `openat(..., O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o660)`, validates `fstat(fd)`, acquires `flock`, verifies that the opened descriptor still matches `fstatat` at the path `(st_dev, st_ino)` after locking, and enforces `fchown`/`fchmod` on the descriptor. When running non-root (`euid != 0`), if `fchown` fails or the resulting `(st_uid, st_gid)` does not match `(euid, service_gid)` or `(euid, egid)`, lock acquisition fails closed instead of ignoring the mismatch.
- **SQLite Non-Follow Descriptor Verification & WAL-Free Snapshot Contract (P1-6, P1-7, P2-10, P2-12):**
  - Pre-open `O_NOFOLLOW` checks (`validate_sqlite_source_paths_with_trusted_uid`, `open_verified_sqlite_source_set`) verify that the main DB and any present `-wal`/`-shm` sidecars are regular files in a root/trusted-owned parent directory and bind `(st_dev, st_ino)` across pre-open and post-open connection acquisition (`verify_sqlite_source_set_unchanged`). Because standard SQLite VFS opens files by pathname, this bounds the race window and detects post-open inode replacement rather than claiming kernel-level VFS `openat` immunity.
  - Online backups convert the staged snapshot to `journal_mode = DELETE` and truncate any WAL before closing, and `verify_sqlite_snapshot_integrity_with_trusted_uid` rejects any snapshot accompanied by `-wal`/`-shm` sidecars, opens the snapshot read-only (`SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_NO_MUTEX`), verifies descriptor `(st_dev, st_ino)` + SHA-256 parity before and after `PRAGMA integrity_check`, and supports explicit configured `trusted_sqlite_uid` (`P2-12`).
  - Checksum sidecar verification (`read_expected_digest_file_nofollow`) uses `O_NOFOLLOW` bounded descriptor reads and emits non-disclosing `InvalidFormat` errors (`P1-7`).
  - Public restore planning and preflight expose additive `sqlite_target_rel_path` + `trusted_sqlite_uid` parity (`plan_restore_from_manifest_with_sqlite_overrides`, `preflight_restore_directory_with_sqlite_overrides_and_trusted_uid`, `preflight_tar_gz_archive_with_sqlite_overrides_and_trusted_uid`, `verify_backup_artifact_with_trusted_uid`) matching `execute_staged_restore` (`P2-10`, `P2-12`).

### 4. Evidence Boundary: Deterministic Crate/Non-Root Fixture Tests vs. Live Disposable VM Drills
- **Deterministic Linux Host & Non-Root Fixture Evidence (`cargo test -p af-host`):**
  - Verifies the security/recovery contracts above (including fault-injected provenance/local journal partial publication, recovery stop failure quiescence, inode-swap detection on staged/rollback files, maintenance lock parent-mode preservation, custom `trusted_sqlite_uid`, `sqlite_target_rel_path` preflight/plan parity, and non-root `setpriv --reuid=65534 --regid=65534` execution) using deterministic unit and temporary filesystem fixtures.
  - Independently trusted custom database ownership is configured through `AETHERFLOW_TRUSTED_SQLITE_UID` / `AETHERFLOW_TRUSTED_SQLITE_GID`, not inferred from archive metadata. The guest ownership fixture explicitly supplies those server-owned values. The CLI WAL fixture copies the verified backup generation inside its isolated root rather than weakening the outside-root rejection.
  - Publication uses an executor-private, descriptor-pinned installation directory rather than a loose temporary filename in a service-writable directory. The SQLite identity regression substitutes a different regular database during connection opening, restores the original name before validation, and keeps an independent original connection open; the connection-specific VFS identity check must reject it.
  - **What crate tests do NOT replace:** Deterministic crate tests use mock/scripted `QuiescenceController` implementations and temporary directories; they do **not** exercise live `systemd` service unit stop/start transitions, Unix domain socket `SO_PEERCRED` enforcement on `aetherflow-api runner`, or full guest-level CLI-to-runner IPC. Those remain the exclusive domain of `scripts/v4_privileged_guest_drills.py` inside a disposable QEMU/systemd Linux guest VM.
