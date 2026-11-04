# AetherFlow v4 Lifecycle & Transient-Systemd Self-Update Guest Drills Runbook (`scripts/v4_lifecycle_guest_drills.py`)

## Overview & Safety Boundaries

`scripts/v4_lifecycle_guest_drills.py` is a stdlib-only Python verification harness that exercises the real shipped `aetherflow-api` (`aetherflow-api runner` running as a genuine isolated `aetherflow-runner.service` systemd unit), `af` (`af-cli` / `af-release`), `systemctl`, and `systemd-run` binaries inside a **disposable QEMU/systemd Linux guest VM**.

It reuses the six fail-closed disposable-guest guardrails (`verify_guest_execution_guardrails`) from `scripts/v4_privileged_guest_drills.py` before creating any directory, unit file, or process:

1. **OS & Effective Identity:** Requires `sys.platform.startswith("linux")` and `os.geteuid() == 0`.
2. **Explicit CLI Confirmation:** Requires `--confirm-disposable-guest`.
3. **Environment Marker:** Requires `AETHERFLOW_DISPOSABLE_GUEST=1`.
4. **Ephemeral `/run` Guest Marker File:** Requires `/run/aetherflow-disposable-guest` (or `--guest-marker-file` under `/run/`) containing the token `AETHERFLOW_DISPOSABLE_GUEST_V4`.
5. **QEMU/KVM Virtualization Probe:** Verifies `systemd-detect-virt --vm` and `/sys/class/dmi/id/*` match `qemu`, `kvm`, `bochs`, or `standard pc`. Bare-metal hosts fail closed with exit code `2`.
6. **Isolated Work Root & Binary Path Guard:** Requires `--work-root` under `/var/tmp/aetherflow-v4-guest-drills*`, rejects any binary or target path inside `/opt/AetherFlow`, `/var/lib/aetherflow`, `/etc/aetherflow`, or `/run/aetherflow/runner.sock`, and refuses to overwrite any existing `/etc/systemd/system/aetherflow-*.service` unit file that references `/opt/AetherFlow`.
7. **Systemd Lifecycle Permission:** Before mutating the work root, requires a root-owned regular non-symlink `/etc/aetherflow-disposable-guest` containing the exact guest token. The disposable runner explicitly sets `AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE=1`; the runner forwards that server-owned flag to both native and shell transient updaters. This flag alone does not bypass the marker requirement in either release engine.

---

## Observed Debian 13 Run: November 3, 2026

All **24/24 assertions in the five real lifecycle phases pass** in a fresh
Debian 13 amd64 QEMU/systemd guest. The source is the provisional frozen stage
`parent-rollback-integrity-20261103-140144` under
`/var/tmp/aetherflow-v4-validation-20261103-052723` on the validation host.
Its source-manifest SHA-256 is
`dd246050355f69d6ace984f2bca94ecc44fde5fcf1205ba44a2643e49e6e50f6`.

| Phase | Assertions |
| --- | --- |
| Binary and systemd provenance | 5/5 |
| Isolated runner and request validation | 5/5 |
| Self-stop rejection without file/controller drift | 6/6 |
| External updater survives runner restart; native SQLite rollback | 4/4 |
| Failed unpublished deploy and durable failure receipt | 4/4 |

The real rollback restores the golden SQLite rows with integrity `ok` and mode
`0600`, quarantines the corrupt database, removes stale WAL/SHM files, selects
the expected previous release, and leaves both disposable units active. Its
success receipt survives controller restart and transient-unit collection.
The unpublished deploy returns a validated terminal failure receipt with exit
code `4` and preserves the active release. This does not test a successful
remote native deploy or a published production artifact.

Evidence is in `logs/guest-suites-20261103-200302` under the validation root:

| Artifact | SHA-256 |
| --- | --- |
| `lifecycle-report.json` | `86bb1958be027ba8e76c8ceb9728d3ff3f43bd2cbdc57c0782c87dc38ba418cf` |
| `vm-execution.json` | `602ba35855b5dd9d40218482c0d01df2f3f4168a3055d35c32996cb990f540a7` |
| `lifecycle-work.tar.gz` | `779d816fc000895a899038c27a726165880c00691e3f3c5b37d29bd8a296e5d7` |

The staged debug binaries in `lifecycle-builds-20261103-140144/debug` are:

| Binary | SHA-256 |
| --- | --- |
| `aetherflow-api` | `4e70e0b8ca6e75a70cbc4b15e48444d6c91c54abaa470a885fd3e37cb88461ba` |
| `af` | `cabce16d36768a066839e9119ecb8181377a4d51678384f8f0699daff825ff14` |

The harness digest is
`d9963809dd11c4b5cd51113d9e4c228a43f00ecb3f5a2a25457fe414ee6a0683`.
The driver confirms owned QEMU PID `2470549` is absent after teardown. No
production operation or YouTube test ran.

Earlier failed runs exposed fixture mistakes: the runner uses
`AETHERFLOW_RUNNER_SOCK` and `/v1/health`; `SQLITE_DB` is a filename while the DB
environment overrides are absolute paths; snapshot manifests use relative
member names; UDS requests require string paths. Report encoding now supports
explicit `Path` values without coercing arbitrary unknown evidence types.
Those corrections retain every integrity, ownership, receipt, and restart
assertion rather than relaxing them.

The failures also exposed a genuine native engine defect: database recovery
errors previously produced a successful rollback receipt. The repaired native
engine persists `Failed`, attempts writer quiescence, returns a rollback error,
and does not restart database services after recovery failure. A focused Linux
regression covers both successful and failed stop attempts while preserving DB
and WAL bytes. All 19 release tests and 34 runner tests plus strict all-target
Clippy pass in `logs/parent-rollback-integrity-20261103-140144`. The corresponding
24-assertion run exercises successful corruption recovery and failed remote
artifact fetch, not the malformed-snapshot failure path. The later six-phase
run below adds and verifies that negative scenario.

This is a bounded Debian 13 debug-binary pass, not final merged-source,
cross-UID/crash-boundary host-recovery, portable release, shell-fallback, or
four-OS certification. The separate host repair and final independent reviews
remain open.

## Rejected Snapshot Failure: Six-Phase Guest Pass

The derived provisional source `parent-rollback-shm-20261103-143504` passes
**29/29 assertions across all six real Debian 13 guest phases**. Its manifest
SHA-256 is `191faad468e2a7b1e350649687013a5956363f416c9933434e3c6bb4ed6d4e50`.
This source deliberately retains the earlier host engine while that engine's
separate fixed-scope repair is in progress; it is not the final merged product.

The runner is the real `aetherflow-api runner` binary. The separate
`aetherflow-api.service` lifecycle target is an explicitly provisioned Python
sleeper, not a running application/API writer. These drills establish real
systemd target stop/restart behavior and isolated SQLite restoration, not API
readiness after a schema migration or safety with an intervening live writer.
Those application-level checks remain part of final clean-OS acceptance.

The new final phase corrupts the isolated database and WAL/SHM, rejects a
wrong snapshot digest through the real runner and external native updater,
and requires a durable failed receipt (`exit_code: 7`), failed recovery state,
unchanged database/WAL/SHM bytes and metadata, and both database units stopped.
It explicitly starts only the control runner to query the same durable failure;
the API writer remains stopped. No writer restart is used to make the drill pass.

The first six-phase attempt at `logs/guest-suites-20261103-203222` correctly
failed because SQLite's read-only integrity query expanded an invalid-header
database's SHM sentinel from 30 to 32768 bytes. An isolated reproduction also
observes this with both default and `sqlite3 -readonly` CLI opens. Native and
shell integrity helpers now reject non-SQLite headers through a regular-file
descriptor before opening SQLite. The Rust rollback regression checks SHM as
well as DB/WAL. This closes the observed invalid-header side effect, not broader
valid-header/WAL substitution or cross-UID SQLite race guarantees.

Evidence is under `logs/guest-suites-20261103-203828` in the validation root:

| Evidence | SHA-256 |
| --- | --- |
| Debug `aetherflow-api` | `08460bc0bb23e55e01f47abd86030ab65fab6fe86d0b15317881a5548576a29f` |
| Debug `af` | `0abde3a31d0437940098697e5440e0f62b62a5ca1aa7662a40bf2d10694fbc9e` |
| Lifecycle harness | `7619f4105b3c8f25f57bf069c76a9504ef3b51aa651b781476ac2fc41b807223` |
| `lifecycle-report.json` | `01543042b2c75a55fb55447ee10c2dd5eaa7d64c69994a22e43890a8e49c81fd` |
| `vm-execution.json` | `ca689babf0dee2b533a125097672f790c462d11e7110aa04196a662e1c332d66` |
| `lifecycle-work.tar.gz` | `e5651053476d58113a0b7317ec873b7266974ac0b19fec7c4957ba26c057a063` |

The driver confirms owned QEMU PID `2502044` is absent after teardown. Locked
release/runner tests pass (19 + 34), strict all-target Clippy passes, and both
binaries build successfully. Logs are in `logs/parent-rollback-shm-20261103-143504`.
All 32 lifecycle Python tests pass on Linux and Windows; all 56 guest-harness
Python tests pass together on Windows.

The shell fallback also now checks snapshot manifest digests, propagates stop
and filesystem mutation failures, exits nonzero after failed recovery, and
never emits rollback completion or restarts writers on that branch. All 28
Linux shell tests pass, including wrong/missing/duplicate digest, failed stop,
unchanged corrupt DB/WAL/SHM, and durable failure receipt cases. Those tests use
mocked systemd, not real shell guest lifecycle certification. Evidence is
`logs/shell-failure-20261103-143257.log`. The separate bounded real-shell probe
below supplies additional lifecycle evidence. Successful remote deploy, final
host integration, portable release, live application-writer acceptance, and the
four-OS matrix remain separate open gates.

## Bounded Real Shell Fallback Guest Pass

A separate fresh Debian 13 guest passes **12/12 top-level assertions** plus
five nested setup checks using the same debug binaries fingerprinted above.
The real runner explicitly selects `legacy_bash_release` with native release
disabled and shell forced, passing the protected isolated configuration and
explicit shell path to external transient updater units in separate cgroups.

The positive rollback restores golden SQLite rows from the verified snapshot,
removes stale WAL/SHM, quarantines corruption, reverts the release link, restarts
the runner and API lifecycle fixture, and preserves its durable success receipt
(`exit_code: 0`) across the runner's own stop/restart. The negative rollback
rejects a wrong snapshot digest, preserves DB/WAL/SHM bytes and metadata, stops
both units, and leaves a durable failed receipt (`exit_code: 4`). Starting only
the control runner returns that same failure without starting the API target.

The API target is the same explicitly labeled sleeper fixture, not a live
application writer. This is real guest/systemd and shell rollback evidence,
not successful deployment, application readiness, arbitrary live-writer
recovery, cross-OS compatibility, or final-source certification. Failed service
stop injection is still covered by mocked-systemd regression, not this probe.

Evidence is preserved at `logs/shell-guest-20261103-204721` in the validation root:

| Evidence | SHA-256 |
| --- | --- |
| Shell source `release-manager.sh` | `f79f717b0252c77e68d28e7dbf93e20825267e1269a5ae56c5fb70bd4a4ed17d` |
| Preserved `shell-guest-drill.py` | `e1b0c21eaa4ccade46cc4610cea6c17c1a7f9e65b32b88ffcbf15e08d354cb5f` |
| `shell-report.json` | `1082a5b9fd3d25972933e5b1025a7ad25ba002ad9b8fe05f1d78a11bb4a10f20` |
| `vm-execution.json` | `110f9dc3e2bd9d4cfe1c952935f37041a2372d2b879595cbcfb2d56ad1ddbe22` |
| `shell-work.tar.gz` | `c5ebcc38da43b52e19e5723e249f91d26c63788a3b1f9f2ededd8ab75cb0dc2c` |

Owned QEMU PID `2506884` is confirmed absent after teardown. The parent driver
is retained at `%TEMP%/aetherflow-v4-completion/run-shell-rollback-guest.py`;
the executed guest probe, package provisioning log, report, commands, and
isolated work archive remain in the evidence directory. An earlier probe
failed closed on a fixture's misplaced systemd environment directive; its
separate evidence is `logs/shell-guest-20261103-204557`.

## Mandatory Lifecycle Drill Phases (`MANDATORY_LIFECYCLE_PHASES`)

The harness evaluates all 6 phases fail-closed (`evaluate_lifecycle_drill_suite_status`). Any missing phase, unexecuted phase (`real_execution=False`), pending contract (`status="pending_contract"`), or failed assertion forces `overall_passed=False` and exit code `1`.

| Phase ID | Exercised Surface | Required Checks |
| --- | --- | --- |
| `binary_and_systemd_environment_provenance` | `aetherflow-api`, `af --json version`, `systemctl --version`, `systemd-run`, optional `--source-manifest` and `--release-artifact` | Records SHA-256, byte size, mode, and UID/GID of staged `aetherflow-api` and `af` binaries, verifies `systemctl` and `systemd-run` presence, verifies `af --json version` envelope, and ensures no live `/opt/AetherFlow` systemd unit is present. |
| `isolated_systemd_runner_and_self_update_validation` | Disposable `/etc/systemd/system/aetherflow-runner.service` + `aetherflow-api.service` + `POST /v1/self-update` over UDS | Starts a genuine `aetherflow-runner.service` unit with server-owned environment (`AETHERFLOW_RUNNER_SOCK`, `AETHERFLOW_CLI_BIN`, `AETHERFLOW_ENABLE_RUST_RELEASE=1`, `AETHERFLOW_FORCE_BASH_RELEASE=0`, `AETHERFLOW_RELEASE_ROOT`, `AETHERFLOW_MAINTENANCE_LOCK_PATH`, `AF_DB_PATH`, `DB_PATH`, `AETHERFLOW_DB_PATH`, `AETHERFLOW_BACKUP_DIR`, `AETHERFLOW_RESTORE_STAGING_ROOT`, `AETHERFLOW_BACKUP_DRY_RUN_QUIESCENCE=0`), records initial `MainPID`, `ControlGroup`, `InvocationID`, and `/proc/<pid>/cgroup`, and verifies `/v1/self-update` rejects invalid commands (`HTTP 400`, `"invalid self-update command"`) and invalid channels (`HTTP 400`, `"invalid update channel"`). |
| `self_stop_quiescence_rejection_preserves_controller` | `POST /v1/backup` (`create_archive`, `restore_execute`) + `validate_quiesce_service_entries` (`crates/af-host/src/restore.rs:254-305`) | Verifies that `restore_execute` requests containing `"aetherflow-runner.service"`, `"aetherflow-runner"`, `"AETHERFLOW-RUNNER.SERVICE"`, or bypass tokens (`"skip"`) in `quiesce_services` fail closed with `HTTP 400` (`"quiesce_services must not include the active control worker unit"` / `"unsafe quiesce_services bypass entry rejected"`) **before** any `systemctl stop` runs, proving `aetherflow-runner.service` `MainPID` is unchanged, `ActiveState == "active"`, and live target files (`aetherflow.sqlite`, `.env`, `lock.json`) have zero drift. |
| `transient_unit_cgroup_survival_and_native_rollback_recovery` | `POST /v1/self-update` (`{"command": "rollback", "channel": "stable"}`) -> `systemd-run --unit=aetherflow-self-update-rollback-stable-<8hex>.service` -> `af release rollback --channel stable --local --config <conf>` | Corrupts the live isolated SQLite database (with stale `-wal`/`-shm` sidecars), holds a short `flock` on `AETHERFLOW_MAINTENANCE_LOCK_PATH` to freeze the updater at a deterministic in-flight interruption boundary, asserts `HTTP 200` with `status == "initiated"`, `completed == false`, `engine == "native_rust_release"`, and `job_unit`, proves `job_unit` runs in an external systemd cgroup (`/system.slice/aetherflow-self-update-rollback-stable-<8hex>.service` != `/system.slice/aetherflow-runner.service`), **deliberately restarts `aetherflow-runner.service`** (`MainPID` rotates), proves the updater PID/unit survives uninterrupted, releases the lock, and verifies native `af-release` rollback completion (`CURRENT_LINK` atomically swapped back to `1700000001_good`, corrupted DB quarantined to `aetherflow.sqlite.corrupted.*`, stale `-wal`/`-shm` unlinked, verified `data-snapshot/aetherflow.sqlite.bak` restored with mode `0600`, `PRAGMA integrity_check == "ok"`, golden marker rows intact, `.recovery_state.json` `phase == "complete"`, and both `aetherflow-runner.service` and `aetherflow-api.service` active). |
| `native_deploy_artifact_provider_contract_probe` | `af --json release deploy --offline` + `POST /v1/self-update` (`{"command": "deploy", "channel": "stable"}`) | Verifies `af release deploy --offline` without `--dry-run` fails closed (`"--offline is only valid with --dry-run"`), verifies `POST /v1/self-update` (`command: "deploy"`) spawns `aetherflow-self-update-deploy-stable-<8hex>.service`, and verifies `CURRENT_LINK` remains safely pinned to the active healthy release when Stage 1 remote GitHub fetch fails closed in an offline/loopback guest. |
| `rejected_snapshot_rollback_preserves_failure_and_quiescence` | Real native rollback through UDS/transient systemd with a corrupt database and rejected snapshot digest | Requires a nonzero durable failed receipt, failed recovery state, unchanged DB/WAL/SHM bytes and metadata, both database units stopped, and the same failure after starting only the control runner; the API writer remains stopped. Runs last. |

---

## Architecture & Contract Notes

### 1. Transient-Unit Environment Forwarding & `release-manager.conf` Resolution

The converged runner and CLI use explicit isolated configuration and durable job
receipts. The harness must match this contract rather than rely on the older
working-directory discovery behavior:

1. `spawn_self_update_transient_unit` invokes:
   ```text
   systemd-run --unit=aetherflow-self-update-<command>-<channel>-<8hex>.service \
     --collect --no-block --property=Type=exec --property=KillMode=control-group \
     [--setenv=K=V ...] \
     <af_bin> --root <isolated_root> release <deploy|rollback> --channel <channel> \
       --local --config <protected_config_snapshot> \
       --job-status-file <durable_receipt> --job-unit <unit>
   ```
2. The fixture sets both `AETHERFLOW_RELEASE_ROOT` and an explicit
   `AETHERFLOW_RELEASE_CONF` in its disposable runner unit. Every configured
   filesystem path stays under `<work_root>/lifecycle_iso`; no production config
   or working-directory fallback is needed.
3. The runner validates the isolated configuration, persists a protected config
   snapshot, and forwards the root, config, shared maintenance lock, database,
   backup, and receipt paths to the transient unit. The CLI consumes the explicit
   root and config snapshot.
4. After rollback, the harness queries `POST /v1/self-update/status` and requires
   a terminal success receipt for the exact job, after the runner has restarted
   and the transient unit has completed. A running/initiation acknowledgment is
   not completion evidence. The failed deploy probe must return a durable failure
   receipt with a nonempty diagnostic instead.
5. The deploy probe uses an unpublished synthetic GitHub repository, never the
   production release repository. It tests fail-closed remote fetch and preserves
   the current release without attempting an uncontrolled production upgrade.

### 2. Honest Contract Report: Native `deploy` (`GithubHttpArtifactProvider`) vs Native `rollback`

Inspection of `backend-rs/crates/af-release/src/artifact.rs` and `ReleaseOptions` in `backend-rs/crates/af-release/src/config.rs` shows:

- `ReleaseEngine::new_production(cfg)` constructs `GithubHttpArtifactProvider::default()`, which hardcodes:
  - `api_base_url: None` -> fallback `"https://api.github.com"`
  - `download_base_url: None` -> fallback `"https://github.com"`
- Neither `ReleaseConfig::load_with_env` nor `GithubHttpArtifactProvider::default()` reads an environment variable or `release-manager.conf` key to override `api_base_url` or `download_base_url` to a loopback `http://127.0.0.1:<port>` server.
- `ReleaseOptions::validate()` rejects `--offline` unless `--dry-run` is also enabled (`"--offline is only valid with --dry-run; refusing to deploy a placeholder binary"`), and `af-runner` does not pass `--dry-run` to the transient unit.
- Consequently:
  - Phase 4 asserts real native rollback execution, cgroup isolation,
    runner-restart survival, atomic `CURRENT_LINK` swap, SQLite corruption
    recovery, service restart, and a durable terminal success receipt.
  - Phase 5 asserts deploy initiation, `--offline` validation, terminal failure
    reporting, and preservation of `CURRENT_LINK` after the synthetic repository
    fetch fails. This is not verified-artifact deployment certification.

---

## Verification Status: Local Unit Tests vs Live Disposable Guest Execution

- **Verified in this task (Local Python Unit Tests):**
  - `tests/test_v4_lifecycle_guest_drills.py` (32 unit tests) passes on Windows and Linux (`OK`).
  - Covers disposable-guest guardrails, isolated path containment, `/v1/self-update` initiation JSON contract (`status: "initiated"`, `completed: false`, `job_unit`), cgroup isolation and runner-restart survival evaluation, self-stop quiescence rejection evaluation, rollback outcome & SQLite recovery evaluation, fail-closed suite evaluation, and unit/process cleanup.
- **Live Disposable Guest VM:**
  - The six-phase, 29-assertion provisional native run and its limits are recorded
    separately above. Unit passes do not establish guest or final-merge evidence.

---

## Running Unit Tests (Local Host / CI)

From the repository root (`C:\Users\armyw\OneDrive\Documents\Antigravity\AetherFlow` or Linux checkout):

```bash
python -m unittest discover -s tests -p "test_v4_lifecycle_guest_drills.py" -v
```

---

## Exact Commands for Parent to Run Inside a Disposable QEMU/systemd Guest

Stage the matching `aetherflow-api` and `af` binaries, source-manifest JSON file,
and both guest harnesses under `/var/tmp/aetherflow-v4-stage` in a fresh
disposable QEMU/systemd guest. Do not delete pre-existing units to bypass the
harness guardrails. If a production unit is detected, abandon that guest image
and use a clean disposable guest instead.

```bash
# 1. Write the required ephemeral disposable-guest marker in /run tmpfs
printf 'AETHERFLOW_DISPOSABLE_GUEST_V4\n' | sudo tee /run/aetherflow-disposable-guest >/dev/null
printf 'AETHERFLOW_DISPOSABLE_GUEST_V4\n' | sudo tee /etc/aetherflow-disposable-guest >/dev/null
sudo chown root:root /etc/aetherflow-disposable-guest
sudo chmod 0600 /etc/aetherflow-disposable-guest

# 2. Execute the guarded lifecycle & transient-systemd self-update guest drill suite as root
sudo env AETHERFLOW_DISPOSABLE_GUEST=1 \
  python3 /var/tmp/aetherflow-v4-stage/scripts/v4_lifecycle_guest_drills.py \
  --confirm-disposable-guest \
  --work-root /var/tmp/aetherflow-v4-guest-drills-lifecycle \
  --api-bin /var/tmp/aetherflow-v4-stage/bin/aetherflow-api \
  --af-bin /var/tmp/aetherflow-v4-stage/bin/af \
  --source-manifest /var/tmp/aetherflow-v4-stage/source-manifest.json \
  --json-out /var/tmp/aetherflow-v4-stage/lifecycle-guest-drills-report.json
```

### Exit Codes

- `0`: All 6 mandatory lifecycle guest drill phases executed against the real binaries and systemd units in the disposable guest and passed every assertion.
- `1`: One or more drill assertions failed, or a phase reported `pending_contract` / `real_execution=False`.
- `2`: Blocked by `GuestSafetyError` before touching the filesystem or systemd (e.g., missing marker, bare-metal host, non-root, or forbidden `/opt/AetherFlow` path).
- `3`: Unexpected harness runtime error.
