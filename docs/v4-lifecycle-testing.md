# AetherFlow v4 Lifecycle & Transient-Systemd Self-Update Guest Drills

## Overview & Safety Boundaries

`scripts/v4_lifecycle_guest_drills.py` is a stdlib-only Python verification harness that exercises the shipped `aetherflow-api` (`aetherflow-api runner` running as an isolated `aetherflow-runner.service` systemd unit), `af` (`af-cli` / `af-release`), `systemctl`, and `systemd-run` binaries inside a **disposable QEMU/systemd Linux guest VM**.

It imports six fail-closed disposable-guest guardrails (`verify_guest_execution_guardrails`) from `scripts/lib/vm_guest_common.py`, adds a seventh local systemd marker check (`verify_lifecycle_systemd_marker`), and loads suite evaluators from `scripts/lib/vm_lifecycle_evaluators.py` before creating any directory, unit file, or process (with production-unit overwrite refusal enforced during Phase 1):

1. **OS & Effective Identity**: Requires `sys.platform.startswith("linux")` and `os.geteuid() == 0`.
2. **Explicit CLI Confirmation**: Requires `--confirm-disposable-guest`.
3. **Environment Marker**: Requires `AETHERFLOW_DISPOSABLE_GUEST=1`.
4. **Ephemeral `/run` Guest Marker File**: Requires `/run/aetherflow-disposable-guest` (or `--guest-marker-file` under `/run/`) containing `AETHERFLOW_DISPOSABLE_GUEST_V4`.
5. **QEMU/KVM Virtualization Probe**: Verifies `systemd-detect-virt --vm`, `/sys/class/dmi/id/*`, or `/sys/hypervisor/type` matches `qemu`, `kvm`, `bochs`, or `standard pc`. Bare-metal hosts fail closed with exit code `2`.
6. **Isolated Work Root & Binary Path Guard**: Requires `--work-root` under `/var/tmp/aetherflow-v4-guest-drills*` (rejected against `FORBIDDEN_HOST_PATHS`, including `/opt/AetherFlow`, `/var/lib/aetherflow`, `/etc/aetherflow`, and `/run/aetherflow/runner.sock`), rejects `--api-bin` / `--af-bin` inside `/opt/AetherFlow` or `/opt/aetherflow` (`validate_binary_not_in_live_host_tree`), and in Phase 1 (`run_phase_1_binary_and_systemd_provenance`) refuses to overwrite any existing `/etc/systemd/system/aetherflow-*.service` referencing `/opt/AetherFlow`.
7. **Systemd Lifecycle Permission (`verify_lifecycle_systemd_marker`)**: Requires a root-owned regular non-symlink `/etc/aetherflow-disposable-guest` containing `AETHERFLOW_DISPOSABLE_GUEST_V4`. The disposable runner sets `AETHERFLOW_ALLOW_ISOLATED_SYSTEMD_LIFECYCLE=1` and forwards it to both native and shell transient updaters; the flag alone does not bypass the `/etc/aetherflow-disposable-guest` marker check.

---

## Observed Debian 13 Guest Runs (November 3, 2026)

### Six-Phase Native Rollback & Rejected-Snapshot Pass (29/29 Assertions)

In a fresh Debian 13 amd64 QEMU/systemd guest run on November 3, 2026 (manifest SHA-256 `191faad468e2a7b1e350649687013a5956363f416c9933434e3c6bb4ed6d4e50`), all **29/29 assertions across all six mandatory phases** passed:

- **Phases 1–5**: Verified binary/systemd provenance, isolated runner request validation, self-stop quiescence rejection without controller/file drift, transient-unit cgroup survival across runner restart + native SQLite corruption rollback (`PRAGMA integrity_check == ok`, mode `0600`, corrupt DB quarantined, stale WAL/SHM removed, durable success receipt preserved), and failed unpublished deploy preserving the active release with a durable failure receipt.
- **Phase 6 (Rejected Snapshot Failure)**: Corrupted the isolated DB and WAL/SHM, rejected a mismatched snapshot digest through the real runner and external native updater, and verified a durable failed receipt (`exit_code: 7`), failed recovery state, unchanged DB/WAL/SHM bytes and metadata (preventing SQLite's read-only open from expanding an invalid-header SHM sentinel), and both database units left stopped (restarting only the control runner to read the durable failure while keeping the API writer stopped).

> [!NOTE]
> In these drills, `aetherflow-runner.service` runs the real `aetherflow-api runner` binary while `aetherflow-api.service` is an isolated sleeper lifecycle target rather than a live API database writer. These runs prove real systemd cgroup isolation and isolated SQLite restoration; live application-writer readiness and full four-OS matrix certification remain separate gates ([Clean-Host KVM Matrix Testing](./v4-clean-host-testing.md)).

### Bounded Real Shell Fallback Guest Pass (12/12 Assertions)

A separate fresh Debian 13 guest passed **12/12 top-level assertions** (plus 5 setup checks) with `legacy_bash_release` forced, verifying positive rollback recovery across runner restart (`exit_code: 0`) and negative wrong-digest rejection (`exit_code: 4`) leaving DB/WAL/SHM unchanged and both units stopped.

---

## Mandatory Lifecycle Drill Phases (`MANDATORY_LIFECYCLE_PHASES`)

`evaluate_lifecycle_drill_suite_status` (`scripts/v4_lifecycle_guest_drills.py`, delegating to `evaluate_drill_suite_status` in `scripts/lib/vm_guest_common.py`) evaluates all 6 phases fail-closed; any missing, unexecuted (`real_execution=False`), `pending_contract`, or failed phase forces `overall_passed=False` and exit code `1`:

| Phase ID | Exercised Surface | Required Checks |
| :--- | :--- | :--- |
| `binary_and_systemd_environment_provenance` | `aetherflow-api`, `af --json version`, `systemctl`, `systemd-run` | Records SHA-256, byte size, mode, and UID/GID of staged `aetherflow-api` and `af`, verifies `systemctl`/`systemd-run` and `af --json version`, and confirms no live `/opt/AetherFlow` systemd unit exists. |
| `isolated_systemd_runner_and_self_update_validation` | Disposable `aetherflow-runner.service` + `aetherflow-api.service` + `POST /v1/self-update` | Starts `aetherflow-runner.service` with isolated environment variables, records `MainPID`/`ControlGroup`/`InvocationID`, and verifies `/v1/self-update` rejects invalid commands and invalid channels (`HTTP 400`). |
| `self_stop_quiescence_rejection_preserves_controller` | `POST /v1/backup` (`create_archive`, `restore_execute`) + `validate_quiesce_service_entries` (`backend-rs/crates/af-host/src/restore/policy.rs`) | Verifies `quiesce_services` containing `aetherflow-runner.service`, `aetherflow-runner`, uppercase variants, or bypass tokens (`skip`) fail closed with `HTTP 400` before `systemctl stop`, leaving runner `MainPID` and target files unchanged. |
| `transient_unit_cgroup_survival_and_native_rollback_recovery` | `POST /v1/self-update` (`rollback`, `stable`) -> `aetherflow-self-update-rollback-stable-<8hex>.service` | Corrupts isolated SQLite + sidecars, pauses updater on `AETHERFLOW_MAINTENANCE_LOCK_PATH`, verifies separate cgroup, deliberately restarts `aetherflow-runner.service`, releases lock, and verifies atomic symlink rollback, DB quarantine/restoration (`0600`, `integrity_check == ok`), `.recovery_state.json` `phase == "complete"`, durable receipt, and active units. |
| `native_deploy_artifact_provider_contract_probe` | `af --json release deploy --offline` + `POST /v1/self-update` (`deploy`, `stable`) | Verifies `--offline` without `--dry-run` fails closed, verifies transient unit spawn for `deploy`, and verifies `CURRENT_LINK` stays pinned to the active healthy release with a durable failure receipt when remote fetch fails in an offline guest. |
| `rejected_snapshot_rollback_preserves_failure_and_quiescence` | Real native rollback with corrupt DB and mismatched snapshot digest | Requires nonzero durable failed receipt, failed recovery state, unchanged DB/WAL/SHM bytes and metadata, both database units stopped, and consistent status after restarting only the control runner. Runs last. |

---

## Architecture & Contract Notes

### 1. Transient-Unit Environment Forwarding & Config Resolution

1. `spawn_self_update_transient_unit` invokes:
   ```text
   systemd-run --unit=aetherflow-self-update-<command>-<channel>-<8hex>.service \
     --collect --no-block --property=Type=exec --property=KillMode=control-group \
     [--setenv=K=V ...] -- \
     <af_bin> --root <isolated_root> release <deploy|rollback> --channel <channel> \
       --local --config <protected_config_snapshot> \
       --job-status-file <durable_receipt> --job-unit <unit>
   ```
2. The fixture sets `AETHERFLOW_RELEASE_ROOT` and explicit `AETHERFLOW_RELEASE_CONF` under `<work_root>/lifecycle_iso`, keeping all paths isolated from host production directories.
3. The runner validates the isolated config, writes a `0600` config snapshot (`<jobs_dir>/<unit>.conf`), and passes root, config, lock, DB, backup, and receipt paths to the transient unit.
4. Completion requires querying `POST /v1/self-update/status` after runner restart and transient-unit exit and observing a terminal receipt (`exit_code: 0` for rollback; nonzero with diagnostic for failed deploy).

### 2. Contract Boundary: Native `deploy` (`GithubHttpArtifactProvider`) vs. Native `rollback`

In `backend-rs/crates/af-release/src/artifact/provider.rs` and `backend-rs/crates/af-release/src/config.rs`:

- `ReleaseEngine::new_production(cfg)` builds `GithubHttpArtifactProvider::default()` targeting `https://api.github.com` and `https://github.com` without reading an environment/config loopback URL override.
- `ReleaseOptions::validate()` rejects `--offline` unless `--dry-run` is set, and `af-runner` never passes `--dry-run`.
- Accordingly:
  - **Phase 4** proves real native rollback, cgroup survival across runner restart, atomic symlink swap, SQLite corruption recovery, service restart, and durable success receipts.
  - **Phase 5** proves deploy initiation, `--offline` rejection, durable failure reporting, and preservation of `CURRENT_LINK` on failed synthetic-repo fetch (not verified-artifact deployment).
  - **Phase 6** proves fail-closed snapshot-digest rejection, byte-identical preservation of corrupt DB/WAL/SHM files, sustained writer quiescence, and durable failure receipts.

---

## Running Unit Tests (Local Host / CI)

From the repository root:

```bash
# Lifecycle guest drill unit tests (33 tests)
python3 -m unittest discover -s tests -p "test_v4_lifecycle_guest_drills.py" -v

# All guest-harness unit suites together (33 lifecycle + 12 privileged + 19 native-package = 64 tests)
python3 -m unittest \
  tests/test_v4_lifecycle_guest_drills.py \
  tests/test_v4_privileged_guest_drills.py \
  tests/test_v4_native_package_guest_drills.py -v
```

---

## Disposable QEMU/systemd Guest Execution Runbook

Stage the matching `aetherflow-api` and `af` binaries, `source-manifest.json`, `scripts/v4_lifecycle_guest_drills.py`, and its shared library modules (`scripts/lib/vm_guest_common.py`, `scripts/lib/vm_lifecycle_evaluators.py`) under `/var/tmp/aetherflow-v4-stage` inside a fresh disposable QEMU/systemd guest. Never delete pre-existing production units to bypass guardrails—use a clean guest image.

```bash
# 1. Verify required script libraries are staged alongside the harness
ls -la /var/tmp/aetherflow-v4-stage/scripts/v4_lifecycle_guest_drills.py \
  /var/tmp/aetherflow-v4-stage/scripts/lib/vm_guest_common.py \
  /var/tmp/aetherflow-v4-stage/scripts/lib/vm_lifecycle_evaluators.py

# 2. Write the required disposable-guest markers
printf 'AETHERFLOW_DISPOSABLE_GUEST_V4\n' | sudo tee /run/aetherflow-disposable-guest >/dev/null
printf 'AETHERFLOW_DISPOSABLE_GUEST_V4\n' | sudo tee /etc/aetherflow-disposable-guest >/dev/null
sudo chown root:root /etc/aetherflow-disposable-guest
sudo chmod 0600 /etc/aetherflow-disposable-guest

# 3. Execute the lifecycle & transient-systemd self-update guest drill suite as root
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

- `0`: All 6 mandatory lifecycle guest drill phases executed against real binaries and systemd units and passed every assertion.
- `1`: One or more assertions failed, or a phase reported `pending_contract` / `real_execution=False`.
- `2`: Blocked by `GuestSafetyError` before touching the filesystem or systemd.
- `3`: Unexpected harness runtime error.
