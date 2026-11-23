# AetherFlow v4 Clean-Guest Native Package Lifecycle Validation

## 1. Scope & Purpose

This document records the methodology, safety guardrails, engine environment contract, and disposable-guest validation results for AetherFlow v4 native package lifecycle verification (`scripts/v4_native_package_guest_drills.py`).

- **Declarative Rust Package Engine**: `backend-rs/crates/af-runner/src/package_executor/declarative_recipes/` (`catalog.rs`) defines **9** opt-in native declarative recipes (`fail2ban`, `quassel`, `threadfin`, `znc`, `xrdp`, `x2go`, `netdata`, `mergerfs`, `rclone`), enabled via `AETHERFLOW_ENABLE_RUST_PACKAGES=1`. The default five-phase clean-guest drill suite exercises end-to-end install, update, data-preserving remove, purge, cancellation, serialization, and rollback across the core three-package lifecycle matrix (`fail2ban`, `quassel`, `threadfin`).
- **Preinstalled Family Verification (`--verify-family`)**: The harness also supports **23** opt-in preinstalled native family checks (`media_servers`, `media_automation`, `media_requests`, `torrents`, `usenet`, `cloud_storage`, `overlay_networking`, `dns_filtering`, `security`, `monitoring`, `availability`, `home_automation`, `filesystems`, `extraction`, `scheduled_sync`, `books`, `messaging`, `documents`, `workflows`, `developer_tools`, `remote_desktops`, `iptv`, `database_backed_streaming`). Repeat `--verify-family <family>` to validate preinstalled representatives after Phase 1 (`binary_and_environment_provenance`) and before Phases 2–5 (authenticated probes accept `AF_GUEST_READINESS_AUTHORIZATION_<PACKAGE>`).

### Latest Passing Guest Retest (November 3, 2026 — 47/47 Assertions)

All **47/47 assertions** passed across the five mandatory phases in a disposable Debian 13 amd64 QEMU/systemd guest run on November 3, 2026 (`native-report.json` SHA-256 `eaef7f149fb7f44d4d65253eed69f1dfd6160390d601e925d69b998299e194c6`):

| Real Guest Phase | Assertions |
| :--- | :---: |
| `1. binary_and_environment_provenance` | 8/8 |
| `2. fail2ban_native_lifecycle` | 12/12 |
| `3. quassel_native_lifecycle_and_preservation` | 13/13 |
| `4. threadfin_native_lifecycle_and_artifact_verification` | 10/10 |
| `5. cancellation_serialization_and_rollback_safety` | 4/4 |

All five defects discovered in the earlier baseline run have been resolved in `backend-rs/crates/af-runner/src/package_executor/declarative_recipes/catalog.rs` and `backend-rs/crates/af-runner/src/sandbox_ops.rs` (including `/run/fail2ban` path normalization, data-preserving APT removal for `quassel`, preseeded Quassel defaults/certificate + sandboxing before APT activation, `Threadfin_linux_amd64_glibc_2.31_compat`, writable `HOME=/var/lib/threadfin`, valid fresh settings schema with loopback bind default, and explicit Threadfin restart on port update `34405 -> 34406`).

> [!NOTE]
> This bounded Debian 13 guest pass verifies native lifecycle execution for `fail2ban`, `quassel`, and `threadfin` on Debian 13; full four-OS matrix certification (`debian-12`, `debian-13`, `ubuntu-22.04`, `ubuntu-24.04`) is governed separately by [`docs/v4-clean-host-testing.md`](./v4-clean-host-testing.md).

### Separation of Evidence Classes

1. **Mocked/Isolated Rust Executor Unit Tests (`cargo test -p af-runner`)**: Exercise recipe validation, template interpolation, symlink/traversal rejection, ELF header parsing, SHA-256 verification, in-flight cancellation, `.af-package-executor.flock` contention, and rollback journaling against `AETHERFLOW_FS_ROOT` using `MockCommandRunner`. They do not spawn real `apt-get`, `dpkg-query`, `useradd`, `openssl`, `systemctl`, or daemon binaries.
2. **Harness Fail-Closed Unit Tests (`tests/test_v4_native_package_guest_drills.py`, 19 tests)**: Verify disposable-guest guardrails, `[PROGRESS:<pct>]` wire parsing, ELF/lockfile checks, `--verify-family` selection/evaluation, and fail-closed suite reporting.
3. **Live Disposable QEMU/KVM Guest Execution (`scripts/v4_native_package_guest_drills.py`)**: Executes inside a single-use Debian 13 cloud-image guest booted via `IsolatedVmSession` (`scripts/lib/vm_remote_engine.py`) with `2 vCPUs`, `3584 MiB` RAM, loopback-only SLIRP networking, zero host mounts, pinned ephemeral Ed25519 SSH keys, and owned QEMU PID cleanup, exercising real `aetherflow-api runner` and `af` binaries with `AETHERFLOW_ENABLE_RUST_PACKAGES=1`, `AETHERFLOW_FORCE_BASH_PACKAGES=0`, and `AETHERFLOW_PACKAGE_DRY_RUN=0`.

---

## 2. Disposable-Guest Safety Guardrails

`scripts/v4_native_package_guest_drills.py` imports the six fail-closed disposable-guest guardrails (`verify_guest_execution_guardrails`) from `scripts/lib/vm_guest_common.py` and refuses to run unless all six hold simultaneously:

1. **OS & Effective Identity**: `sys.platform.startswith("linux")` and `os.geteuid() == 0`.
2. **Explicit CLI Confirmation**: `--confirm-disposable-guest` is passed.
3. **Environment Gate**: `AETHERFLOW_DISPOSABLE_GUEST=1` is set.
4. **Ephemeral `/run` Marker**: `/run/aetherflow-disposable-guest` is a regular file containing `AETHERFLOW_DISPOSABLE_GUEST_V4`.
5. **Hardware/Hypervisor Virtualization**: `systemd-detect-virt`, `/sys/class/dmi/id/{product_name,sys_vendor,board_vendor}`, or `/sys/hypervisor/type` confirms a `qemu`/`kvm`/`bochs` guest (bare-metal hosts fail closed with exit code `2`).
6. **Isolated Paths**: `--work-root` resides under `/var/tmp/aetherflow-v4-guest-drills*`, and `--api-bin` / `--af-bin` reside outside `/opt/AetherFlow` and `/opt/aetherflow`.

---

## 3. Native Engine Environment Contract

Derived from `backend-rs/crates/af-runner/src/package_executor.rs`, `declarative_recipes/`, and `lib.rs`:

| Environment Variable | Value in Live Drill | Effect |
| :--- | :--- | :--- |
| `AETHERFLOW_RUNNER_SOCK` | `<work_root>/run/<phase>.sock` | Binds `aetherflow-api runner` UDS listener inside isolated work root |
| `AETHERFLOW_ENABLE_RUST_PACKAGES` | `1` | Enables `PackageEngineMode::DeclarativeRust` for the 9 built-in declarative recipes |
| `AETHERFLOW_FORCE_BASH_PACKAGES` | `0` | Disables the legacy Bash fallback override |
| `AETHERFLOW_PACKAGE_DRY_RUN` | `0` | Forces `TokioCommandRunner` to spawn real OS child processes |
| `AETHERFLOW_FS_ROOT` | *(unset)* | Targets real guest `/` so `apt-get`, `chown`, and `systemctl` operate on guest state |
| `DELETE_DATA` | `false` (default) / `true` (purge) | Controls whether `remove` preserves or purges package data directories |
| `AETHERFLOW_ARTIFACT_CACHE_DIR` | `<work_root>/threadfin_upstream_cache` (Phase 4) / `<work_root>/corrupt_artifact_cache` (Phase 5) | Serves cached upstream Threadfin binaries in Phase 4 (`daemon_keep`/`daemon_purge`) and injects a mismatched digest in Phase 5 to verify fail-closed SHA-256 rollback |

---

## 4. Running Unit Tests & Guest Drills

### Harness Unit Tests (Any Host / CI)

```bash
python3 -m unittest discover -s tests -p "test_v4_native_package_guest_drills.py" -v
```

### Staging & Running Inside a Disposable Guest

Stage `scripts/v4_native_package_guest_drills.py` together with `scripts/lib/vm_guest_common.py` (required at import time) and the candidate `aetherflow-api` / `af` binaries under `/var/tmp/aetherflow-v4-stage`:

```bash
printf 'AETHERFLOW_DISPOSABLE_GUEST_V4\n' | sudo tee /run/aetherflow-disposable-guest >/dev/null

sudo env AETHERFLOW_DISPOSABLE_GUEST=1 \
  python3 /var/tmp/aetherflow-v4-stage/scripts/v4_native_package_guest_drills.py \
  --confirm-disposable-guest \
  --work-root /var/tmp/aetherflow-v4-guest-drills-native \
  --api-bin /var/tmp/aetherflow-v4-stage/bin/aetherflow-api \
  --af-bin /var/tmp/aetherflow-v4-stage/bin/af \
  --json-out /var/tmp/aetherflow-v4-stage/native-package-drill-report.json
```

Pass one or more `--verify-family <family>` flags to run preinstalled family readiness checks after Phase 1 (`binary_and_environment_provenance`) and before Phases 2–5.

---

## 5. Historical Baseline Run (Superseded — 39/47 Assertions)

The earlier November 3, 2026 Debian 13 clean-guest baseline (`native-package-drill-report.json` SHA-256 `566b0bd1a419660a3766ff2d0608093bfa8fc59439493fefa8c9c0f1c971b15a`) failed closed at **39/47** assertions and surfaced five real Debian 13 defects that mocked unit tests had not caught. All five were subsequently fixed in `backend-rs/crates/af-runner/src/package_executor/declarative_recipes/catalog.rs` and `backend-rs/crates/af-runner/src/sandbox_ops.rs` and verified in the 47/47 pass above:

1. **`fail2ban` `/var/run` symlink traversal**: Removal listed `/var/run/fail2ban` (symlinked to `/run` on Debian 13); updated to `/run/fail2ban`.
2. **`quassel` non-purge data loss**: `apt-get purge quassel-core` triggered Debian's `postrm` deletion of `/var/lib/quassel` even with `DELETE_DATA=false`; switched non-purge removal to `apt-get remove`.
3. **`quassel-core` `postinst` default cert**: Preseeded `/var/lib/quassel` defaults and certificate before `quassel-core` activation.
4. **`threadfin` upstream asset filename**: Corrected `amd64` asset name from `Threadfin_linux_amd64_compat` (HTTP 404) to `Threadfin_linux_amd64_glibc_2.31_compat`.
5. **`threadfin` sandbox `HOME` & restart**: Set writable `HOME=/var/lib/threadfin` in `threadfin.service` and ensured port updates explicitly restart the service.
