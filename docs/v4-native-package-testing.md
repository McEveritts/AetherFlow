# AetherFlow v4 Clean-Guest Native Package Lifecycle Validation (`fail2ban`, `quassel`, `threadfin`)

## 1. Scope & Purpose

### Latest Bounded Retest: November 3, 2026

All **47/47 assertions** pass across the five mandatory phases in a disposable
Debian 13 amd64 QEMU/systemd guest. The candidate is
`package-fixes-7dfac856f608`, derived from frozen `source-20261103-080109` with
only `af-runner/src/package_executor.rs` replaced (SHA-256
`7dfac856f6083de3cc21e5133e07f976dbdfdb62c40dc96a57b9d429d54457ff`).
Its 33 runner tests, strict runner Clippy, and both debug binary builds pass.

| Real guest phase | Assertions |
| --- | --- |
| Binary and environment provenance | 8/8 |
| Fail2ban native lifecycle | 12/12 |
| Quassel lifecycle and data preservation | 13/13 |
| Threadfin lifecycle and artifact verification | 10/10 |
| Cancellation, serialization, and rollback safety | 4/4 |

The final repair explicitly restarts Threadfin after rewriting its unit; the
live update now changes its listener from 34405 to 34406 while preserving the
configuration fixture. Earlier repairs include data-preserving APT removal,
preseeded Quassel defaults/certificate and sandboxing before APT activation,
the published Threadfin artifact name, writable HOME, and a valid fresh settings
schema with a loopback bind default.

Evidence directory on the validation host:
`/var/tmp/aetherflow-v4-validation-20261103-052723/logs/guest-suites-20261103-154632`.

| Evidence | SHA-256 |
| --- | --- |
| `native-report.json` | `eaef7f149fb7f44d4d65253eed69f1dfd6160390d601e925d69b998299e194c6` |
| `vm-execution.json` | `396791be40b8f3fb94d97cf5bc302a999391562d98496ea90780cefa2fc955c9` |
| `native-work.tar.gz` | `036706c62ce28e988366d7f2d28a628172be2d06284a3c61b24ac6bb84b5ec88` |
| Debug `aetherflow-api` | `da6ae27dd3d32a3608d635c857c512c85639c8e32fd4f41b4ae3d8e3070b5246` |
| Debug `af` | `64eacf2a1f026ed737ecf1f6d68433f42a6442957f2c423348a21b1aa46f5520` |

This proves the bounded native package lifecycle on this guest, not certification
of the final merged source, portable release artifact, other supported OSes,
or production deployment. The original 39/47 run and its defects remain below
as historical evidence; its recommendations are not the current recipe state.

This document records the methodology, safety guardrails, test matrix, and live disposable-guest execution results for AetherFlow v4 Backlog Item #10: **Native Package Executor Clean-Guest Lifecycle Validation** (`fail2ban`, `quassel`, and `threadfin`).

### Separation of Evidence Classes

To maintain strict reporting integrity, AetherFlow v4 separates three distinct layers of verification for `backend-rs/crates/af-runner/src/package_executor.rs`:

1. **Existing Mocked/Isolated Rust Executor Unit Tests (20 tests in `af-runner::package_executor::tests`)**:
   - Exercise recipe validation, template interpolation, symlink/traversal rejection, ELF header parsing, SHA-256 verification, in-flight cancellation, cross-process `.af-package-executor.flock` contention, and rollback journaling against a temporary directory (`AETHERFLOW_FS_ROOT`) using `MockCommandRunner`.
   - **Limitation**: These unit tests do **not** run real `apt-get`, `dpkg-query`, `useradd`, `openssl`, `systemctl`, or real daemon binaries (`fail2ban-server`, `quasselcore`, `threadfin`). They do not establish real systemd service activation or package lifecycle convergence on a Linux guest.

2. **Harness Fail-Closed Unit Tests (`tests/test_v4_native_package_guest_drills.py`, 12 tests)**:
   - Verify that `scripts/v4_native_package_guest_drills.py` enforces all disposable-guest guardrails (refusing execution on non-Linux, non-root, bare-metal hosts, live `/opt/AetherFlow` paths, or missing `--confirm-disposable-guest` / `AETHERFLOW_DISPOSABLE_GUEST=1` / `/run/aetherflow-disposable-guest` markers), parses `[PROGRESS:<pct>]` wire streams fail-closed, validates ELF headers and lockfiles, labels synthetic test-provisioning fixtures explicitly, and refuses to pass suites with missing, unexecuted, or failed phases.
   - **Limitation**: Unit tests validate the harness evaluators and safety gates; they do **not** establish live service success.

3. **Live Disposable Debian 13 QEMU/KVM Guest Execution (`scripts/v4_native_package_guest_drills.py`)**:
   - Executes inside a fresh, single-use Debian 13 (`trixie`) cloud-image guest booted via `IsolatedVmSession` (`scripts/v4_vm_matrix.py`) with `2 vCPUs`, `3584 MiB` RAM, loopback-only SLIRP user networking, zero host filesystem mounts, pinned ephemeral Ed25519 SSH host keys, and owned QEMU PID cleanup.
   - Exercises the real compiled `aetherflow-api runner` UDS daemon and shipped `af` (`af-cli`) binary with native engine flags (`AETHERFLOW_ENABLE_RUST_PACKAGES=1`, `AETHERFLOW_FORCE_BASH_PACKAGES=0`, `AETHERFLOW_PACKAGE_DRY_RUN=0`) against real `apt-get`, `dpkg-query`, `openssl`, `useradd`/`userdel`, `systemctl`, and upstream HTTPS downloads.

---

## 2. Disposable-Guest Safety Guardrails

`scripts/v4_native_package_guest_drills.py` reuses the fail-closed guardrail helpers from `scripts/v4_privileged_guest_drills.py` and refuses to run unless all six conditions hold simultaneously:

1. **Linux Kernel**: `sys.platform` starts with `"linux"`.
2. **Root Effective UID**: `os.geteuid() == 0`.
3. **Explicit CLI Confirmation**: `--confirm-disposable-guest` is passed on the command line.
4. **Environment Gate**: `AETHERFLOW_DISPOSABLE_GUEST=1` is present in the environment.
5. **Ephemeral `/run` Marker**: `/run/aetherflow-disposable-guest` exists as a regular file and contains the token `AETHERFLOW_DISPOSABLE_GUEST_V4`.
6. **Hardware/Hypervisor Virtualization**: `systemd-detect-virt`, `/sys/class/dmi/id/{product_name,sys_vendor,board_vendor}`, or `/proc/cpuinfo` confirms a `qemu`/`kvm`/`bochs` guest environment.
7. **Isolated Paths**: `--work-root` resides strictly under `/var/tmp/aetherflow-v4-guest-drills*`, and `--api-bin` / `--af-bin` reside outside `/opt/AetherFlow` and `/opt/aetherflow`.

---

## 3. Native Engine Environment Contract

Derived directly from `backend-rs/crates/af-runner/src/package_executor.rs` and `backend-rs/crates/af-runner/src/lib.rs`:

| Environment Variable | Value in Live Drill | Effect |
| :--- | :--- | :--- |
| `AETHERFLOW_RUNNER_SOCK` | `<work_root>/run/<phase>.sock` | Binds `aetherflow-api runner` UDS listener inside isolated work root |
| `AETHERFLOW_ENABLE_RUST_PACKAGES` | `1` | Enables `PackageEngineMode::DeclarativeRust` for `fail2ban`, `quassel`, `threadfin` |
| `AETHERFLOW_FORCE_BASH_PACKAGES` | `0` | Ensures legacy Bash fallback switch is disabled |
| `AETHERFLOW_PACKAGE_DRY_RUN` | `0` | Forces `TokioCommandRunner` to spawn real OS child processes |
| `AETHERFLOW_FS_ROOT` | *(unset)* | Targets real guest root `/` so `apt-get`, `chown`, and `systemctl` mutate real guest state |
| `DELETE_DATA` | `false` (default) / `true` (purge) | Controls whether `remove` preserves or purges `/var/lib/quassel`, `/var/log/quassel`, and `/var/lib/threadfin` |
| `AETHERFLOW_ARTIFACT_CACHE_DIR` | `<work_root>/corrupt_artifact_cache` *(Phase 5 only)* | Used in Phase 5 rollback drill to test fail-closed SHA-256 mismatch rejection |

---

## 4. Provenance & Fingerprints

- **Source Snapshot**: `/var/tmp/aetherflow-v4-validation-20261103-052723/source-20261103-071256`
- **Source Manifest SHA-256**: `1e863b3c300d5793ff26f0f342277cb9981cb0c18fcdfad8acb2acd0eeaf3aa7`
- **Release `aetherflow-api` Binary SHA-256**: `47e9c60e98e4a49e3ed106cc27c3e17ae9cf428d196199b5956138da9e027e3f` (`22,545,840` bytes, `ELF64 amd64`)
- **Release `af` (`af-cli`) Binary SHA-256**: `37b7fac89a775f5f7d24d1804b384b4b7945cfbcbd4e7a3f0999a21ca729afc0` (`9,203,536` bytes, `ELF64 amd64`)
- **Debug `aetherflow-api` Binary SHA-256**: `66f6deacad215c35df7c685275d1d088567374eda84e734fddc77345accabf7e`
- **Debug `af` (`af-cli`) Binary SHA-256**: `fdf3f892d552dc8e0c2f664ab7650b1a1d3c19fa13938f64ee37cb6da341f6a4`
- **Official Debian 13 (`trixie`) Cloud Image**: `/var/tmp/aetherflow-v4-vm-matrix/images/debian-13-genericcloud-amd64.qcow2`
  - **Cloud Image SHA-256**: `dd7f5e92d879a983d757fc6acd8c5df0294abd9ba57137b29f8c863bb74a6904`
- **Owned Validation Harness & Test Suite**:
  - `scripts/v4_native_package_guest_drills.py` SHA-256: `564a2bf0bee9b19cdc7d4059fe104d0817d028cb781213bd3f6ffe32faa29e6f`
  - `tests/test_v4_native_package_guest_drills.py` SHA-256: `a57832e03b84066dba4afad8f9e2602a2c7f1f14ac9e3dfdf2ff18501bd94f53`
- **Preserved Live Guest Execution Evidence on `hetzner`**:
  - `/var/tmp/aetherflow-v4-native-package-validation/logs/native-package-drill-report.json` SHA-256: `566b0bd1a419660a3766ff2d0608093bfa8fc59439493fefa8c9c0f1c971b15a`
  - `/var/tmp/aetherflow-v4-native-package-validation/logs/vm-driver-summary.json` SHA-256: `8f1d7146f86edd45c48758d2ec3d6cc3a7d91fde66dc24a4fefa12dee3a86961`
  - `/var/tmp/aetherflow-v4-native-package-validation/logs/guest-logs.tar.gz` SHA-256: `5613b36805f09a439d88f5020c9bb383bc027f319a9f84e2183fdb71729068f2`

---

## 5. Live Guest Execution Results & Phase Breakdown

### Guest Environment Summary
- **Guest OS**: `Debian GNU/Linux 13 (trixie)` (`ID=debian`, `VERSION_ID=13`, `VERSION_CODENAME=trixie`)
- **Hypervisor**: QEMU `10.0.13` (`/dev/kvm` hardware acceleration, `-machine q35,accel=kvm -cpu host -smp 2 -m 3584M`, loopback SLIRP user networking, zero host mounts, pinned ephemeral Ed25519 SSH host key, owned PID torn down cleanly after run)
- **Overall Suite Status**: **`failed` (Fail-Closed — 39 / 47 live assertions passed; 5 genuine core recipe/sandbox defects in `backend-rs/crates/af-runner/src/package_executor.rs` exposed and preserved)**

| Phase ID | Status | Assertions Passed | Duration | Summary |
| :--- | :--- | :--- | :--- | :--- |
| `1. binary_and_environment_provenance` | **PASSED** | `8 / 8` | `187.94 ms` | Verified staged ELF64 `aetherflow-api` and `af` binaries outside `/opt/AetherFlow`, Debian 13 (`trixie`) guest identity, `af --json version`, `af --json package info {fail2ban,quassel,threadfin}`, and live UDS `af --socket ... --json health` (`ready`). |
| `2. fail2ban_native_lifecycle` | **FAILED (Fail-Closed)** | `10 / 12` | `25,210.08 ms` | Native install (`X-AetherFlow-Package-Engine: declarative_rust`, 11 progress events to 100%), real APT install (`fail2ban 1.1.0-8`, `python3-systemd 235-1+b6`), `/etc/fail2ban/jail.local` (`0644`, `backend = systemd`, `port = 2222,ssh` probed from `/etc/ssh/sshd_config`), privileged sandbox exemption, `fail2ban.service` active (`MainPID > 0`), `fail2ban-client ping` -> `Server replied: pong`, idempotent `af package install fail2ban` skip, and `af package update fail2ban` all **PASSED**. `af package remove fail2ban` **FAILED** due to `/var/run` symlink rejection in `validate_filesystem_path` (Defect #1). |
| `3. quassel_native_lifecycle_and_preservation` | **FAILED (Fail-Closed)** | `10 / 13` | `55,310.25 ms` | Native install (`X-AetherFlow-Package-Engine: declarative_rust`, 14 progress events to 100%), real APT install (`quassel-core 1:0.14.0-3`, `openssl 3.5.7-1~deb13u3`), `/etc/default/quasselcore` (`PORT="4244"`), `/var/lib/quassel/.af-version` (`0.14.0`), systemd sandbox drop-in (`ProtectSystem=strict`, `NoNewPrivileges=yes`), `quasselcore.service` active (`MainPID=2363`), TCP listener on `127.0.0.1:4244`, update to `PORT="4245"` preserving cert + labeled SQLite fixture (`test_provisioning_fixture_only`), `af package remove quassel` envelope, and explicit `DELETE_DATA=true` purge all **PASSED**. Exposed two Debian `quassel-core` maintainer-script interactions (Defects #2 and #3). |
| `4. threadfin_native_lifecycle_and_artifact_verification` | **FAILED (Fail-Closed)** | `7 / 10` | `148,770.65 ms` | Direct uncached install exposed broken upstream asset filename `Threadfin_linux_amd64_compat` (HTTP 404 on GitHub 1.2.37; Defect #4). Staging the real official `Threadfin_linux_amd64_glibc_2.31_compat` binary (`10,535,064` bytes, SHA-256 `0b80a1bb5dc270c35288531408657189fd27c2e4346686743ebd36f3b6acbe42`) into `AETHERFLOW_ARTIFACT_CACHE_DIR` verified full native install (12 progress events to 100%), ELF64 `amd64` + pinned SHA-256 verification, `/var/lib/threadfin/.af-version` (`1.2.37`), `threadfin.service` active (`MainPID=6566`), update port switch (`34405 -> 34406`), non-purge `af package remove threadfin` preserving `/var/lib/threadfin/conf/af_test_provisioning_sentinel.json` (`test_provisioning_fixture_only`), `af package install threadfin --port 34405` reinstall preserving config, and `DELETE_DATA=true` full purge. Exposed `go` sandbox `ProtectHome=read-only` blocking Threadfin HTTP listener startup (Defect #5). |
| `5. cancellation_serialization_and_rollback_safety` | **PASSED** | `4 / 4` | `1,893.99 ms` | Verified in-flight duplicate execution rejection (`dependency lock error: package 'threadfin' already has an operation in flight`), `af --socket ... --json package cancel threadfin` (`cancellation signalled for threadfin`), cooperative stream cancellation without writing `/install/.threadfin.lock` while preserving `.af-package-executor.flock` inode, and fail-closed SHA-256 mismatch rollback preserving prior `/usr/local/bin/threadfin` sentinel with zero `.af-rollback-bak` leftovers. |

---

## 6. Genuine Core Recipe & Sandbox Defects Uncovered on Debian 13 (For `af-runner` / `af-host` Owner)

Per task ownership rules, `backend-rs/crates/af-runner/src/package_executor.rs` and `backend-rs/crates/af-host/src/sandbox.rs` were **not** edited. The live Debian 13 clean-guest validation uncovered five concrete core defects that were masked by the 20 mocked unit tests:

### Defect 1: `fail2ban` `remove_steps` Fails Closed on Modern Debian/Ubuntu Because `/var/run` Is a Symlink to `/run`
- **Location**: `backend-rs/crates/af-runner/src/package_executor.rs` (`build_fail2ban_recipe`, lines 2151–2158)
- **Observed Error**:
  ```text
  runner socket IPC error (/v1/package): remove fail2ban (removepackage-fail2ban) failed:
  security policy violation: refusing to traverse or mutate symlink path component: /var/run
  ```
- **Root Cause**:
  - `build_fail2ban_recipe()` includes `"/var/run/fail2ban"` in `DeclarativeStep::RemovePaths`.
  - On Debian 13 (and all modern systemd distributions), `/var/run` is a symbolic link to `/run`.
  - `validate_filesystem_path()` walks every ancestor component with `fs::symlink_metadata` and returns `PackageExecutorError::SecurityViolation("refusing to traverse or mutate symlink path component: /var/run")` before removing `/var/run/fail2ban` and before unlinking `/install/.fail2ban.lock`.
  - In mocked unit tests (`test_fail2ban_install_and_remove_in_isolated_root`), `AETHERFLOW_FS_ROOT` creates `<tmp>/var/run` as a plain directory rather than a symlink, so the unit test never encountered the `/var/run -> /run` symlink.
- **Recommended Fix for `af-runner` Owner**:
  - Replace `"/var/run/fail2ban"` with `"/run/fail2ban"` in `build_fail2ban_recipe()` (or resolve well-known OS top-level compatibility symlinks `/var/run -> /run` and `/var/lock -> /run/lock` before ancestor symlink inspection).

### Defect 2: `quassel` `Remove` with `DELETE_DATA=false` Runs `apt-get purge quassel-core`, Whose Debian `postrm` Unconditionally Deletes `/var/lib/quassel` and `/var/log/quassel`
- **Location**: `backend-rs/crates/af-runner/src/package_executor.rs` (`build_quassel_recipe`, lines 2274–2297)
- **Observed Failure**:
  - When `DELETE_DATA=false`, `af package remove quassel` executes `DeclarativeStep::AptPurge { packages: vec!["quassel-core"] }` (`apt-get -y purge quassel-core`) before the conditional `RemovePaths { only_if_delete_data: true }`.
  - On Debian 13, `/var/lib/dpkg/info/quassel-core.postrm` executes `rm -rf /var/lib/quassel /var/log/quassel` whenever `postrm` is invoked with `purge`!
  - Consequently, even though `package_executor.rs` skipped its own `RemovePaths` step when `delete_data=false`, `apt-get purge quassel-core` wiped `/var/lib/quassel/quasselCert.pem` and `/var/lib/quassel/quassel-storage.sqlite`.
- **Recommended Fix for `af-runner` Owner**:
  - Use `apt-get remove` (non-purge) when `delete_data == false`, or back up `/var/lib/quassel` before `apt-get purge` and restore it when `delete_data == false`, only invoking `apt-get --purge` when `delete_data == true`.

### Defect 3: `quassel-core` Debian `postinst` Pre-Generates Default Certificate Before `EnsureSelfSignedCert` Runs
- **Location**: `backend-rs/crates/af-runner/src/package_executor.rs` (`build_quassel_recipe`, lines 2183–2219)
- **Observed Behavior**:
  - Step 2 of `build_quassel_recipe()` runs `apt-get install quassel-core openssl`.
  - On Debian 13, `quassel-core.postinst` immediately runs `openssl req ...` with Debian's default `/etc/ssl/openssl.cnf` subject (`subject=C=AU, ST=Some-State, O=Internet Widgits Pty Ltd`) and writes `/var/lib/quassel/quasselCert.pem`.
  - When Step 5 (`EnsureSelfSignedCert` with `common_name: "quassel.aether.local"`) runs, `/var/lib/quassel/quasselCert.pem` already exists on disk, so `EnsureSelfSignedCert` logs `"preserved existing TLS certificate /var/lib/quassel/quasselCert.pem"` and never generates the `CN=quassel.aether.local` certificate on a clean install.
- **Recommended Fix for `af-runner` Owner**:
  - Run `EnsureDirectories` + `EnsureSelfSignedCert` *before* `AptInstall { packages: ["quassel-core"] }` (ensuring `openssl` is installed first), or replace a stock `Internet Widgits Pty Ltd` postinst certificate generated during the same initial install transaction.

### Defect 4: `threadfin` Recipe Requests `Threadfin_linux_amd64_compat`, Which Returns HTTP 404 on Upstream GitHub Release `1.2.37`
- **Location**: `backend-rs/crates/af-runner/src/package_executor.rs` (`build_threadfin_recipe`, lines 2394–2401)
- **Observed Error**:
  ```text
  artifact verification failed: HTTP 404 Not Found when downloading
  https://github.com/Threadfin/Threadfin/releases/download/1.2.37/Threadfin_linux_amd64_compat
  ```
- **Root Cause**:
  - Upstream GitHub release `Threadfin/Threadfin` tag `1.2.37` publishes `Threadfin_linux_amd64_glibc_2.31_compat` (SHA-256 `0b80a1bb5dc270c35288531408657189fd27c2e4346686743ebd36f3b6acbe42`, `10,535,064` bytes) and `Threadfin_linux_amd64`, **not** `Threadfin_linux_amd64_compat`.
  - Notably, `fetch_artifact_to_temp()` at line 3648 already has a comment/branch referencing `"Threadfin_linux_amd64_glibc_2.31_compat"`, but `build_threadfin_recipe()` sets `arch_map.amd64 = "Threadfin_linux_amd64_compat"`.
- **Recommended Fix for `af-runner` Owner**:
  - Update `arch_map.amd64` in `build_threadfin_recipe()` from `"Threadfin_linux_amd64_compat"` to `"Threadfin_linux_amd64_glibc_2.31_compat"`.

### Defect 5: `threadfin` Systemd Unit + `go` Sandbox Profile (`ProtectHome=read-only` + `ReadWritePaths=/root`) Prevents `threadfin` From Binding Its HTTP Port
- **Location**: `backend-rs/crates/af-runner/src/package_executor.rs` (`build_threadfin_recipe`, line 2435) and `backend-rs/crates/af-host/src/sandbox.rs` (`go` profile for `threadfin`)
- **Observed Behavior**:
  - When `threadfin.service` starts under `User=threadfin` with `/etc/systemd/system/threadfin.service.d/aetherflow-sandbox.conf`, the drop-in contains:
    ```ini
    ProtectSystem=strict
    ProtectHome=read-only
    ReadWritePaths=/var/lib/threadfin /root -/mnt ...
    ```
  - Simultaneously, the `threadfin` binary (`1.2 Build 37`) initializes `/var/lib/threadfin/conf/settings.json` and logs up to `BRANCH: Main`, then attempts to check/create its default `$HOME/.threadfin` directory (`/home/threadfin` or `/root`) before binding the HTTP listener on `34405`. Because `User=threadfin` has no writable `HOME=/var/lib/threadfin` environment variable set in `threadfin.service` and `ProtectHome=read-only` blocks creation outside `/var/lib/threadfin`, the process stalls before reaching `Web Interface: http://...:34405/web/`.
  - Running the exact same binary on Debian 13 with `HOME=/var/lib/threadfin` immediately initializes `UUID` and binds `http://0.0.0.0:34405/web/` in `< 1.5 seconds`.
- **Recommended Fix for `af-runner` Owner**:
  - Add `Environment="HOME=/var/lib/threadfin"` to `threadfin.service` in `build_threadfin_recipe()` and ensure `ensure_system_user` sets `/var/lib/threadfin` as `threadfin`'s home directory so `{{SERVICE_HOME}}` resolves to `/var/lib/threadfin` instead of `/root`.
