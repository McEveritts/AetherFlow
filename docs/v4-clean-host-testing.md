# AetherFlow v4.0 Clean-Host QEMU/KVM Matrix Testing

This document specifies the architecture, isolation boundaries, clean-OS boot evidence, GLIBC compatibility contract, and clean-host lifecycle certification runbook for AetherFlow v4.0.

---

## 1. Architecture & Isolation Invariants

The clean-host matrix runner ([`scripts/v4_vm_matrix.py`](../scripts/v4_vm_matrix.py)), backed by [`scripts/lib/vm_matrix_helpers.py`](../scripts/lib/vm_matrix_helpers.py) and [`scripts/lib/vm_remote_engine.py`](../scripts/lib/vm_remote_engine.py), orchestrates bare-metal `systemd` virtual machines under QEMU/KVM (`accel=kvm`, `-cpu host`) across the four supported AetherFlow v4 Linux distributions:

| Target ID | Distribution | Official Cloud Image Source | Manifest & Digest |
| :--- | :--- | :--- | :--- |
| `debian-12` | Debian GNU/Linux 12 (bookworm) | `https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2` | `SHA512SUMS` (`sha512`) |
| `debian-13` | Debian GNU/Linux 13 (trixie) | `https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2` | `SHA512SUMS` (`sha512`) |
| `ubuntu-22.04` | Ubuntu 22.04 LTS (Jammy Jellyfish) | `https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img` | `SHA256SUMS` (`sha256`) |
| `ubuntu-24.04` | Ubuntu 24.04 LTS (Noble Numbat) | `https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img` | `SHA256SUMS` (`sha256`) |

### Strict Host & Guest Safety Boundaries

1. **Native Kernel & `systemd` PID 1**: Every guest boots its distribution kernel and `systemd` PID 1 (`systemctl is-system-running`) without container overlays.
2. **Cryptographic Verification Before Boot**: Official `SHA512SUMS` / `SHA256SUMS` manifests are fetched over HTTPS and verified against the cached cloud image before `qemu-img` or `qemu-system-x86_64` starts; any mismatch fails closed.
3. **Immutable Base Images & Copy-on-Write Overlays**: Each run creates a fresh 24 GiB qcow2 overlay (`qemu-img create -f qcow2 -F qcow2 -b <base>`) under `/var/tmp/aetherflow-v4-vm-matrix/runs/<run_id>/overlay.qcow2`.
4. **Ephemeral SSH Keys & Pinned Host Keys (`StrictHostKeyChecking=yes`)**: Each run generates ephemeral `0600` Ed25519 client and guest host keypairs outside the repository, injects them through a NoCloud `cidata` ISO (`user-data` + `meta-data`), and pins `[127.0.0.1]:<ssh_port>` in a per-run `UserKnownHostsFile`.
5. **Loopback-Only Networking & Zero Host Mounts**: QEMU uses user-mode SLIRP networking bound strictly to `127.0.0.1:<ephemeral_port>-:22` with no `-virtfs` / `-fsdev` host mounts.
6. **Non-Intrusive Host Resource Discipline**:
   - Supports either host-installed QEMU/genisoimage or an isolated QEMU root (`--qemu-root`) without installing packages on the host.
   - Keeps all images, overlays, and evidence strictly under `/var/tmp/aetherflow-v4-vm-matrix` (never touching `/tmp`, `/opt/AetherFlow`, or live host services).
   - Runs **one VM at a time** sequentially with `nice -n 10 ionice -c 2 -n 7`, `2 vCPUs`, and `3584 MiB` RAM.
   - Terminates only the specific QEMU PID recorded in `qemu.pid` after verifying `/proc/<pid>/cmdline`.

---

## 2. Clean-OS Guest Boot Matrix Evidence (November 3, 2026)

Executed on a Debian 13 KVM validation host via:

```bash
python3 scripts/v4_vm_matrix.py boot-matrix \
  --ssh-host <ssh-host> \
  --targets debian-12 debian-13 ubuntu-22.04 ubuntu-24.04
```

| Target | Verified Image Digest | OS Release (`/etc/os-release`) | Guest Kernel (`uname -r`) | Guest GLIBC | `systemd` Version & State | `cloud-init` | Boot Time | Status |
| :--- | :--- | :--- | :--- | :---: | :--- | :---: | :---: | :---: |
| **`debian-12`** | `sha512: 0464b5d4ae3aa4f6...712aaad652`<br/>(`sha256: 24036a8b79cbb11d...bd7a256e`) | `Debian GNU/Linux 12 (bookworm)` | `6.1.0-54-cloud-amd64` | **`2.36`** | `systemd 252 (252.39-1~deb12u2)` (`running`) | `status: done` | `9.65s` | `boot_verified` |
| **`debian-13`** | `sha512: 3ace18e33bdd036e...66adbc1b8e`<br/>(`sha256: dd7f5e92d879a983...bb74a6904`) | `Debian GNU/Linux 13 (trixie)` (`13.7`) | `6.12.113+deb13-cloud-amd64` | **`2.41`** | `systemd 257 (257.13-1~deb13u1)` (`running`) | `status: done` | `14.85s` | `boot_verified` |
| **`ubuntu-22.04`** | `sha256: 58be26aa7452f300...66a17ca0` | `Ubuntu 22.04.5 LTS (Jammy Jellyfish)` | `5.15.0-198-generic` | **`2.35`** | `systemd 249 (249.11-0ubuntu3.23)` (`running`) | `status: done` | `18.28s` | `boot_verified` |
| **`ubuntu-24.04`** | `sha256: 04e8f2461a16a44e...985b6c94` | `Ubuntu 24.04.5 LTS (Noble Numbat)` | `6.8.0-147-generic` | **`2.39`** | `systemd 255 (255.4-1ubuntu8.18)` (`running`) | `status: done` | `15.64s` | `boot_verified` |

---

## 3. GLIBC Compatibility & Baseline Builder Path

The supported OS matrix spans four GNU C Library versions:

- **Ubuntu 22.04 LTS (`jammy`)**: `GLIBC 2.35` (lowest in matrix)
- **Debian 12 (`bookworm`)**: `GLIBC 2.36`
- **Ubuntu 24.04 LTS (`noble`)**: `GLIBC 2.39`
- **Debian 13 (`trixie`)**: `GLIBC 2.41` (highest in matrix)

> [!IMPORTANT]
> A dynamically linked `x86_64-unknown-linux-gnu` binary built on Debian 13 (`GLIBC 2.41`) references `GLIBC_2.38`/`GLIBC_2.39` symbols and fails to start on **Ubuntu 22.04 (`GLIBC 2.35`)** and **Debian 12 (`GLIBC 2.36`)**.
>
> Shipping `aetherflow-linux-amd64.tar.gz` artifacts must be built on **Ubuntu 22.04 (`GLIBC 2.35`)** (via CI `ubuntu-22.04` runners or `build-baseline-artifact`) or a verified target requiring `<= GLIBC_2.35`.

### Building a GLIBC-2.35-Compatible Release Artifact (`build-baseline-artifact`)

```bash
python3 scripts/v4_vm_matrix.py build-baseline-artifact \
  --ssh-host <ssh-host> \
  --source-dir <remote-source-dir> \
  --output-dir /var/tmp/aetherflow-v4-vm-matrix/artifacts/ubuntu-22.04-build
```

`build-baseline-artifact` enforces inside the isolated `ubuntu-22.04` guest:

1. **External WASM Dashboard Build**: Installs pinned WASM tools, clears `web/dist` and `frontend-rs/dist`, and runs `scripts/build_wasm_frontend.sh --stage`, requiring a non-empty `index.html` and `.wasm` bundle before packaging.
2. **Locked Dependency Prefetch & Offline Compilation**: Requires a non-empty `backend-rs/Cargo.lock`, prefetches crates with `cargo fetch --locked`, and invokes `scripts/build_gold.sh` with `CARGO_LOCKED=1`, `CARGO_NET_OFFLINE=true`, and `CARGO_BUILD_JOBS=2`.
3. **Bounded Guest Resource Usage**: Runs with `nice -n 10 ionice -c 2 -n 7` and `CARGO_BUILD_JOBS=2` inside a 2-vCPU, 3584 MiB guest.
4. **Post-Build Contract & GLIBC Verification**: Runs `inspect_artifact_bundle` against `aetherflow-linux-amd64.tar.gz` and independent `SHA256SUMS`, verifying all required files, executable modes, `web/dist` assets, and `GLIBC <= 2.35`.

---

## 4. Artifact Contract (`4.0.0-clean-host-v1`) & Pre-Certification Gates

Certification bundles must satisfy `DEFAULT_ARTIFACT_CONTRACT` in [`scripts/lib/vm_matrix_helpers.py`](../scripts/lib/vm_matrix_helpers.py):

```bash
python3 scripts/v4_vm_matrix.py print-contract
```

| Field | Requirement |
| :--- | :--- |
| **Archive Filename** | `aetherflow-linux-amd64.tar.gz` |
| **Independent Checksum Manifest** | Independent `SHA256SUMS` (`<64-hex-sha256>  aetherflow-linux-amd64.tar.gz`); never synthesized by the harness |
| **Required Archive Entries** | `aetherflow-api`, `bin/af`, `bin/speedtest-backend`, `.version`, `web/dist/index.html` (plus non-empty `.wasm`), `deploy/release-manager.sh`, `deploy/release-manager.conf`, `config/packages.json`, `config/package_automation.json`, `plugins/telemetry-inspector/plugin.manifest.json`, `plugins/telemetry-inspector/backend/hooks/start.sh`, `plugins/telemetry-inspector/backend/runtime.py`, `plugins/telemetry-inspector/frontend/dist/index.html` |
| **Required Executable Entries** | `aetherflow-api`, `bin/af`, `bin/speedtest-backend`, `deploy/release-manager.sh`, `plugins/telemetry-inspector/backend/hooks/start.sh` (each verified with an execute bit set, `(mode & 0o111) != 0`; `build_gold.sh` normalizes to `0755`) |
| **Optional Executable Entries** | `bin/af-transcode` (verified executable and `<= GLIBC_2.35` whenever present in the bundle) |
| **Archive Safety** | Regular files and directories only; no symlinks, hardlinks, device nodes, or `..` traversal |
| **Max GLIBC Requirement** | `<= GLIBC_2.35` (verified via `readelf --version-info`) |
| **Source Tarball Layout** | Validated pre-extraction via `inspect_source_tarball_layout` (`flat` -> `--strip-components=0`, `single_top_dir` -> `--strip-components=1`) and post-extraction check of `setup/modules/{00-core,02-packages,05-finalize,06-state,modern_stack}.sh` and `deploy/release-manager.{sh,conf}` |
| **Readiness Endpoint** | `http://127.0.0.1:8080/health/ready` returning HTTP `200` with `{"status":"ready"}` or `{"status":"ok"}` |

### Validating a Candidate Release Bundle Locally

```bash
python3 scripts/v4_vm_matrix.py verify-contract \
  --artifact-tarball /path/to/aetherflow-linux-amd64.tar.gz \
  --artifact-sha256-file /path/to/SHA256SUMS
```

---

## 5. Full Clean-Host Lifecycle Certification Drills (`certify-matrix`)

```bash
python3 scripts/v4_vm_matrix.py certify-matrix \
  --ssh-host <ssh-host> \
  --artifact-tarball /var/tmp/aetherflow-v4-vm-matrix/artifacts/ubuntu-22.04-build/aetherflow-linux-amd64.tar.gz \
  --artifact-sha256-file /var/tmp/aetherflow-v4-vm-matrix/artifacts/ubuntu-22.04-build/SHA256SUMS \
  --source-tarball <remote-source-tarball> \
  --targets debian-12 debian-13 ubuntu-22.04 ubuntu-24.04
```

### Pre-Certification Verification & Evidence Fingerprinting

Before starting guest lifecycle drills, `certify-matrix`:

1. Requires an independent `--artifact-sha256-file` (`SHA256SUMS`) distinct from `--artifact-tarball` and verifies the tarball digest against it.
2. Inspects `--source-tarball` via `inspect_source_tarball_layout` to choose exact `--strip-components` (`0` or `1`) without lossy fallback extraction.
3. Records cryptographic provenance under `artifact_validation` (`artifact_sha256`, `manifest_expected_sha256`, `manifest_file_sha256`, `source_sha256`, `source_layout`, and `contract_report`).

### Mandatory Lifecycle Phases (`MANDATORY_CERTIFICATION_PHASES`)

Release drill tags (healthy update, broken candidate, interrupted candidate) are derived dynamically from the bootstrap release tag via `derive_drill_release_plan(bootstrap_tag)` in `scripts/lib/vm_matrix_helpers.py`. A target receives `overall_status: "certified"` only when all four mandatory phases pass with `fixture_only: false`:

1. **Phase 1 — `bootstrap_install_health_and_cli` (Mandatory)**:
   - Verifies independent `SHA256SUMS` inside the guest (`sha256sum --ignore-missing -c SHA256SUMS`).
   - Confirms `_stage_prebuilt_release_archive` fails closed on a tampered SHA-256 digest before touching `/opt/AetherFlow/current`.
   - Runs `_syscommands`, `_build_modern_stack`, and `_boot` with `AETHERFLOW_PREBUILT_TARBALL` and `AETHERFLOW_PREBUILT_SHA256_FILE`.
   - Verifies `aetherflow-runner.service` and `aetherflow-api.service` are `active`, `http://127.0.0.1:8080/health/ready` returns HTTP `200`, and `/usr/local/bin/af --version`, `af health --json`, and `af release status --json` succeed.
2. **Phase 2 — `release_update` (Mandatory)**:
   - Seeds a verification marker row (`release_marker = pre_v4_0_1`) into `/var/lib/aetherflow/aetherflow.sqlite`.
   - Serves the derived update bundle over a guest loopback HTTP server (`127.0.0.1:18080`), runs `deploy/release-manager.sh deploy --channel stable`, and verifies `/opt/AetherFlow/current` points to the new release, `.previous_release` points to the prior slot, and `/health/ready` passes.
3. **Phase 3 — `failed_health_rollback_and_db_recovery` (Mandatory)**:
   - Deploys the derived broken candidate via `deploy/release-manager.sh deploy` whose stub binary corrupts `/var/lib/aetherflow/aetherflow.sqlite` and exits `1`.
   - Verifies exit code `2` (`HealthProbeFailedRollback`), atomic reversion of `/opt/AetherFlow/current` to the Phase 2 release, restoration of the pre-swap SQLite backup (`PRAGMA integrity_check == ok` and `release_marker == pre_v4_0_1`), and healthy `/health/ready`.
4. **Phase 4A — `interrupted_update_recovery_fixture` (Auxiliary Non-Certifying Fixture, `fixture_only: true`)**:
   - Exercises the `.recovery_state.json` (`phase: "stage2_symlink_swap"`) guard in `af release deploy --local` and rollback via `af release rollback --local --json`; cannot satisfy certification alone.
5. **Phase 4B — `interrupted_update_recovery` (Mandatory Real Updater Interruption & Recovery, `fixture_only: false`)**:
   - Launches `deploy/release-manager.sh deploy --channel stable` in its own process group (`setsid`) for the derived interrupted candidate.
   - Waits for Stage 1, Stage 1.5 SQLite backup, and Stage 2 atomic symlink swap into Stage 3 readiness polling (`/var/tmp/af-drill/post-swap-observed`).
   - Verifies `/proc/<updater_pid>/cmdline` belongs to `release-manager.sh` and terminates only the owned updater process group with `kill -KILL -<updater_pid>` before Stage 4 rollback executes.
   - Recovers via `/usr/local/bin/af release rollback --local --json` and verifies `/opt/AetherFlow/current` reverts to the Phase 2 release, SQLite passes `PRAGMA integrity_check == ok` with `release_marker == pre_v4_0_1`, both core systemd units are `active`, and `/health/ready` passes.

---

## 6. Verification Status & Evidence Boundary

- **Unit & Regression Tests**: `python3 -m unittest tests/test_v4_vm_matrix.py -v` covers **32** tests validating manifest parsing, `/var/tmp` path guardrails, QEMU command/environment isolation, NoCloud seed generation, `DEFAULT_ARTIFACT_CONTRACT` + GLIBC verification, source tarball layout detection, independent `SHA256SUMS` enforcement, mandatory phase evaluation, baseline builder invariants, and remote execution helpers.
- **Clean-Guest Boot Verification**: Official cloud images for `debian-12`, `debian-13`, `ubuntu-22.04`, and `ubuntu-24.04` have been cryptographically verified and boot-checked under QEMU/KVM.
- **Certification Gate**: Full four-OS install/update/rollback/interrupted-recovery certification requires running `build-baseline-artifact` and `certify-matrix` against the target release commit and confirming `overall_status: "certified"` across all four targets.
