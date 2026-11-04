# AetherFlow v4.0 Clean-Host QEMU/KVM Matrix Testing (`docs/v4-clean-host-testing.md`)

This document specifies the architecture, isolation boundaries, executed clean-OS boot evidence, GLIBC compatibility contract, and lifecycle certification runbook for Backlog #5 (**Clean-host installation and rollback testing**).

---

## 1. Architecture & Isolation Invariants

The clean-host matrix runner ([`scripts/v4_vm_matrix.py`](../scripts/v4_vm_matrix.py)) orchestrates real bare-metal `systemd` virtual machines under QEMU/KVM (`accel=kvm`, `-cpu host`) across the four supported AetherFlow v4 Linux distributions:

| Target ID | Distribution | Official Cloud Image Source | Manifest & Digest |
| :--- | :--- | :--- | :--- |
| `debian-12` | Debian GNU/Linux 12 (bookworm) | `https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2` | `SHA512SUMS` (`sha512`) |
| `debian-13` | Debian GNU/Linux 13 (trixie) | `https://cloud.debian.org/images/cloud/trixie/latest/debian-13-genericcloud-amd64.qcow2` | `SHA512SUMS` (`sha512`) |
| `ubuntu-22.04` | Ubuntu 22.04 LTS (Jammy Jellyfish) | `https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img` | `SHA256SUMS` (`sha256`) |
| `ubuntu-24.04` | Ubuntu 24.04 LTS (Noble Numbat) | `https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img` | `SHA256SUMS` (`sha256`) |

### Strict Host & Guest Safety Boundaries

1. **Zero Docker / Pure Bare-Metal `systemd`**:
   Every guest boots its native distribution kernel and `systemd` PID 1 (`systemctl is-system-running`). No Docker daemons or container overlays are used.
2. **Cryptographic Verification Before Boot**:
   Official `SHA512SUMS` / `SHA256SUMS` manifests are fetched over HTTPS and verified against the local cloud image file before `qemu-img` or `qemu-system-x86_64` is invoked. Any digest mismatch fails closed.
3. **Immutable Base Images & Per-Run Copy-on-Write Overlays**:
   Each VM run creates an ephemeral 24 GiB qcow2 overlay (`qemu-img create -f qcow2 -F qcow2 -b <base>`) under `/var/tmp/aetherflow-v4-vm-matrix/runs/<run_id>/overlay.qcow2`.
4. **Ephemeral SSH Keys & Pinned Host Keys (`StrictHostKeyChecking=yes`)**:
   Each VM run generates a fresh 0600 Ed25519 client keypair and a fresh guest Ed25519 host keypair outside the repository, injects them via a NoCloud `cidata` ISO (`user-data` + `meta-data`), and pins `[127.0.0.1]:<ssh_port>` in a per-run `UserKnownHostsFile`. No keys are stored in the repository and no `StrictHostKeyChecking=no` bypass is used.
5. **Loopback-Only Networking & Zero Host Mounts**:
   QEMU uses user-mode SLIRP networking bound strictly to `127.0.0.1:<ephemeral_port>-:22`. No `-virtfs` / `-fsdev` host mounts or operator secrets are exposed to the guest.
6. **Non-Intrusive Host Resource Discipline**:
   - Uses extracted QEMU 10.0.13 and `genisoimage` from `/var/tmp/aetherflow-v4-validation-20261103-052723/tools/qemu-root` with isolated `LD_LIBRARY_PATH` and `-L` BIOS/firmware paths (zero `apt install` on the host).
   - Stores all images, overlays, and evidence strictly under `/var/tmp/aetherflow-v4-vm-matrix` (never `/tmp`, which is 99% full, and never touching host `/opt/AetherFlow` or live host services).
   - Runs **one VM at a time** sequentially with `nice -n 10 ionice -c 2 -n 7`, `2 vCPUs`, and `3584 MiB` RAM.
   - Terminates only the specific QEMU PID recorded in the run's `qemu.pid` after verifying `/proc/<pid>/cmdline`.

---

## 2. Verified Clean-OS Guest Boot Matrix Evidence (November 3, 2026)

Executed on `hetzner` (`Linux Debian-1305-trixie-amd64-base 6.12.113+deb13-amd64 x86_64`) via:

```powershell
python scripts/v4_vm_matrix.py boot-matrix --ssh-host hetzner --targets debian-12 debian-13 ubuntu-22.04 ubuntu-24.04
```

Machine-readable evidence persisted on `hetzner` at:
- `/var/tmp/aetherflow-v4-vm-matrix/evidence/boot-matrix-1793703307.json`
- `/var/tmp/aetherflow-v4-vm-matrix/evidence/latest-boot-matrix.json`
- `/var/tmp/aetherflow-v4-vm-matrix/evidence/certify-matrix-1793703474.json`

| Target | Verified Image Digest | OS Release (`/etc/os-release`) | Guest Kernel (`uname -r`) | Guest GLIBC | `systemd` Version & State | `cloud-init` | Boot Time | Status |
| :--- | :--- | :--- | :--- | :---: | :--- | :---: | :---: | :---: |
| **`debian-12`** | `sha512: 0464b5d4ae3aa4f6...712aaad652`<br/>(`sha256: 24036a8b79cbb11d...bd7a256e`) | `Debian GNU/Linux 12 (bookworm)` | `6.1.0-54-cloud-amd64` | **`2.36`** | `systemd 252 (252.39-1~deb12u2)` (`running`) | `status: done` | `9.65s` | `boot_verified` |
| **`debian-13`** | `sha512: 3ace18e33bdd036e...66adbc1b8e`<br/>(`sha256: dd7f5e92d879a983...bb74a6904`) | `Debian GNU/Linux 13 (trixie)` (`13.7`) | `6.12.113+deb13-cloud-amd64` | **`2.41`** | `systemd 257 (257.13-1~deb13u1)` (`running`) | `status: done` | `14.85s` | `boot_verified` |
| **`ubuntu-22.04`** | `sha256: 58be26aa7452f300...66a17ca0` | `Ubuntu 22.04.5 LTS (Jammy Jellyfish)` | `5.15.0-198-generic` | **`2.35`** | `systemd 249 (249.11-0ubuntu3.23)` (`running`) | `status: done` | `18.28s` | `boot_verified` |
| **`ubuntu-24.04`** | `sha256: 04e8f2461a16a44e...985b6c94` | `Ubuntu 24.04.5 LTS (Noble Numbat)` | `6.8.0-147-generic` | **`2.39`** | `systemd 255 (255.4-1ubuntu8.18)` (`running`) | `status: done` | `15.64s` | `boot_verified` |

---

## 3. GLIBC Compatibility Finding & Baseline Builder Path

As proven by the live guest probes above, the supported OS matrix spans four distinct GNU C Library versions:
- **Ubuntu 22.04 LTS (`jammy`)**: `GLIBC 2.35` (lowest in matrix)
- **Debian 12 (`bookworm`)**: `GLIBC 2.36`
- **Ubuntu 24.04 LTS (`noble`)**: `GLIBC 2.39`
- **Debian 13 (`trixie`, host OS)**: `GLIBC 2.41` (highest in matrix)

> [!IMPORTANT]
> A dynamically linked `x86_64-unknown-linux-gnu` binary compiled directly on the Debian 13 host (`GLIBC 2.41`) links against `GLIBC_2.38` / `GLIBC_2.39` symbols and will fail to start on **Ubuntu 22.04 (`GLIBC 2.35`)** and **Debian 12 (`GLIBC 2.36`)**.
>
> To guarantee portability across all four supported OS targets, the shipping `aetherflow-linux-amd64.tar.gz` release artifact must either:
> 1. Be built inside the clean **Ubuntu 22.04 (`GLIBC 2.35`)** guest VM using `python scripts/v4_vm_matrix.py build-baseline-artifact`, OR
> 2. Be compiled on Ubuntu 22.04 in CI (`ubuntu-22.04` runner), OR
> 3. Use a verified static target (`x86_64-unknown-linux-musl`) with zero dynamic `GLIBC_*` symbol requirements above `2.35`.

### Building a GLIBC-2.35-Compatible Release Artifact in the Ubuntu 22.04 VM (`build-baseline-artifact`)

When the final converged source tree and committed `backend-rs/Cargo.lock` are ready on `hetzner`, run:

```powershell
python scripts/v4_vm_matrix.py build-baseline-artifact `
  --ssh-host hetzner `
  --source-dir /var/tmp/aetherflow-v4-validation-20261103-052723/source `
  --node-root /var/tmp/aetherflow-v4-validation-20261103-052723/tools/node `
  --output-dir /var/tmp/aetherflow-v4-vm-matrix/artifacts/ubuntu-22.04-build
```

`build-baseline-artifact` enforces the following build and resource guarantees inside the isolated `ubuntu-22.04` guest:
1. **Unconditional Frontend Static Export & Embedded Asset Verification**:
   - Never skips the frontend build merely because placeholder `web/dist` or `backend/web/dist` directories (with `.keep`) exist in the repository.
   - Removes `web/dist`, `backend/web/dist`, and `frontend/out`, runs `npm ci --no-fund --no-audit` and `NEXT_STATIC_EXPORT=1 npm run build --workspace frontend` using the isolated guest Node 24 toolchain, copies `frontend/out/.` into both `web/dist/` and `backend/web/dist/`, and verifies `test -s web/dist/index.html`, `test -d web/dist/_next`, and `test -s backend/web/dist/index.html` before compiling Rust so `rust-embed` (`af-api/src/embed.rs`) embeds the real UI assets.
2. **Locked Dependency Prefetch + Offline Rust Compilation (`--locked` + `CARGO_NET_OFFLINE=true`)**:
   - Requires a non-empty `backend-rs/Cargo.lock` (`test -s backend-rs/Cargo.lock`).
   - Runs `cargo fetch --locked` first, then invokes `scripts/build_gold.sh` with `CARGO_LOCKED=1`, `CARGO_NET_OFFLINE=true`, and `CARGO_BUILD_JOBS=2`.
3. **Host-Friendly Resource Limits (`2 jobs` + `nice` / `ionice`)**:
   - Wraps `npm ci`, `npm run build`, `cargo fetch --locked`, and `scripts/build_gold.sh` with `nice -n 10 ionice -c 2 -n 7` and `CARGO_BUILD_JOBS=2` inside a 2-vCPU, 3584 MiB guest.
4. **Post-Build Contract & GLIBC Verification**:
   - Inspects the downloaded `aetherflow-linux-amd64.tar.gz` and independent `SHA256SUMS` via `inspect_artifact_bundle`, verifying required files, executable permissions, embedded UI markers (`index.html` and `_next/`), and `GLIBC <= 2.35` via `readelf --version-info`.

---

## 4. Pending Artifact Contract (`4.0.0-clean-host-v1`) & Pre-Certification Gates

To run the full end-to-end clean-host installation, update, rollback, and interrupted-recovery certification across all four guests, the supplied bundle must satisfy [`DEFAULT_ARTIFACT_CONTRACT`](../scripts/v4_vm_matrix.py):

```powershell
python scripts/v4_vm_matrix.py print-contract
```

| Field | Requirement |
| :--- | :--- |
| **Archive Filename** | `aetherflow-linux-amd64.tar.gz` |
| **Independent Checksum Manifest** | Independent `SHA256SUMS` (`<64-hex-sha256>  aetherflow-linux-amd64.tar.gz`); **never** synthesized from the tarball by the certification harness |
| **Required Archive Entries** | `aetherflow-api`, `af`, `bin/af`, `.version`, `deploy/release-manager.sh`, `deploy/release-manager.conf`, `config/packages.json`, `config/package_automation.json` |
| **Required Executable Entries** | `aetherflow-api` (`0755`), `af` (`0755`), `bin/af` (`0755`), `deploy/release-manager.sh` (`0755`) |
| **Archive Safety** | Regular files and directories only; no symlinks, hardlinks, device nodes, or `..` traversal |
| **Max GLIBC Requirement** | `<= GLIBC_2.35` (verified via `readelf --version-info` for `ubuntu-22.04` compatibility) |
| **Source Tarball Layout** | Validated pre-extraction via `inspect_source_tarball_layout` (`flat` -> `--strip-components=0`, `single_top_dir` -> `--strip-components=1`) and post-extraction check of `setup/modules/{00-core,02-packages,05-finalize,06-state,modern_stack}.sh` and `deploy/release-manager.{sh,conf}` |
| **Readiness Endpoint** | `http://127.0.0.1:8080/health/ready` returning HTTP `200` with `{"status":"ready"}` or `{"status":"ok"}` |

### Validating a Candidate Release Bundle Locally

```powershell
python scripts/v4_vm_matrix.py verify-contract `
  --artifact-tarball /path/to/aetherflow-linux-amd64.tar.gz `
  --artifact-sha256-file /path/to/SHA256SUMS
```

---

## 5. Full Clean-Host Lifecycle Certification Drills (`certify-matrix`)

Once the final v4 release artifact, independent `SHA256SUMS`, and source snapshot tarball are available on `hetzner`, run:

```powershell
python scripts/v4_vm_matrix.py certify-matrix `
  --ssh-host hetzner `
  --artifact-tarball /var/tmp/aetherflow-v4-vm-matrix/artifacts/ubuntu-22.04-build/aetherflow-linux-amd64.tar.gz `
  --artifact-sha256-file /var/tmp/aetherflow-v4-vm-matrix/artifacts/ubuntu-22.04-build/SHA256SUMS `
  --source-tarball /var/tmp/aetherflow-v4-validation-20261103-052723/source.tar.gz `
  --targets debian-12 debian-13 ubuntu-22.04 ubuntu-24.04
```

### Pre-Certification Verification & Evidence Fingerprinting

Before running guest lifecycle drills, `certify-matrix`:
1. **Requires an independent supplied `--artifact-sha256-file` (`SHA256SUMS`)** whenever `--artifact-tarball` is supplied, verifies that its path is distinct from the tarball, and cryptographically verifies the tarball SHA-256 against `SHA256SUMS`. It **never** synthesizes a sidecar checksum file.
2. **Inspects and fingerprints `--source-tarball`** via `inspect_source_tarball_layout`, determining the exact `strip_components` (`0` for flat-root archives, `1` for single top-level directory archives) without any `tar --strip-components=1 || tar ...` fallback that could silently drop root files or strip `setup/` paths on flat tarballs.
3. **Records full cryptographic provenance** in the JSON report under `artifact_validation`: `artifact_sha256`, `manifest_expected_sha256`, `manifest_file_sha256`, `source_sha256`, `source_layout`, and `contract_report`.

### Mandatory Lifecycle Phases (`MANDATORY_CERTIFICATION_PHASES`)

A target only receives `overall_status: "certified"` when **all four mandatory phases** execute and pass with `fixture_only: false` (an empty drill list `[]` or fixture-only pass always evaluates to `"failed"`):

1. **Phase 1 — `bootstrap_install_health_and_cli` (Mandatory)**:
   - Verifies independent `SHA256SUMS` inside the guest (`sha256sum -c SHA256SUMS`).
   - Verifies `_stage_prebuilt_release_archive` fails closed on a tampered SHA-256 digest before touching `/opt/AetherFlow/current`.
   - Runs `_syscommands`, `_build_modern_stack`, and `_boot` using the verified prebuilt tarball (`AETHERFLOW_PREBUILT_TARBALL` + `AETHERFLOW_PREBUILT_SHA256_FILE`).
   - Verifies `aetherflow-runner.service` and `aetherflow-api.service` are `active`, `http://127.0.0.1:8080/health/ready` returns HTTP 200, and `/usr/local/bin/af --version`, `af health --json`, and `af release status --json` succeed.
2. **Phase 2 — `release_update` (Mandatory)**:
   - Seeds a verification marker row (`release_marker = pre_v4_0_1`) into `/var/lib/aetherflow/aetherflow.sqlite`.
   - Stages a second verified release (`v4.0.1-matrix`), swaps `/opt/AetherFlow/current`, restarts systemd units, and verifies `.previous_release` points to the prior slot and `/health/ready` passes.
3. **Phase 3 — `failed_health_rollback_and_db_recovery` (Mandatory)**:
   - Deploys a candidate release (`v4.0.2-broken`) via `deploy/release-manager.sh deploy` whose binary intentionally corrupts `/var/lib/aetherflow/aetherflow.sqlite` and exits `1` (failing `/health/ready`).
   - Verifies `deploy/release-manager.sh deploy` exits with code `2` (`HealthProbeFailedRollback`), atomically reverts `/opt/AetherFlow/current` to `v4.0.1-matrix`, restores the pre-swap SQLite `.bak` snapshot (`PRAGMA integrity_check == ok` and `release_marker == pre_v4_0_1`), and brings `/health/ready` back to `ready`.
4. **Phase 4A — `interrupted_update_recovery_fixture` (Auxiliary Non-Certifying Fixture, `fixture_only: true`)**:
   - Exercises the `.recovery_state.json` (`phase: "stage2_symlink_swap"`) guard in `af release deploy --local` and rollback via `af release rollback --local --json`. Kept as a labeled auxiliary regression check that **cannot** satisfy certification on its own.
5. **Phase 4B — `interrupted_update_recovery` (Mandatory Real Launched Updater Interruption & Recovery, `fixture_only: false`)**:
   - Launches the real updater (`deploy/release-manager.sh deploy --channel stable`) in its own process group (`setsid`) deploying candidate `v4.0.3-interrupted`.
   - Allows the updater to execute its real Stage 1 scaffold, Stage 1.5 pre-swap SQLite backup (`data-snapshot/aetherflow.sqlite.bak`), and Stage 2 atomic symlink swap of `/opt/AetherFlow/current` to the candidate release.
   - Observes the controlled post-swap boundary when the updater enters Stage 3 and polls `http://127.0.0.1:8080/health/ready` (writing `/var/tmp/af-drill/post-swap-observed` with the swapped target path).
   - Verifies `/proc/<updater_pid>/cmdline` belongs to `release-manager.sh` and terminates **only** the owned updater process group (`kill -TERM -<updater_pid>`) before Stage 4 rollback can run, leaving the guest genuinely interrupted post-swap with `/opt/AetherFlow/current` pointing at `v4.0.3-interrupted` and `.previous_release` pointing at `v4.0.1-matrix`.
   - Recovers via the shipped CLI (`/usr/local/bin/af release rollback --local --json`) and asserts `/opt/AetherFlow/current` is restored to `v4.0.1-matrix`, SQLite passes `PRAGMA integrity_check == ok` with `release_marker == pre_v4_0_1`, both `aetherflow-runner.service` and `aetherflow-api.service` are `active`, and `http://127.0.0.1:8080/health/ready` succeeds.

---

## 6. Current Verification Status, Honesty Boundary & Remaining Integration Prerequisites

- **Verified**:
  - `python -m unittest tests/test_v4_vm_matrix.py -v` passes all 21 unit and regression tests (manifest parsing, `/var/tmp` path guardrails, QEMU command/env isolation, NoCloud seed generation, artifact/GLIBC contract verification, flat vs. single-top-dir source tarball layout extraction, independent `SHA256SUMS` enforcement, mandatory phase evaluation, baseline guest build script invariants, and single remote engine execution).
  - Official cloud images for **Debian 12**, **Debian 13**, **Ubuntu 22.04**, and **Ubuntu 24.04** are cached and cryptographically verified on `hetzner` under `/var/tmp/aetherflow-v4-vm-matrix/images`, and all 4 clean guests have been boot-verified under QEMU/KVM (`/var/tmp/aetherflow-v4-vm-matrix/evidence/latest-boot-matrix.json`).
- **Remaining Integration Prerequisites Before Full OS Matrix Certification**:
  1. **Converged Rust Workspace Compilation (`af-host` & `Cargo.lock`)**: Other builders are still converging `backend-rs` (in the current `/var/tmp/aetherflow-v4-validation-20261103-052723/source-20261103-055020` snapshot, `af-host` fails to compile due to unstable edits, and a final converged `backend-rs/Cargo.lock` must be present).
  2. **Build the Converged Ubuntu 22.04 (`GLIBC 2.35`) Release Bundle**: Once `backend-rs` compiles cleanly with a committed `Cargo.lock`, run `python scripts/v4_vm_matrix.py build-baseline-artifact ...` to produce `aetherflow-linux-amd64.tar.gz` + `SHA256SUMS`.
  3. **Execute `certify-matrix` Across All 4 OS Targets**: Run `python scripts/v4_vm_matrix.py certify-matrix ...` with the built `aetherflow-linux-amd64.tar.gz`, independent `SHA256SUMS`, and converged `source.tar.gz`.
  - **Honesty Boundary**: Full OS install/update/rollback/interrupted-recovery matrix certification is **not** claimed until `certify-matrix` completes with `overall_status: "certified"` across `debian-12`, `debian-13`, `ubuntu-22.04`, and `ubuntu-24.04` on the final converged release artifact.
