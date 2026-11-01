# Rust Host Management & Shared Backup Foundation (`af-host`)

## Overview

`backend-rs/crates/af-host` provides AetherFlow's bounded, shared Rust foundation for host backup orchestration, WAL-safe SQLite snapshotting, versioned backup manifests, SHA-256 artifact/sidecar verification, chunk splitting/reassembly, and non-destructive restore preflight planning.

It unifies the previously separate backup implementations across:
- **`packages/system/af-backup`** (host configuration `.tar.gz` archiving, `.sha256` sidecars, and `.part.00000` chunking),
- **`af-api::storage`** (`perform_system_backup`, `.sha256` sidecar verification, chunked upload/download, and retention pruning), and
- **`af-services::workers`** (`start_smart_backup_scheduler` / `execute_online_sqlite_backup`).

All host management and backup operations adhere strictly to AetherFlow's **bare-metal systemd + Apache2** architecture (`apache2.service` fronting `aetherflow-api.service` and `aetherflow-runner.service`, with zero Docker dependencies).

---

## Core Architectural & Safety Invariants

### 1. Never Plain-Copy a Live SQLite Database & Always Stage in Private `0700`/`0600` Storage
Copying a live SQLite database file (`aetherflow.sqlite`) using `std::fs::copy`, `cp`, or `tar` while writers or WAL frames (`-wal` / `-shm`) are active risks torn pages and uncheckpointed transactions.
- `af-host::snapshot` exclusively captures database snapshots via:
  1. **`SnapshotMethod::VacuumInto`** (`VACUUM INTO '<staging_path>'`) inside an exclusively created `0700` private staging directory on a busy-timeout-configured SQLite connection (followed by `0600` file permission tightening before moving out of the private staging directory), or
  2. **`SnapshotMethod::OnlineBackupApi`** (`rusqlite::backup::Backup` / `sqlite3_backup_init`) into a pre-created `0600` (`create_new` + `O_NOFOLLOW`) staging file with configurable page batches and step pauses.
- Every staged snapshot is verified read-only with `PRAGMA quick_check;` (plus `PRAGMA user_version;` and `PRAGMA journal_mode;`) **before** atomic rename into its final destination and `.sha256` sidecar generation.
- `snapshot_sqlite_with_conn` accepts an already borrowed `&rusqlite::Connection` so callers holding `af-db`'s `max_size(1)` pooled connection never deadlock by attempting a nested pool checkout.
- All backup directories, staging directories, archives, manifests, sidecars, and `.part.NNNNN` chunks are created with private `0700` directory / `0600` file permissions (`create_new(true)` + UUID-suffixed temporary filenames) **before** secret payload bytes are written.

### 2. Typed Versioned Manifest (`af-host.backup-manifest.v1`) & Cross-Entry Validation
Every backup bundle produces a `<artifact>.manifest.json` (and `<artifact>.manifest.json.sha256` sidecar) backed by [`BackupManifest`](../backend-rs/crates/af-host/src/manifest.rs):
- **`format`**: `"af-host.backup-manifest.v1"`
- **`schema_version`**: `1` (validated against `MIN_SUPPORTED_MANIFEST_SCHEMA_VERSION..=MAX_SUPPORTED_MANIFEST_SCHEMA_VERSION`)
- **`app_version` & `min_compatible_app_version`**: Semantic version triplet checking via `BackupManifest::check_compatibility`, rejecting cross-major restores or restores from a newer minor/patch backup onto an older host binary.
- **`sqlite_snapshot`**: Optional [`SqliteSnapshotMetadata`](../backend-rs/crates/af-host/src/manifest.rs) recording `capture_method` (`vacuum_into` or `online_backup_api`), `sqlite_user_version`, `journal_mode`, `integrity_check` (`"ok"`), `size_bytes`, and `sha256`. Plain file copy capture methods are rejected at manifest validation time. `BackupManifest::validate` cross-checks `sqlite_snapshot` against a matching `BackupTargetKind::SqliteSnapshot` entry in `entries` (verifying identical `relative_path`, `sha256`, and `size_bytes`) and rejects orphan `SqliteSnapshot` entries or inconsistent `chunk_count`/`chunk_size_bytes` fields.
- **`entries`**: Ordered list of [`BackupManifestEntry`](../backend-rs/crates/af-host/src/manifest.rs) records with normalized relative paths, `BackupTargetKind`, `sha256`, `size_bytes`, optional `unix_mode`, and `required` flags.

### 3. Dual-Compatible SHA-256 Sidecar, Exact 5-Digit Chunking & Full Artifact Verification
- `write_sha256_sidecar` atomically writes GNU `sha256sum`-compatible sidecars (`<64-hex>  <basename>\n`) via an exclusive `0600` UUID-suffixed temporary file.
- `parse_sha256_sidecar_str` and `verify_file_with_sidecar` accept both GNU `sha256sum` format (`packages/system/af-backup`) and single-token `<64-hex>\n` sidecars (`af-api` / `af-services`).
- `split_backup_into_chunks` removes any stale `<file>.part.<5 digits>` regular files before splitting, creates each `<file>.part.00000` chunk exclusively with `0600` permissions, and `list_backup_inventory` / `delete_backup_artifacts` match only exact 5-digit `.part.NNNNN` non-symlink regular files.
- `verify_backup_artifact` validates the primary `.sha256` sidecar, loads and verifies `<filename>.manifest.json` (+ sidecar), verifies all `.tar.gz` archive members against `manifest.entries` (or runs `PRAGMA quick_check` on standalone `.sqlite` artifacts), and verifies that any `.part.00000`..`.part.<N-1>` chunks on disk match `manifest.chunk_count`, `chunk_size_bytes`, total byte length, and concatenated SHA-256 digest.

### 4. Non-Destructive Restore Planning & Preflight (Explicitly Unsupported Destructive Restore)
- `plan_restore_from_manifest`, `preflight_restore_directory`, and `preflight_tar_gz_archive` are **strictly non-destructive**: they never write to, overwrite, or delete files under `target_root`.
- **Path Traversal Rejection**: Any entry path with `..`, `.`, empty segments, leading `/` or `\`, Windows drive prefixes (`C:`), or NUL bytes is rejected with `HostBackupError::TraversalRejected`.
- **Full-Ancestor Symlink & Link Rejection**: `reject_if_symlink` and `reject_symlink_chain` inspect every existing ancestor component from the filesystem root to the leaf (`backup_dir`, source SQLite DB, `target_root`, and staged paths) and propagate unexpected metadata errors. Any symbolic link (`EntryType::Symlink`), hard link (`EntryType::Link`), FIFO/device node in a tar stream or source directory — or any existing symlink along an ancestor chain — is rejected with `HostBackupError::SymlinkRejected`.
- **Normalized Staging `target_root` & Unsafe Overwrite Rejection**: `target_root` must be an absolute path free of `.` or `..` segments with at least two normal path components, and must not target system roots (`/`, `//etc`, `/etc`, `/var`, `/var/lib`, `/usr`, `/proc`, `/sys`, `/dev`, `/tmp`, `/opt`, `C:\Windows`, etc.). Under `OverwritePolicy::RejectExisting` (the default), any pre-existing file or directory at a planned destination fails closed with `HostBackupError::UnsafeOverwriteRejected`.
- **Streaming `.tar.gz` SQLite Integrity Caveat**: `preflight_restore_directory` runs live `PRAGMA quick_check` on standalone SQLite snapshot files (`RestorePlan::sqlite_integrity_verified = true`), whereas `preflight_tar_gz_archive` streams `.tar.gz` entries in-memory and verifies the SQLite member's SHA-256 and byte size against the manifest without extracting to disk (`RestorePlan::sqlite_integrity_verified = false`).
- **Destructive Restore Disabled by Design**: `execute_destructive_restore` always returns `Err(HostBackupError::DestructiveRestoreUnsupported)` rather than performing an uncoordinated live overwrite while `aetherflow-api.service` or managed systemd units hold open database/config descriptors.

---

## Exported Public API (`af_host`)

| Module | Exported Types & Functions | Purpose |
| :--- | :--- | :--- |
| `error` | `HostBackupError`, `HostBackupResult` | Typed error taxonomy with `is_security_rejection()` and `is_integrity_failure()` classifiers |
| `manifest` | `BackupManifest`, `BackupManifestEntry`, `BackupTargetKind`, `SqliteSnapshotMetadata`, `CompatibilityReport`, `parse_semver_triplet`, `BACKUP_MANIFEST_FORMAT`, `CURRENT_MANIFEST_SCHEMA_VERSION` | Versioned manifest serialization, atomic persistence with `.sha256` sidecar, and host/SQLite version compatibility checks |
| `snapshot` | `SnapshotMethod`, `SnapshotOptions`, `SqliteSnapshotReceipt`, `snapshot_sqlite_database`, `snapshot_sqlite_with_conn`, `verify_sqlite_snapshot_integrity` | WAL-consistent SQLite snapshots (`VACUUM INTO` / Online Backup API) + `PRAGMA quick_check` verification |
| `verify` | `ChecksumVerification`, `compute_file_sha256`, `write_sha256_sidecar`, `verify_file_sha256`, `verify_file_with_sidecar`, `parse_sha256_sidecar_str`, `checksum_sidecar_path`, `validate_backup_filename`, `safe_backup_file_path`, `validate_no_parent_traversal`, `validate_relative_backup_path`, `reject_if_symlink`, `reject_symlink_chain`, `split_backup_into_chunks`, `assemble_verified_chunks` | Streaming SHA-256 verification, sidecar management, traversal/symlink guards, and chunk split/reassembly |
| `restore` | `OverwritePolicy`, `PlannedRestoreAction`, `RestorePlan`, `RestorePlanItem`, `RestorePreflightOptions`, `StagedRestoreReceipt`, `plan_restore_from_manifest`, `preflight_restore_directory`, `preflight_tar_gz_archive`, `execute_coordinated_restore`, `execute_staged_restore`, `execute_destructive_restore` | Non-destructive restore planning, streaming `.tar.gz` & directory preflight inspection, verified staged extraction (`execute_staged_restore`), and explicit refusal of uncoordinated live root overwrite |
| `backup` | `HostBackupConfig`, `HostBackupTargetSpec`, `HostBackupReceipt`, `BackupInventoryItem`, `MaintenanceOwnerCrate`, `MaintenanceHelperOwnership`, `create_sqlite_snapshot_backup`, `create_host_archive_backup`, `default_host_targets_for_root`, `list_backup_inventory`, `verify_backup_artifact`, `delete_backup_artifacts`, `prune_backup_inventory`, `maintenance_helper_ownership_registry` | End-to-end backup creation, inventory listing, retention pruning, and system maintenance ownership registry |
| `maintenance` | `SentinelScanReport`, `SentinelOffender`, `NetworkTuningReport`, `LogCleanupReport`, `UserSpaceEntry`, `ShowspaceReport`, `sentinel_scan_auth_log`, `compute_sysctl_network_tuning`, `apply_network_tuning`, `clean_system_logs`, `inspect_home_disk_space` | Native Rust implementations of `af-sentinel.py`, `af-tune`, log cleanup (`af-heal`), and `showspace` |

---

## Maintenance Helper Ownership Decisions (`packages/system/*`)

To keep crate boundaries clean and avoid privilege escalation inside unprivileged workers, host maintenance scripts under `packages/system/` are partitioned across the Rust workspace as follows (codified programmatically in `af_host::maintenance_helper_ownership_registry()`):

| System Helper | Owner Crate / Boundary | Rust Entry Point / Status | Ownership Rationale |
| :--- | :--- | :--- | :--- |
| `packages/system/af-backup` | **`af-host`** (shared library) | `af_host::{create_sqlite_snapshot_backup, create_host_archive_backup, verify_backup_artifact, preflight_tar_gz_archive, execute_staged_restore}` | Shared library foundation used by `af-api`, `af-services::workers`, and `af-cli`. Replaces raw `tar` over live files with manifest-verified archives and WAL-safe SQLite snapshots. |
| `packages/system/af-heal` | **`af-services`** + **`af-runner`** + **`af-host`** | `af_services::workers::start_heal_worker` $\to$ `af_runner` (`/v1/systemctl` restart) + `af_host::clean_system_logs` | Service watchdog state and notification persistence live in `af-services`; privileged `systemctl restart` is isolated in `af-runner`; stale log cleanup (`>7d`) is provided by `af_host::clean_system_logs`. |
| `packages/system/af-systemd-sandbox` | **`af-runner`** | `af_runner::{apply_package_sandbox_local, render_systemd_sandbox_dropin}` | Writing `/etc/systemd/system/<unit>.service.d/aetherflow-sandbox.conf` and running `systemctl daemon-reload` requires root privileges in `af-runner`. |
| `packages/system/setdisk` | **`af-runner`** | `af_runner::{execute_set_quota_local, parse_quota_size_to_1k_blocks}` | Invoking `setquota -u <user> ... -a` requires root privileges in `af-runner`. |
| `packages/system/updateAetherFlow` | **`af-release`** | `af_release` + `deploy/release-manager.sh` | Single-binary control-plane upgrades, pre-swap SQLite snapshots, and atomic `/opt/AetherFlow/current` symlink swaps are owned by `af-release`. |
| `packages/system/af-certbot-sync` | **Retained System Script** + **`af-runner`** | `af_runner::update_hosts_file_local` (`/etc/hosts`) + `af-certbot-sync` timer | Internal `.aether.local` `/etc/hosts` block management is owned by `af-runner`/`af-services`; external Let's Encrypt `certbot --expand` + `systemctl reload apache2` remains a root systemd timer script. |
| `packages/system/af-tune` | **`af-host`** + **`af-cli`** | `af_host::{compute_sysctl_network_tuning, apply_network_tuning}` (`af tune` / `af provision run bbr`) | Native Rust generator and atomic writer for `/etc/sysctl.d/99-aetherflow-tune.conf` (`bbr` + `fq` + 64 MiB socket buffers). |
| `packages/system/af-sentinel.py` | **`af-host`** + **`af-cli`** | `af_host::sentinel_scan_auth_log` (`af sentinel`) | Native Rust `/var/log/auth.log` brute-force scanner parsing IPv4/IPv6 failed SSH attempts without following symlinks. |
| `packages/system/showspace` | **`af-host`** + **`af-cli`** + **`af-hardware`** | `af_host::inspect_home_disk_space` (`af showspace`) + `af_hardware::get_system_metrics_core` | Native Rust `/home/<user>` recursive disk usage calculator (`af showspace`) alongside control-plane partition/quota telemetry. |

---

## Staged Restore & Runtime Integration

1. **Coordinated Staged Restore (`execute_staged_restore` / `execute_coordinated_restore`)**:
   - Uncoordinated live root overwrite (`execute_destructive_restore`) continues to return `Err(HostBackupError::DestructiveRestoreUnsupported)`.
   - `execute_staged_restore` (`af backup restore <filename> --staging-root <dir>`) runs full `.sha256` sidecar + `.manifest.json` preflight verification, extracts all archive entries into an isolated staging directory (`0700` dirs / `0600` files) without following symlinks, re-verifies every extracted file's SHA-256 digest against the manifest, and runs `PRAGMA quick_check` on any extracted SQLite snapshot (`sqlite_integrity_verified = true`).
2. **Smart Backup Worker Consolidation (`af-services::workers`)**:
   - `execute_online_sqlite_backup` in `backend-rs/crates/af-services/src/workers.rs` delegates directly to `af_host::create_sqlite_snapshot_backup` with `SnapshotMethod::OnlineBackupApi`, generating verified `.sqlite`, `.sqlite.sha256`, `.sqlite.manifest.json`, and `.sqlite.manifest.json.sha256` artifacts and pruning expired sidecars/manifests cleanly.

## Validation

The crate passes all 18 unit tests with `cargo test -p af-host` in an isolated Linux checkout, covering ancestor symlink rejection, private filesystem permissions, manifest/archive/chunk tampering, staged restore extraction and SQLite `quick_check` verification, `sentinel_scan_auth_log`, `apply_network_tuning`, `clean_system_logs`, `inspect_home_disk_space`, and concurrent atomic writes.
