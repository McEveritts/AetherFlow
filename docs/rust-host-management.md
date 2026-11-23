# Rust Host Management & Shared Backup Foundation (`af-host`)

## Overview

`backend-rs/crates/af-host` provides AetherFlow's shared Rust foundation for host backup orchestration, WAL-safe SQLite snapshotting, versioned backup manifests, SHA-256 artifact/sidecar verification, chunk splitting/reassembly, non-destructive restore preflight planning, confirmed staged restore execution (`execute_staged_restore`) with service quiescence and write-ahead provenance recovery, and native host maintenance (`sentinel`, `tune`, `clean-logs`, `showspace`).

It unifies backup and host-maintenance implementations across:

- **`af backup` & `af maintenance` (`af-cli`)** (host configuration `.tar.gz` archiving, `.sha256` sidecars, `.part.00000` chunking, staged restore, and maintenance utilities),
- **`af-api::storage`** (`perform_system_backup`, `.sha256` sidecar verification, chunked upload/download, and retention pruning), and
- **`af-services::workers`** (`start_smart_backup_scheduler` / `execute_online_sqlite_backup`).

All host management and backup operations target bare-metal Linux hosts running `systemd` and `Apache2`.

---

## Core Architectural & Safety Invariants

### 1. Never Plain-Copy a Live SQLite Database & Always Stage in Private `0700`/`0600` Storage

Copying a live SQLite database file (`aetherflow.sqlite`) using `std::fs::copy`, `cp`, or `tar` while writers or WAL frames (`-wal` / `-shm`) are active risks torn pages and uncheckpointed transactions.

- `af-host::snapshot` exclusively captures database snapshots via:
  1. **`SnapshotMethod::VacuumInto`** (default in `SnapshotOptions::default()`): executes `VACUUM INTO '<staging_path>'` inside an exclusively created `0700` private staging directory on a busy-timeout-configured SQLite connection (followed by `0600` file permission tightening before moving out of staging), or
  2. **`SnapshotMethod::OnlineBackupApi`**: runs `rusqlite::backup::Backup` (`sqlite3_backup_init`) into a pre-created `0600` (`create_new` + `O_NOFOLLOW`) staging file with configurable page batches and step pauses.
- Every staged snapshot is verified read-only with **both** `PRAGMA quick_check;` and `PRAGMA integrity_check;` (plus `PRAGMA user_version;` and `PRAGMA journal_mode;`) **before** atomic rename into its final destination and `.sha256` sidecar generation.
- `snapshot_sqlite_with_conn` accepts an already borrowed `&rusqlite::Connection` so callers holding `af-db`'s `max_size(1)` pooled connection never deadlock by attempting a nested pool checkout.
- All backup directories, staging directories, archives, manifests, sidecars, and `.part.NNNNN` chunks are created with private `0700` directory / `0600` file permissions (`create_new(true)` + UUID-suffixed temporary filenames) **before** secret payload bytes are written.

### 2. Typed Versioned Manifest (`af-host.backup-manifest.v1`) & Cross-Entry Validation

Every backup bundle produces `<artifact>.manifest.json` (and `<artifact>.manifest.json.sha256`) backed by [`BackupManifest`](../backend-rs/crates/af-host/src/manifest.rs):

- **`format`**: `"af-host.backup-manifest.v1"`
- **`schema_version`**: `1` (validated against `MIN_SUPPORTED_MANIFEST_SCHEMA_VERSION..=MAX_SUPPORTED_MANIFEST_SCHEMA_VERSION`)
- **`app_version` & `min_compatible_app_version`**: Semantic version triplet checking via `BackupManifest::check_compatibility`, rejecting cross-major restores or restores from a newer minor/patch backup onto an older host binary.
- **`sqlite_snapshot`**: Optional [`SqliteSnapshotMetadata`](../backend-rs/crates/af-host/src/manifest.rs) recording `capture_method` (`vacuum_into` or `online_backup_api`), `sqlite_user_version`, `journal_mode`, `integrity_check` (`"ok"`), `size_bytes`, and `sha256`. Plain file-copy capture methods are rejected at manifest validation time. `BackupManifest::validate` cross-checks `sqlite_snapshot` against a matching `BackupTargetKind::SqliteSnapshot` entry in `entries` (verifying identical `relative_path`, `sha256`, and `size_bytes`) and rejects orphan `SqliteSnapshot` entries or inconsistent `chunk_count`/`chunk_size_bytes` fields.
- **`entries`**: Ordered list of [`BackupManifestEntry`](../backend-rs/crates/af-host/src/manifest.rs) records with normalized relative paths, `BackupTargetKind`, `sha256`, `size_bytes`, optional `unix_mode`, `logical_target_path`, `unix_uid`, `unix_gid`, and `required` flags.

### 3. Dual-Compatible SHA-256 Sidecar, Exact 5-Digit Chunking & Full Artifact Verification

- `write_sha256_sidecar` atomically writes GNU `sha256sum`-compatible sidecars (`<64-hex>  <basename>\n`) via an exclusive `0600` UUID-suffixed temporary file.
- `parse_sha256_sidecar_str` and `verify_file_with_sidecar` accept both GNU `sha256sum` format (`<64-hex>  <filename>\n`) and single-token `<64-hex>\n` sidecars (`af-api` / `af-services`).
- `split_backup_into_chunks` removes any stale `<file>.part.<5 digits>` regular files before splitting, creates each `<file>.part.00000` chunk exclusively with `0600` permissions, and `list_backup_inventory` / `delete_backup_artifacts` match only exact 5-digit `.part.NNNNN` non-symlink regular files.
- `verify_backup_artifact` validates the primary `.sha256` sidecar, loads and verifies `<filename>.manifest.json` (+ sidecar), verifies all `.tar.gz` archive members against `manifest.entries` (or runs `PRAGMA quick_check` + `PRAGMA integrity_check` on standalone `.sqlite` artifacts), and verifies that any `.part.00000`..`.part.<N-1>` chunks on disk match `manifest.chunk_count`, `chunk_size_bytes`, total byte length, and concatenated SHA-256 digest.

### 4. Restore Preflight, Confirmed Staged Restore & Unconfirmed Live-Overwrite Guard

- **Non-Destructive Preflight**: `plan_restore_from_manifest`, `preflight_restore_directory`, and `preflight_tar_gz_archive` never write to, overwrite, or delete files under `target_root`.
- **Path Traversal, Symlink & Archive Entry Rejection**: Any entry path with `..`, `.`, empty segments, leading `/` or `\`, Windows drive prefixes (`C:`), or NUL bytes is rejected with `HostBackupError::TraversalRejected`. Filesystem path checks (`reject_if_symlink` / `reject_symlink_chain`) inspect every existing ancestor component from root to leaf and reject symlinks with `HostBackupError::SymlinkRejected`. During tar inspection (`preflight_tar_gz_archive` and `execute_staged_restore`), `EntryType::Symlink` and `EntryType::Link` return `HostBackupError::SymlinkRejected`, while FIFOs and device nodes return `HostBackupError::Archive`.
- **`target_root` Validation & Overwrite Policy**: Internal `validate_safe_target_root` rejects `/` and allows only safe multi-segment staging directories (two or more normal components under `/tmp/...`, `/var/backups/...`, `/opt/...`, etc.); internal `validate_execution_target_root` permits canonical host root `/` (restricting every destination via `resolve_trusted_canonical_host_destination_with_sqlite_override`, which currently excludes `var/lib/aetherflow/.master.creds` and `var/lib/aetherflow/oidc_rsa.pem` — full archives containing either file must be restored into a staging directory and promoted manually) and delegates non-`/` staging roots to `validate_safe_target_root`. Single-component non-`/` roots, sensitive system subtrees (`etc`, `proc`, `sys`, `dev`, `boot`, `bin`, `sbin`, `lib`, `lib64`, `usr`, `windows`, `system32`), two-segment `/var/{lib,www,log,mail,spool,backups}`, and two-segment `/home/<user>` are rejected. Under `OverwritePolicy::RejectExisting` (default), pre-existing destination files fail closed with `HostBackupError::UnsafeOverwriteRejected`.
- **Streaming `.tar.gz` SQLite Integrity Caveat**: `preflight_restore_directory` runs live `PRAGMA quick_check` + `PRAGMA integrity_check` on standalone SQLite snapshot files (`RestorePlan::sqlite_integrity_verified = true`), whereas `preflight_tar_gz_archive` verifies the SQLite member's SHA-256 and byte size against the manifest in memory without extracting to disk (`RestorePlan::sqlite_integrity_verified = false`).
- **Confirmed Staged Execution (`execute_staged_restore`) vs. Unconfirmed Guard**: `execute_destructive_restore` always returns `Err(HostBackupError::DestructiveRestoreUnsupported)` to block unconfirmed overwrites. Confirmed restores run via `execute_staged_restore` (detailed in [Staged Restore & Runtime Integration](#staged-restore--runtime-integration)).

---

## Exported Public API (`af_host`)

| Module | Exported Types & Functions | Purpose |
| :--- | :--- | :--- |
| `error` | `HostBackupError`, `HostBackupResult` | Typed error taxonomy with `is_security_rejection()` and `is_integrity_failure()` classifiers |
| `manifest` | `BackupManifest`, `BackupManifestEntry`, `BackupTargetKind`, `SqliteSnapshotMetadata`, `CompatibilityReport`, `parse_semver_triplet`, `BACKUP_MANIFEST_FORMAT`, `CURRENT_MANIFEST_SCHEMA_VERSION` | Versioned manifest serialization, atomic persistence with `.sha256` sidecar, and host/SQLite version compatibility checks |
| `snapshot` | `SnapshotMethod`, `SnapshotOptions`, `SqliteSnapshotReceipt`, `snapshot_sqlite_database`, `snapshot_sqlite_with_conn`, `af_host::snapshot::snapshot_sqlite_with_conn_and_trusted_uid` (submodule-only), `verify_sqlite_snapshot_integrity`, `verify_sqlite_snapshot_integrity_with_trusted_uid` | WAL-consistent SQLite snapshots (`VACUUM INTO` default / `OnlineBackupApi`) + `PRAGMA quick_check` and `PRAGMA integrity_check` verification |
| `verify` | `ChecksumVerification`, `HostMaintenanceLockGuard`, `DEFAULT_MAINTENANCE_LOCK_PATH`, `resolve_maintenance_lock_path`, `resolve_trusted_service_account_ids`, `compute_file_sha256`, `write_sha256_sidecar`, `verify_file_sha256`, `verify_file_with_sidecar`, `parse_sha256_sidecar_str`, `checksum_sidecar_path`, `validate_backup_filename`, `safe_backup_file_path`, `validate_no_parent_traversal`, `validate_relative_backup_path`, `reject_if_symlink`, `reject_symlink_chain`, `open_existing_regular_file_nofollow`, `open_or_create_dir_nofollow`, `atomic_install_file_at_destination*`, `unlink_file_at_destination*`, `sync_parent_directory`, `split_backup_into_chunks`, `assemble_verified_chunks` | Streaming SHA-256 verification, sidecar management, traversal/symlink/nofollow guards, atomic destination install, maintenance locking, and chunk split/reassembly |
| `restore` | `OverwritePolicy`, `PlannedRestoreAction`, `RestorePlan`, `RestorePlanItem`, `RestorePreflightOptions`, `RestoreExecutionOptions`, `RestoreExecutionReport`, `RollbackFailureJournal`, `RollbackFailureJournalEntry`, `RecoveryContext`, `ServiceQuiescenceController`, `CommandQuiescenceController`, `NoopQuiescenceController`, `DEFAULT_MANDATORY_QUIESCE_SERVICES`, `IN_PROGRESS_RECOVERY_JOURNAL_FILENAME`, `plan_restore_from_manifest`, `preflight_restore_directory`, `preflight_tar_gz_archive`, `*_with_sqlite_override*`, `af_host::restore::*_for_execution` (submodule-only), `execute_staged_restore`, `recover_interrupted_restore`, `recover_interrupted_restore_with_context`, `resolve_recovery_provenance_dir`, `execute_destructive_restore` | Non-destructive restore planning, preflight inspection, quiesced/journaled staged restore execution, interrupted-restore recovery, and fail-closed unconfirmed overwrite guard |
| `backup` | `HostBackupConfig`, `HostBackupTargetSpec`, `HostBackupReceipt`, `BackupInventoryItem`, `MaintenanceOwnerCrate`, `MaintenanceHelperOwnership`, `DEFAULT_MAX_RETAINED_BACKUPS`, `DEFAULT_RETENTION_DAYS`, `create_sqlite_snapshot_backup`, `create_host_archive_backup`, `default_host_targets_for_root`, `list_backup_inventory`, `verify_backup_artifact`, `verify_backup_artifact_with_trusted_uid`, `delete_backup_artifacts`, `prune_backup_inventory`, `maintenance_helper_ownership_registry` | End-to-end backup creation, inventory listing, retention pruning, and system maintenance ownership registry |
| `maintenance` | `DEFAULT_SENTINEL_THRESHOLD`, `SentinelScanReport` (`ip_counts`, `offending_ips`), `TuningReport`, `CleanLogReport`, `CleanedLogFile`, `HomeSpaceEntry`, `sentinel_scan_auth_log`, `compute_sysctl_network_tuning`, `apply_network_tuning`, `clean_system_logs`, `inspect_home_disk_space`, `format_human_space_bytes` | Native Rust implementations powering `af maintenance` (`sentinel`, `tune`, `clean-logs`, `showspace`) |

---

## Maintenance Helper Ownership Decisions (`packages/system/*`)

Host maintenance scripts under `packages/system/` are partitioned across the Rust workspace in `af_host::maintenance_helper_ownership_registry()` (9 entries; the legacy `af-heal` shell script was retired and replaced by `af_services::workers::start_heal_worker`). Thin compatibility shims (`af-backup`, `af-sentinel.py`, `clean_log`, `af-tune`, `showspace`) remain under `packages/system/` forwarding to `af`:

| System Helper | Owner Crate / Boundary | Rust Entry Point / Status | Ownership Rationale |
| :--- | :--- | :--- | :--- |
| `packages/system/af-backup` (thin shim to `af backup`) | **`af-host`** + **`af-cli`** | `af_host::{create_sqlite_snapshot_backup, create_host_archive_backup, verify_backup_artifact, preflight_tar_gz_archive}` (`af backup`) | Shared library foundation used by `af-api`, `af-services::workers`, and `af-cli`. Replaces raw `tar` over live files with manifest-verified archives and WAL-safe SQLite snapshots. |
| `packages/system/clean_log` (thin shim to `af clean-logs`) | **`af-host`** | `af_host::clean_system_logs` (`af maintenance clean-logs`) | Bounded truncation of oversized `.log` files under `/var/log` and `/srv/aetherflow/lock` without following symlinks. |
| `packages/system/af-systemd-sandbox` | **`af-runner`** | `af_runner::{apply_package_sandbox_local, render_systemd_sandbox_dropin}` | Standalone `/v1/sandbox` / `af sandbox apply` path writes `/etc/systemd/system/<unit>.service.d/10-aetherflow-sandbox.conf`, removes legacy `aetherflow-sandbox.conf`, and runs `systemctl daemon-reload` with root privileges in `af-runner` (distinct from opt-in declarative recipe pre-start sandboxing in `package_executor/helpers.rs`, which writes both `aetherflow-sandbox.conf` and `10-aetherflow-sandbox.conf` under `<unit>.d/` where `<unit>` already includes `.service`). |
| `packages/system/setdisk` | **`af-runner`** | `af_runner::{execute_set_quota_local, parse_quota_size_to_1k_blocks}` | Invoking `setquota -u <user> ... -a` requires root privileges in `af-runner`. |
| `packages/system/updateAetherFlow` | **`af-release`** | `af_release` + `deploy/release-manager.sh` | Atomic multi-binary + external `web/dist/` release upgrades, pre-swap SQLite snapshots, and `/opt/AetherFlow/current` symlink swaps are owned by `af-release`. |
| `packages/system/af-certbot-sync` | **Retained System Script** + **`af-runner`** | `af_runner::update_hosts_file_local` (`/etc/hosts`) + `af-certbot-sync` | Internal `.aether.local` `/etc/hosts` block management is owned by `af-runner`/`af-services`; external Let's Encrypt `certbot --expand` + `systemctl reload apache2` remains a root system script. |
| `packages/system/af-tune` (thin shim to `af tune`) | **`af-host`** + **`af-cli`** | `af_host::{compute_sysctl_network_tuning, apply_network_tuning}` (`af tune` / `af provision run bbr`) | Native Rust generator and atomic writer for `/etc/sysctl.d/99-aetherflow-tune.conf` (`bbr` + `fq` + 64 MiB socket buffers). |
| `packages/system/af-sentinel.py` (thin shim to `af sentinel`) | **`af-host`** + **`af-cli`** | `af_host::sentinel_scan_auth_log` (`af maintenance sentinel` / `af sentinel`) | Native Rust `/var/log/auth.log` brute-force scanner parsing IPv4/IPv6 failed SSH attempts without following symlinks. |
| `packages/system/showspace` (thin shim to `af showspace`) | **`af-host`** + **`af-cli`** + **`af-hardware`** | `af_host::inspect_home_disk_space` (`af showspace`) + `af_hardware::get_system_metrics_core` | Native Rust `/home/<user>` recursive disk usage calculator (`Vec<HomeSpaceEntry>`) alongside control-plane partition/quota telemetry. |

---

## Staged Restore & Runtime Integration

### Coordinated Staged Restore (`execute_staged_restore`)

Unconfirmed live root overwrites (`execute_destructive_restore`) always fail closed with `HostBackupError::DestructiveRestoreUnsupported`. Confirmed restores (`af backup restore <filename> --target-root <dir> --confirm-destructive-restore`, returning `RestoreExecutionReport`) run the following sequence:

1. **Preflight Verification**: Validates `.sha256` sidecars, `.manifest.json` schema/semver compatibility, tar entry types, canonical `/` destination allowlist (excluding `.master.creds` / `oidc_rsa.pem`), and overwrite policy (`--allow-overwrite` required for existing targets on live `/`).
2. **Service Quiescence**: Stops writers via `ServiceQuiescenceController` (defaulting to `aetherflow-api.service`; on Linux without isolated `--root`, `CommandQuiescenceController` stops and restarts live `aetherflow-api.service` even when restoring into a staging directory).
3. **Rollback Snapshot & Provenance Journal**: Captures pre-restore rollback copies (including SQLite `-wal`/`-shm` sidecars) in private `0700`/`0600` staging storage and records a write-ahead recovery journal authenticated against protected provenance (`/etc/AetherFlow/.restore-provenance` or `<target_root>/.restore-provenance`).
4. **Atomic Install & Permission Sanitization**: Installs verified files atomically with per-class modes:
   - Secret files (`.env`, `.key`, `.pem`, `*secret*`, `*token*`): capped at `0600`.
   - SQLite snapshots: masked to `0660` (`0640` default).
   - Regular configuration files: masked to `0755` (`0640` fallback).
5. **Post-Install Verification & Rollback**: Re-verifies SHA-256 digests and runs `PRAGMA quick_check` + `PRAGMA integrity_check` (`sqlite_integrity_verified = true`), automatically rolling back on failure and restarting quiesced services on terminal success or rollback.

### Smart Backup Worker Consolidation (`af-services::workers`)

`execute_online_sqlite_backup` in `backend-rs/crates/af-services/src/workers.rs` calls `af_host::create_sqlite_snapshot_backup` with `SnapshotOptions::default()` (`SnapshotMethod::VacuumInto`), generating verified `.sqlite`, `.sqlite.sha256`, `.sqlite.manifest.json`, and `.sqlite.manifest.json.sha256` artifacts and pruning expired sidecars/manifests.

## Validation

`cargo test --manifest-path backend-rs/Cargo.toml -p af-host --locked` validates ancestor symlink rejection, private filesystem permissions, `.master.creds` and `oidc_rsa.pem` host preservation, manifest/archive/chunk tampering, quiesced staged restore and interrupted-restore provenance recovery, SQLite `quick_check` + `integrity_check` verification, `sentinel_scan_auth_log`, `apply_network_tuning`, `clean_system_logs`, `inspect_home_disk_space`, and concurrent atomic writes in an isolated Linux checkout.
