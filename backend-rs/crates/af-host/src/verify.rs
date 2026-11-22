//! SHA-256 file hashing, `.sha256` sidecar parsing/writing, path sanitization,
//! and chunked backup helper verification for `af-host`.
//!
//! Aligns with both `packages/system/af-backup` (`sha256sum <file> > <file>.sha256`
//! and `split -b ... <file>.part.00000`) and `af-api`/`af-services` (`<checksum>\n`
//! sidecar format).

mod checksums;
mod dirfd;
mod install;
mod lock;
mod paths;

pub(crate) use checksums::compute_reader_sha256;
pub use checksums::{
    assemble_verified_chunks, checksum_sidecar_path, compute_file_sha256,
    open_verified_regular_file_for_read, parse_sha256_sidecar_str,
    read_verified_text_file_nofollow, split_backup_into_chunks, verify_file_sha256,
    verify_file_sha256_with_trusted_uid, verify_file_with_sidecar,
    verify_file_with_sidecar_and_trusted_uid, write_sha256_sidecar, ChecksumVerification,
};
pub use dirfd::{
    open_existing_regular_file_nofollow, open_or_create_dir_nofollow,
    open_or_create_dir_nofollow_with_trusted_uid, open_or_create_provenance_dir_nofollow,
};
#[cfg(test)]
pub(crate) use install::set_pre_rename_install_hook;
pub use install::{
    atomic_install_file_at_destination,
    atomic_install_file_at_destination_with_trusted_ancestor_uid,
    atomic_install_file_at_destination_with_verification, unlink_file_at_destination,
    unlink_file_at_destination_with_trusted_ancestor_uid,
};
pub use lock::{
    resolve_maintenance_lock_path, resolve_trusted_service_account_ids, HostMaintenanceLockGuard,
    DEFAULT_MAINTENANCE_LOCK_PATH,
};
pub(crate) use paths::{
    create_unique_private_staging_dir, create_unique_private_temp_file, ensure_private_dir_all,
    parse_exact_chunk_index, set_private_file_permissions, write_private_file_atomic,
    write_private_file_atomic_tracking_rename,
};
pub use paths::{
    reject_if_symlink, reject_symlink_chain, safe_backup_file_path, sync_parent_directory,
    validate_backup_filename, validate_no_parent_traversal, validate_relative_backup_path,
};
