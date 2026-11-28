pub mod app_metadata;
mod constant_time;
pub use constant_time::constant_time_eq;
mod marketplace;
pub mod md5;
pub mod secret_zeroize;
pub use secret_zeroize::{SecretBytes, SecretString};
#[cfg(not(target_arch = "wasm32"))]
pub mod package_receipts;
#[cfg(not(target_arch = "wasm32"))]
pub use package_receipts::{
    format_retained_package_receipt, inspect_canonical_package_receipt, inspect_package_receipts,
    inspect_receipt_file, inspect_retained_receipt_file, parse_port_from_receipt_content,
    read_package_receipt_port, read_receipt_file_bounded, resolve_package_fs_root,
    resolve_package_lock_name, resolve_package_lock_paths, resolve_path_for_fs_root,
    retained_receipt_path_for_canonical, PackageLockPaths, PackageReceiptStatus,
    MAX_PACKAGE_RECEIPT_BYTES,
};
#[cfg(not(target_arch = "wasm32"))]
mod paths;
mod runner;
pub mod secret_redaction;
mod telemetry;

pub use marketplace::*;
#[cfg(not(target_arch = "wasm32"))]
pub use paths::*;
pub use runner::*;
pub use telemetry::*;

pub(crate) fn is_zero_i32(val: &i32) -> bool {
    *val == 0
}

pub(crate) fn is_false(val: &bool) -> bool {
    !*val
}

#[cfg(test)]
mod tests;
