use crate::BrowserFs;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub name: String,
    pub path: String,
    pub kind: String,
    pub size: u64,
    pub modified: Option<String>,
}

#[derive(Debug)]
pub struct ResolvedFile {
    pub file: File,
    pub resolved_path: String,
    pub resolution_paths: Vec<String>,
    pub entry: Entry,
}

#[derive(Debug)]
pub struct ResolvedDir {
    pub fs: BrowserFs,
    pub resolved_path: String,
    pub resolution_paths: Vec<String>,
    pub entry: Entry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedEntry {
    pub entry: Entry,
    pub resolved_path: String,
    pub resolution_paths: Vec<String>,
    pub was_symlink: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedDirListing {
    pub entries: Vec<Entry>,
    pub resolved_path: String,
    pub resolution_paths: Vec<String>,
    pub entry: Entry,
}

/// Error returned by [`BrowserFs::remove_tree_with_size`], carrying the total regular-file bytes
/// already unlinked before the failure occurred so callers can accurately adjust storage quotas.
#[derive(Debug)]
pub struct RemovalError {
    pub removed_bytes: u64,
    pub error: io::Error,
}

impl std::fmt::Display for RemovalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} (after removing {} bytes)",
            self.error, self.removed_bytes
        )
    }
}

impl std::error::Error for RemovalError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}
