use crate::mcbrowser::McBrowserError;
use af_files::Entry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Deserialize, Default)]
pub struct SearchQuery {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub q: String,
    #[serde(default, rename = "type")]
    pub entry_type: Option<String>,
    #[serde(default)]
    pub ai: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct SearchResponse {
    pub entries: Vec<Entry>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_interpretation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ai_powered: Option<bool>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum OperationConflictPolicy {
    #[default]
    Error,
    Overwrite,
    KeepBoth,
}

impl OperationConflictPolicy {
    pub fn parse(raw: &str) -> Result<Self, McBrowserError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "error" | "fail" | "none" => Ok(Self::Error),
            "overwrite" | "override" | "replace" => Ok(Self::Overwrite),
            "keep-both" | "keep_both" | "keepboth" | "rename" => Ok(Self::KeepBoth),
            _ => Err(McBrowserError::BadRequest(
                "Invalid conflict resolution policy: expected 'error', 'overwrite' ('override'), or 'keep-both' ('rename')".to_string(),
            )),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Overwrite => "overwrite",
            Self::KeepBoth => "keep-both",
        }
    }
}

impl Serialize for OperationConflictPolicy {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for OperationConflictPolicy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(|error| {
            serde::de::Error::custom(match error {
                McBrowserError::BadRequest(message) => message,
                other => format!("{other:?}"),
            })
        })
    }
}

pub fn resolve_operation_conflict_policy(
    conflict: Option<OperationConflictPolicy>,
    overwrite_flag: Option<bool>,
    rename_flag: Option<bool>,
) -> Result<OperationConflictPolicy, McBrowserError> {
    if overwrite_flag == Some(true) && rename_flag == Some(true) {
        return Err(McBrowserError::BadRequest(
            "Conflict options 'overwrite' and 'rename' ('keep-both') cannot both be true"
                .to_string(),
        ));
    }

    let flag_derived = if overwrite_flag == Some(true) {
        Some(OperationConflictPolicy::Overwrite)
    } else if rename_flag == Some(true) {
        Some(OperationConflictPolicy::KeepBoth)
    } else if overwrite_flag == Some(false) || rename_flag == Some(false) {
        Some(OperationConflictPolicy::Error)
    } else {
        None
    };

    match (conflict, flag_derived) {
        (Some(explicit), Some(derived)) if explicit != derived => Err(McBrowserError::BadRequest(
            "Conflicting conflict policy and boolean override/rename flags".to_string(),
        )),
        (Some(explicit), _) => Ok(explicit),
        (None, Some(derived)) => Ok(derived),
        (None, None) => Ok(OperationConflictPolicy::Error),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CopyRequest {
    pub from: String,
    pub to: String,
    #[serde(default, alias = "policy", alias = "on_conflict", alias = "onConflict")]
    pub conflict: Option<OperationConflictPolicy>,
    #[serde(default, rename = "override", alias = "overwrite", alias = "replace")]
    pub overwrite_existing: Option<bool>,
    #[serde(default, alias = "keep_both", alias = "keepBoth")]
    pub rename: Option<bool>,
}

impl CopyRequest {
    pub fn resolved_conflict_policy(&self) -> Result<OperationConflictPolicy, McBrowserError> {
        resolve_operation_conflict_policy(self.conflict, self.overwrite_existing, self.rename)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RenameMoveRequest {
    pub from: String,
    pub to: String,
    #[serde(default, alias = "policy", alias = "on_conflict", alias = "onConflict")]
    pub conflict: Option<OperationConflictPolicy>,
    #[serde(default, rename = "override", alias = "overwrite", alias = "replace")]
    pub overwrite_existing: Option<bool>,
    #[serde(default, alias = "keep_both", alias = "keepBoth")]
    pub rename: Option<bool>,
}

impl RenameMoveRequest {
    pub(crate) fn resolved_conflict_policy(
        &self,
    ) -> Result<OperationConflictPolicy, McBrowserError> {
        resolve_operation_conflict_policy(self.conflict, self.overwrite_existing, self.rename)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CopyMoveResponse {
    pub success: bool,
    pub path: String,
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub accounting_pending: bool,
}

#[derive(Debug, Deserialize)]
pub struct DeleteRecursiveRequest {
    pub path: String,
}

#[derive(Debug, Serialize)]
pub struct ContentResponse {
    pub path: String,
    pub content: String,
    pub etag: String,
}

#[derive(Debug, Deserialize)]
pub struct PutContentRequest {
    pub content: String,
    pub etag: String,
}

#[derive(Debug, Serialize)]
pub struct PutContentResponse {
    pub success: bool,
    pub etag: String,
    pub accounting_pending: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateFileRequest {
    pub path: String,
    #[serde(default)]
    pub content: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct InfoQuery {
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub checksum: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoResponse {
    pub entry: Entry,
    pub checksums: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_files: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_dirs: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct ArchiveRequest {
    pub paths: Vec<String>,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArchiveTicketResponse {
    pub url: String,
    pub filename: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SearchKindFilter {
    Any,
    File,
    Directory,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChecksumAlgorithm {
    Md5,
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    Tar,
    TarGz,
    TarBz2,
    TarXz,
    TarLz4,
    TarSz,
    TarBr,
    TarZst,
}

impl ArchiveFormat {
    #[cfg(test)]
    pub const ALL: [ArchiveFormat; 9] = [
        Self::Zip,
        Self::Tar,
        Self::TarGz,
        Self::TarBz2,
        Self::TarXz,
        Self::TarLz4,
        Self::TarSz,
        Self::TarBr,
        Self::TarZst,
    ];

    pub fn parse(raw: &str) -> Result<Self, McBrowserError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "zip" | ".zip" => Ok(Self::Zip),
            "tar" | ".tar" => Ok(Self::Tar),
            "targz" | "tar.gz" | ".tar.gz" | "tgz" => Ok(Self::TarGz),
            "tarbz2" | "tar.bz2" | ".tar.bz2" | "tbz2" => Ok(Self::TarBz2),
            "tarxz" | "tar.xz" | ".tar.xz" | "txz" => Ok(Self::TarXz),
            "tarlz4" | "tar.lz4" | ".tar.lz4" | "tlz4" => Ok(Self::TarLz4),
            "tarsz" | "tar.sz" | ".tar.sz" | "tsz" => Ok(Self::TarSz),
            "tarbr" | "tar.br" | ".tar.br" | "tbr" => Ok(Self::TarBr),
            "tarzst" | "tar.zst" | ".tar.zst" | "tzst" => Ok(Self::TarZst),
            _ => Err(McBrowserError::BadRequest(
                "Invalid archive format: expected one of 'zip', 'tar', 'targz' ('tar.gz'), 'tarbz2' ('tar.bz2'), 'tarxz' ('tar.xz'), 'tarlz4' ('tar.lz4'), 'tarsz' ('tar.sz'), 'tarbr' ('tar.br'), or 'tarzst' ('tar.zst')".to_string(),
            )),
        }
    }

    pub fn algo_id(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Tar => "tar",
            Self::TarGz => "targz",
            Self::TarBz2 => "tarbz2",
            Self::TarXz => "tarxz",
            Self::TarLz4 => "tarlz4",
            Self::TarSz => "tarsz",
            Self::TarBr => "tarbr",
            Self::TarZst => "tarzst",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Tar => "tar",
            Self::TarGz => "tar.gz",
            Self::TarBz2 => "tar.bz2",
            Self::TarXz => "tar.xz",
            Self::TarLz4 => "tar.lz4",
            Self::TarSz => "tar.sz",
            Self::TarBr => "tar.br",
            Self::TarZst => "tar.zst",
        }
    }

    pub fn content_type(self) -> &'static str {
        match self {
            Self::Zip => "application/zip",
            Self::Tar => "application/x-tar",
            Self::TarGz => "application/gzip",
            Self::TarBz2 => "application/x-bzip2",
            Self::TarXz => "application/x-xz",
            Self::TarLz4 => "application/x-lz4",
            Self::TarSz => "application/x-snappy-framed",
            Self::TarBr => "application/x-brotli",
            Self::TarZst => "application/zstd",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeleteRecursiveOutcome {
    pub removed_bytes: u64,
    pub accounting_pending: bool,
}
