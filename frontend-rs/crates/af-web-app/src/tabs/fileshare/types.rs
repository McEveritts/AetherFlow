//! Version-tolerant shares, local entries, uploads, policies, and audit records.
use crate::tabs::contracts::{nullable, string};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) struct FetchedFile {
    pub(super) name: String,
    #[serde(default)]
    pub(super) size: u64,
    #[serde(default)]
    #[serde(alias = "mod_time")]
    pub(super) mod_time: String,
    #[serde(default)]
    pub(super) extension: String,
    #[serde(default)]
    #[serde(alias = "is_dir")]
    pub(super) is_dir: bool,
    #[serde(flatten)]
    pub(super) extra: BTreeMap<String, Value>,
}
pub(super) fn parse_files(value: &Value) -> Result<Vec<FetchedFile>, String> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    let rows = if value.is_array() {
        value
    } else {
        value
            .get("files")
            .or_else(|| value.get("entries"))
            .ok_or("Invalid directory response")?
    };
    serde_json::from_value(rows.clone()).map_err(|_| "Invalid directory response".into())
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct ShareRow {
    #[serde(deserialize_with = "string")]
    pub id: String,
    pub path: String,
    pub name: String,
    #[serde(alias = "isDirectory")]
    pub is_directory: bool,
    #[serde(alias = "passwordRequired")]
    pub password_required: bool,
    #[serde(alias = "expiresAt")]
    pub expires_at: Option<String>,
    #[serde(alias = "allowDownload")]
    pub allow_download: bool,
    #[serde(alias = "createdAt")]
    pub created_at: String,
    pub url: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct SharesPage {
    #[serde(deserialize_with = "nullable")]
    pub shares: Vec<ShareRow>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct CreatedShare {
    pub share: ShareRow,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct ChunkUploadResponse {
    pub message: String,
    pub error: Option<String>,
    pub filename: String,
    pub complete: Option<bool>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}
impl ChunkUploadResponse {
    pub fn failure_message(self) -> Option<String> {
        self.error
            .filter(|message| !message.is_empty())
            .or_else(|| (!self.message.is_empty()).then_some(self.message))
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct SharePermissions {
    pub read: Option<bool>,
    pub create: Option<bool>,
    pub rename: Option<bool>,
    pub modify: Option<bool>,
    pub delete: Option<bool>,
    pub share: Option<bool>,
    pub download: Option<bool>,
    pub execute: Option<bool>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct SharePathRule {
    pub path: String,
    pub allow: bool,
    pub regex: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct SharePolicy {
    pub permissions: SharePermissions,
    #[serde(deserialize_with = "nullable")]
    pub rules: Vec<SharePathRule>,
    pub scope: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct AuditRow {
    pub event_id: String,
    pub timestamp: String,
    pub user_id: i64,
    pub username: String,
    pub trigger: String,
    pub relative_path: String,
    pub destination_path: Option<String>,
    pub byte_delta: i64,
    pub status: String,
    pub error_code: Option<String>,
    pub updated_at: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub(super) struct AuditPage {
    #[serde(deserialize_with = "nullable")]
    pub events: Vec<AuditRow>,
    pub truncated: bool,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn share_rows_keep_one_time_urls_and_future_fields() {
        let created: CreatedShare = serde_json::from_value(json!({"share":{"id":9,"path":"audio.wav","url":"/share?token=once","allow_download":true,"new_policy":{"audit":true}}})).unwrap();
        assert_eq!(created.share.id, "9");
        assert!(created.share.allow_download);
        let value = serde_json::to_value(created).unwrap();
        assert_eq!(value["share"]["new_policy"]["audit"], true);
        let listed: SharesPage =
            serde_json::from_value(json!({"shares":[{"id":"9","url":null}]})).unwrap();
        assert!(listed.shares[0].url.is_none());
    }

    #[test]
    fn directory_rows_keep_unknown_fields_without_accepting_missing_names() {
        let files = parse_files(
            &json!({"entries":[{"name":"movie.mkv","mod_time":"today","size":4,"etag":"future"}]}),
        )
        .unwrap();
        assert_eq!(files[0].mod_time, "today");
        assert_eq!(serde_json::to_value(&files[0]).unwrap()["etag"], "future");
        assert!(parse_files(&json!([{"size":1}])).is_err());
    }

    #[test]
    fn chunk_completion_is_explicit_and_errors_keep_backend_messages() {
        let chunk: ChunkUploadResponse = serde_json::from_value(
            json!({"filename":"media.wav","complete":false,"message":"Chunk received"}),
        )
        .unwrap();
        assert_eq!(chunk.complete, Some(false));
        let failure: ChunkUploadResponse =
            serde_json::from_value(json!({"error":"Quota exceeded","code":"QUOTA_EXCEEDED"}))
                .unwrap();
        assert_eq!(failure.failure_message().as_deref(), Some("Quota exceeded"));
        assert_eq!(ChunkUploadResponse::default().complete, None);
    }

    #[test]
    fn policy_and_audit_contracts_keep_unknown_permissions_and_event_metadata() {
        let policy: SharePolicy = serde_json::from_value(
            json!({"scope":"user-2","permissions":{"share":false,"future":true},"rules":null}),
        )
        .unwrap();
        assert_eq!(policy.permissions.share, Some(false));
        assert_eq!(policy.permissions.download, None);
        assert_eq!(
            serde_json::to_value(policy).unwrap()["permissions"]["future"],
            true
        );
        let audit: AuditPage = serde_json::from_value(json!({"events":[{"event_id":"ev-1","trigger":"share.create","status":"success","byte_delta":-1,"receipt":"future"}],"truncated":true})).unwrap();
        assert!(audit.truncated);
        assert_eq!(audit.events[0].byte_delta, -1);
        assert_eq!(
            serde_json::to_value(audit).unwrap()["events"][0]["receipt"],
            "future"
        );
    }
}
