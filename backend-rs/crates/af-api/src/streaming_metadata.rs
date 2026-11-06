use axum::http::{header, StatusCode};
use once_cell::sync::Lazy;
use reqwest::Client;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use url::Url;

pub const MAX_ACTIVE_ITEM_IDS_PER_CALL: usize = 32;
pub const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(6);
pub const MAX_METADATA_JSON_PAYLOAD_BYTES: usize = 2 * 1024 * 1024;
pub const METADATA_CACHE_SUCCESS_TTL: Duration = Duration::from_secs(600);
pub const METADATA_CACHE_ERROR_TTL: Duration = Duration::from_secs(120);
pub const METADATA_CACHE_MAX_ENTRIES: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemLibraryLabel {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderItemMetadata {
    pub item_id: String,
    pub item_name: Option<String>,
    pub libraries: Vec<ItemLibraryLabel>,
    pub genres: Vec<String>,
}

#[derive(Debug, Clone)]
enum CacheValue {
    Success(ProviderItemMetadata),
    Error(StreamingMetadataError),
}

#[derive(Debug, Clone)]
struct CacheEntry {
    value: CacheValue,
    expires_at: Instant,
}

#[derive(Default)]
struct MetadataCache {
    entries: HashMap<(String, String, String), CacheEntry>,
    libraries: HashMap<(String, String), (HashMap<String, String>, Instant)>,
}

impl MetadataCache {
    fn get(
        &self,
        provider: &str,
        server_id: &str,
        item_id: &str,
        now: Instant,
    ) -> Option<CacheValue> {
        let key = (
            provider.trim().to_ascii_lowercase(),
            server_id.trim().to_string(),
            item_id.trim().to_string(),
        );
        let entry = self.entries.get(&key)?;
        if entry.expires_at > now {
            Some(entry.value.clone())
        } else {
            None
        }
    }

    fn put(
        &mut self,
        provider: &str,
        server_id: &str,
        item_id: &str,
        value: CacheValue,
        ttl: Duration,
        now: Instant,
    ) {
        let key = (
            provider.trim().to_ascii_lowercase(),
            server_id.trim().to_string(),
            item_id.trim().to_string(),
        );
        if self.entries.len() >= METADATA_CACHE_MAX_ENTRIES {
            self.entries.retain(|_, entry| entry.expires_at > now);
            if self.entries.len() >= METADATA_CACHE_MAX_ENTRIES {
                if let Some(first_key) = self.entries.keys().next().cloned() {
                    self.entries.remove(&first_key);
                }
            }
        }
        self.entries.insert(
            key,
            CacheEntry {
                value,
                expires_at: now + ttl,
            },
        );
    }

    fn get_libraries(
        &self,
        provider: &str,
        server_id: &str,
        now: Instant,
    ) -> Option<HashMap<String, String>> {
        let key = (
            provider.trim().to_ascii_lowercase(),
            server_id.trim().to_string(),
        );
        let (libs, exp) = self.libraries.get(&key)?;
        if *exp > now {
            Some(libs.clone())
        } else {
            None
        }
    }

    fn put_libraries(
        &mut self,
        provider: &str,
        server_id: &str,
        libs: HashMap<String, String>,
        ttl: Duration,
        now: Instant,
    ) {
        self.libraries.retain(|_, (_, expiry)| *expiry > now);
        if self.libraries.len() >= METADATA_CACHE_MAX_ENTRIES {
            if let Some(key) = self.libraries.keys().next().cloned() {
                self.libraries.remove(&key);
            }
        }
        let key = (
            provider.trim().to_ascii_lowercase(),
            server_id.trim().to_string(),
        );
        self.libraries.insert(key, (libs, now + ttl));
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.libraries.clear();
    }
}

static METADATA_CACHE: Lazy<Mutex<MetadataCache>> =
    Lazy::new(|| Mutex::new(MetadataCache::default()));

static METADATA_HTTP_CLIENT: Lazy<Client> = Lazy::new(|| {
    af_services::streaming_http_client_builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(HTTP_REQUEST_TIMEOUT)
        .pool_max_idle_per_host(8)
        .build()
        .expect("bounded metadata HTTP client")
});

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamingMetadataError {
    InvalidProvider(String),
    InvalidUrl(String),
    ServerIdMismatch { expected: String, actual: String },
    TooManyItems { count: usize, max: usize },
    PayloadTooLarge { limit_bytes: usize },
    RedirectDisallowed(u16),
    Transport(String),
    UpstreamStatus { status: u16, path: String },
    InvalidPayload(String),
    Database(String),
}

impl std::fmt::Display for StreamingMetadataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidProvider(p) => write!(f, "unsupported streaming metadata provider: {p}"),
            Self::InvalidUrl(msg) => write!(f, "invalid server URL: {msg}"),
            Self::ServerIdMismatch { expected, actual } => {
                write!(
                    f,
                    "server identity mismatch: expected {expected}, got {actual}"
                )
            }
            Self::TooManyItems { count, max } => {
                write!(f, "item count {count} exceeds batch maximum of {max}")
            }
            Self::PayloadTooLarge { limit_bytes } => {
                write!(f, "payload exceeded limit of {limit_bytes} bytes")
            }
            Self::RedirectDisallowed(code) => {
                write!(f, "upstream HTTP redirect {code} is disallowed")
            }
            Self::Transport(msg) => write!(f, "transport error: {msg}"),
            Self::UpstreamStatus { status, path } => {
                write!(f, "upstream HTTP {status} for path {path}")
            }
            Self::InvalidPayload(msg) => write!(f, "invalid payload: {msg}"),
            Self::Database(msg) => write!(f, "database error: {msg}"),
        }
    }
}

impl std::error::Error for StreamingMetadataError {}

impl From<rusqlite::Error> for StreamingMetadataError {
    fn from(err: rusqlite::Error) -> Self {
        Self::Database(err.to_string())
    }
}

pub fn normalize_metadata_provider(raw: &str) -> Result<String, StreamingMetadataError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "jellyfin" => Ok("jellyfin".to_string()),
        "emby" => Ok("emby".to_string()),
        other => Err(StreamingMetadataError::InvalidProvider(other.to_string())),
    }
}

pub fn validate_and_clean_server_url(raw: &str) -> Result<String, StreamingMetadataError> {
    let validated = af_services::validate_server_url(raw).map_err(|_| {
        StreamingMetadataError::InvalidUrl("invalid or disallowed target".to_string())
    })?;
    let parsed =
        Url::parse(raw.trim()).map_err(|e| StreamingMetadataError::InvalidUrl(e.to_string()))?;
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(StreamingMetadataError::InvalidUrl(
            "scheme must be http or https".to_string(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(StreamingMetadataError::InvalidUrl(
            "credentials not allowed in URL".to_string(),
        ));
    }
    if parsed.query().is_some() {
        return Err(StreamingMetadataError::InvalidUrl(
            "query parameters not allowed in base URL".to_string(),
        ));
    }
    if parsed.fragment().is_some() {
        return Err(StreamingMetadataError::InvalidUrl(
            "fragments not allowed in base URL".to_string(),
        ));
    }
    parsed
        .host_str()
        .ok_or_else(|| StreamingMetadataError::InvalidUrl("missing host".to_string()))?;
    Ok(validated)
}

fn sanitize_header_token(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_graphic() && *c != '"' && *c != '\\')
        .take(512)
        .collect()
}

pub async fn execute_provider_request(
    client: &Client,
    method: reqwest::Method,
    url: &str,
    provider: &str,
    api_key: &str,
) -> Result<(Vec<u8>, StatusCode), StreamingMetadataError> {
    let mut req = client.request(method, url).timeout(HTTP_REQUEST_TIMEOUT);
    let clean_key = sanitize_header_token(api_key);
    if !clean_key.is_empty() {
        if provider == "jellyfin" {
            let auth_val = format!(
                "MediaBrowser Client=\"AetherFlow\", Device=\"Nexus\", DeviceId=\"aetherflow-nexus\", Version=\"4.0\", Token=\"{}\"",
                clean_key
            );
            req = req
                .header("X-Emby-Token", &clean_key)
                .header("X-MediaBrowser-Token", &clean_key)
                .header(header::AUTHORIZATION, auth_val);
        } else if provider == "emby" {
            let auth_val = format!(
                "Emby Client=\"AetherFlow\", Device=\"Nexus\", DeviceId=\"aetherflow-nexus\", Version=\"4.0\", Token=\"{}\"",
                clean_key
            );
            req = req
                .header("X-Emby-Token", &clean_key)
                .header("X-Emby-Authorization", &auth_val)
                .header(header::AUTHORIZATION, auth_val);
        }
    }
    req = req.header(header::ACCEPT, "application/json");

    let mut resp = req
        .send()
        .await
        .map_err(|e| StreamingMetadataError::Transport(e.to_string()))?;

    let status = resp.status();
    if status.is_redirection() {
        return Err(StreamingMetadataError::RedirectDisallowed(status.as_u16()));
    }

    if let Some(content_len) = resp.content_length() {
        if content_len > MAX_METADATA_JSON_PAYLOAD_BYTES as u64 {
            return Err(StreamingMetadataError::PayloadTooLarge {
                limit_bytes: MAX_METADATA_JSON_PAYLOAD_BYTES,
            });
        }
    }

    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| StreamingMetadataError::Transport(e.to_string()))?
    {
        if body.len().saturating_add(chunk.len()) > MAX_METADATA_JSON_PAYLOAD_BYTES {
            return Err(StreamingMetadataError::PayloadTooLarge {
                limit_bytes: MAX_METADATA_JSON_PAYLOAD_BYTES,
            });
        }
        body.extend_from_slice(&chunk);
    }

    Ok((body, status))
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct PublicSystemInfoRaw {
    #[serde(default)]
    id: String,
}

pub async fn verify_remote_server_identity(
    client: &Client,
    clean_url: &str,
    provider: &str,
    api_key: &str,
    expected_server_id: &str,
) -> Result<String, StreamingMetadataError> {
    let probe_url = format!("{clean_url}/System/Info/Public");
    let (body, status) =
        execute_provider_request(client, reqwest::Method::GET, &probe_url, provider, api_key)
            .await?;
    if status != StatusCode::OK {
        return Err(StreamingMetadataError::UpstreamStatus {
            status: status.as_u16(),
            path: "/System/Info/Public".to_string(),
        });
    }
    let parsed: PublicSystemInfoRaw = serde_json::from_slice(&body).map_err(|e| {
        StreamingMetadataError::InvalidPayload(format!("malformed /System/Info/Public: {e}"))
    })?;
    let actual_id = parsed.id.trim();
    if expected_server_id.trim().is_empty()
        || actual_id.is_empty()
        || !actual_id.eq_ignore_ascii_case(expected_server_id.trim())
    {
        return Err(StreamingMetadataError::ServerIdMismatch {
            expected: expected_server_id.trim().to_string(),
            actual: actual_id.to_string(),
        });
    }
    Ok(expected_server_id.trim().to_string())
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct MediaFoldersResponseRaw {
    #[serde(default)]
    items: Vec<MediaFolderItemRaw>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct MediaFolderItemRaw {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
}

pub async fn fetch_server_media_folders(
    client: &Client,
    clean_url: &str,
    provider: &str,
    server_id: &str,
    api_key: &str,
    now: Instant,
) -> Result<HashMap<String, String>, StreamingMetadataError> {
    if let Some(cached) = METADATA_CACHE
        .lock()
        .unwrap()
        .get_libraries(provider, server_id, now)
    {
        return Ok(cached);
    }
    let url = format!("{clean_url}/Library/MediaFolders");
    let mut map = HashMap::new();
    let (body, status) =
        execute_provider_request(client, reqwest::Method::GET, &url, provider, api_key).await?;
    if status != StatusCode::OK {
        return Err(StreamingMetadataError::UpstreamStatus {
            status: status.as_u16(),
            path: "/Library/MediaFolders".to_string(),
        });
    }
    let parsed = serde_json::from_slice::<MediaFoldersResponseRaw>(&body).map_err(|_| {
        StreamingMetadataError::InvalidPayload("malformed media folders".to_string())
    })?;
    for item in parsed.items {
        let id = item.id.trim().to_string();
        let name = if item.name.trim().is_empty() {
            id.clone()
        } else {
            item.name.trim().to_string()
        };
        if !id.is_empty() {
            map.insert(id, name);
        }
    }
    METADATA_CACHE.lock().unwrap().put_libraries(
        provider,
        server_id,
        map.clone(),
        METADATA_CACHE_SUCCESS_TTL,
        now,
    );
    Ok(map)
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct ItemResponseRaw {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    genres: Vec<String>,
    #[serde(default)]
    genre_items: Vec<NameIdPairRaw>,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct NameIdPairRaw {
    #[serde(default)]
    name: String,
}

#[derive(Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
struct AncestorItemRaw {
    #[serde(default)]
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    r#type: String,
}

pub async fn fetch_single_item_metadata(
    client: &Client,
    clean_url: &str,
    provider: &str,
    server_id: &str,
    api_key: &str,
    item_id: &str,
    known_libraries: &HashMap<String, String>,
    now: Instant,
) -> Result<ProviderItemMetadata, StreamingMetadataError> {
    if let Some(cached) = METADATA_CACHE
        .lock()
        .unwrap()
        .get(provider, server_id, item_id, now)
    {
        match cached {
            CacheValue::Success(meta) => return Ok(meta),
            CacheValue::Error(error) => return Err(error),
        }
    }

    let encoded_item_id = urlencoding::encode(item_id.trim());
    let item_url = format!("{clean_url}/Items/{encoded_item_id}");
    let (item_body, item_status) =
        match execute_provider_request(client, reqwest::Method::GET, &item_url, provider, api_key)
            .await
        {
            Ok(res) => res,
            Err(err) => {
                METADATA_CACHE.lock().unwrap().put(
                    provider,
                    server_id,
                    item_id,
                    CacheValue::Error(err.clone()),
                    METADATA_CACHE_ERROR_TTL,
                    now,
                );
                return Err(err);
            }
        };

    if item_status != StatusCode::OK {
        METADATA_CACHE.lock().unwrap().put(
            provider,
            server_id,
            item_id,
            CacheValue::Error(StreamingMetadataError::UpstreamStatus {
                status: item_status.as_u16(),
                path: format!("/Items/{encoded_item_id}"),
            }),
            METADATA_CACHE_ERROR_TTL,
            now,
        );
        return Err(StreamingMetadataError::UpstreamStatus {
            status: item_status.as_u16(),
            path: format!("/Items/{encoded_item_id}"),
        });
    }

    let raw_item: ItemResponseRaw = serde_json::from_slice(&item_body).map_err(|e| {
        StreamingMetadataError::InvalidPayload(format!("malformed item response: {e}"))
    })?;
    if !raw_item.id.trim().eq_ignore_ascii_case(item_id.trim()) {
        return Err(StreamingMetadataError::InvalidPayload(
            "item identity mismatch".to_string(),
        ));
    }

    let mut genres = Vec::new();
    let mut seen_genres = BTreeSet::new();
    for g in raw_item.genres {
        let trimmed = g.trim();
        if !trimmed.is_empty() && seen_genres.insert(trimmed.to_ascii_lowercase()) {
            genres.push(trimmed.to_string());
        }
    }
    if genres.is_empty() {
        for gi in raw_item.genre_items {
            let trimmed = gi.name.trim();
            if !trimmed.is_empty() && seen_genres.insert(trimmed.to_ascii_lowercase()) {
                genres.push(trimmed.to_string());
            }
        }
    }

    let ancestors_url = format!("{clean_url}/Items/{encoded_item_id}/Ancestors");
    let mut libraries = Vec::new();
    let mut seen_libs = BTreeSet::new();

    let (anc_body, ancestor_status) = execute_provider_request(
        client,
        reqwest::Method::GET,
        &ancestors_url,
        provider,
        api_key,
    )
    .await?;
    if ancestor_status != StatusCode::OK {
        return Err(StreamingMetadataError::UpstreamStatus {
            status: ancestor_status.as_u16(),
            path: format!("/Items/{encoded_item_id}/Ancestors"),
        });
    }
    let ancestors = serde_json::from_slice::<Vec<AncestorItemRaw>>(&anc_body).map_err(|_| {
        StreamingMetadataError::InvalidPayload("malformed item ancestors".to_string())
    })?;
    for anc in ancestors {
        let anc_id = anc.id.trim();
        if anc_id.is_empty() {
            continue;
        }
        let is_known = known_libraries.contains_key(anc_id);
        let is_collection_folder = anc.r#type.eq_ignore_ascii_case("CollectionFolder");

        if (is_known || is_collection_folder) && seen_libs.insert(anc_id.to_string()) {
            let name = if let Some(known_name) = known_libraries.get(anc_id) {
                known_name.clone()
            } else if !anc.name.trim().is_empty() {
                anc.name.trim().to_string()
            } else {
                anc_id.to_string()
            };
            libraries.push(ItemLibraryLabel {
                id: anc_id.to_string(),
                name,
            });
        }
    }

    let item_name = if raw_item.name.trim().is_empty() {
        None
    } else {
        Some(raw_item.name.trim().to_string())
    };

    let meta = ProviderItemMetadata {
        item_id: item_id.trim().to_string(),
        item_name,
        libraries,
        genres,
    };

    METADATA_CACHE.lock().unwrap().put(
        provider,
        server_id,
        item_id,
        CacheValue::Success(meta.clone()),
        METADATA_CACHE_SUCCESS_TTL,
        now,
    );

    Ok(meta)
}

pub async fn fetch_provider_item_metadata(
    client: &Client,
    provider: &str,
    server_url: &str,
    api_key: &str,
    expected_server_id: &str,
    item_ids: &[String],
) -> Result<Vec<ProviderItemMetadata>, StreamingMetadataError> {
    let norm_provider = normalize_metadata_provider(provider)?;
    let clean_url = validate_and_clean_server_url(server_url)?;

    let mut unique_items = Vec::new();
    let mut seen_ids = BTreeSet::new();
    for id in item_ids {
        let trimmed = id.trim();
        if !trimmed.is_empty() && seen_ids.insert(trimmed.to_string()) {
            unique_items.push(trimmed.to_string());
        }
    }

    if unique_items.is_empty() {
        return Ok(Vec::new());
    }

    if unique_items.len() > MAX_ACTIVE_ITEM_IDS_PER_CALL {
        return Err(StreamingMetadataError::TooManyItems {
            count: unique_items.len(),
            max: MAX_ACTIVE_ITEM_IDS_PER_CALL,
        });
    }

    let verified_server_id = verify_remote_server_identity(
        client,
        &clean_url,
        &norm_provider,
        api_key,
        expected_server_id,
    )
    .await?;

    let now = Instant::now();
    let known_libraries = fetch_server_media_folders(
        client,
        &clean_url,
        &norm_provider,
        &verified_server_id,
        api_key,
        now,
    )
    .await?;

    let mut results = Vec::new();
    for id in unique_items {
        if let Ok(meta) = fetch_single_item_metadata(
            client,
            &clean_url,
            &norm_provider,
            &verified_server_id,
            api_key,
            &id,
            &known_libraries,
            now,
        )
        .await
        {
            results.push(meta);
        }
    }

    Ok(results)
}

pub fn apply_provider_item_metadata(
    conn: &Connection,
    provider: &str,
    server_id: &str,
    metadata: &[ProviderItemMetadata],
) -> Result<usize, StreamingMetadataError> {
    apply_scoped_provider_item_metadata(conn, provider, server_id, metadata, false)
}

fn apply_scoped_provider_item_metadata(
    conn: &Connection,
    provider: &str,
    server_id: &str,
    metadata: &[ProviderItemMetadata],
    recent_only: bool,
) -> Result<usize, StreamingMetadataError> {
    let norm_provider = normalize_metadata_provider(provider)?;
    let clean_server_id = server_id.trim();
    let transaction = conn.unchecked_transaction()?;
    let conn = &transaction;

    let configured_server_id: Option<String> = conn
        .query_row(
            "SELECT server_id FROM streaming_servers WHERE provider = ?1",
            params![norm_provider],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| StreamingMetadataError::Database(e.to_string()))?;

    if clean_server_id.is_empty()
        || configured_server_id.as_deref().map(str::trim) != Some(clean_server_id)
    {
        return Err(StreamingMetadataError::ServerIdMismatch {
            expected: configured_server_id.unwrap_or_default(),
            actual: clean_server_id.to_string(),
        });
    }

    let mut rows_updated: usize = 0;

    for item_meta in metadata {
        let clean_item_id = item_meta.item_id.trim();
        if clean_item_id.is_empty() {
            continue;
        }

        if item_meta.libraries.is_empty() && item_meta.genres.is_empty() {
            continue;
        }

        let mut query = "SELECT id FROM streaming_history
                 WHERE provider = ?1
                   AND server_id = ?2
                   AND item_id = ?3
                   AND provenance = 'observed_session'"
            .to_string();
        if recent_only {
            query.push_str(" AND last_seen_at >= datetime('now', '-10 minutes')");
        }
        let mut stmt = conn
            .prepare(&query)
            .map_err(|e| StreamingMetadataError::Database(e.to_string()))?;

        let history_ids: Vec<i64> = stmt
            .query_map(
                params![norm_provider, clean_server_id, clean_item_id],
                |row| row.get(0),
            )
            .map_err(|e| StreamingMetadataError::Database(e.to_string()))?
            .filter_map(|r| r.ok())
            .collect();

        for history_id in history_ids {
            let mut label_stmt = conn
                .prepare(
                    "SELECT kind, value, name FROM streaming_history_labels WHERE history_id = ?1",
                )
                .map_err(|e| StreamingMetadataError::Database(e.to_string()))?;

            let mut existing: HashMap<(String, String), String> = HashMap::new();
            let rows = label_stmt
                .query_map(params![history_id], |row| {
                    Ok((
                        (row.get::<_, String>(0)?, row.get::<_, String>(1)?),
                        row.get::<_, String>(2)?,
                    ))
                })
                .map_err(|e| StreamingMetadataError::Database(e.to_string()))?;

            for r in rows {
                if let Ok((k, v)) = r {
                    existing.insert(k, v);
                }
            }

            let mut history_changed = false;

            for lib in &item_meta.libraries {
                let lib_id = lib.id.trim();
                if lib_id.is_empty() {
                    continue;
                }
                let lib_name = if lib.name.trim().is_empty() {
                    lib_id
                } else {
                    lib.name.trim()
                };
                let key = ("library".to_string(), lib_id.to_string());
                match existing.get(&key) {
                    Some(curr_name) if curr_name == lib_name => {}
                    Some(_) => {
                        conn.execute(
                            "UPDATE streaming_history_labels SET name = ?1 WHERE history_id = ?2 AND kind = 'library' AND value = ?3",
                            params![lib_name, history_id, lib_id],
                        )?;
                        history_changed = true;
                    }
                    None => {
                        conn.execute(
                            "INSERT INTO streaming_history_labels (history_id, kind, value, name) VALUES (?1, 'library', ?2, ?3)",
                            params![history_id, lib_id, lib_name],
                        )?;
                        history_changed = true;
                    }
                }
            }

            for genre in &item_meta.genres {
                let g = genre.trim();
                if g.is_empty() {
                    continue;
                }
                let key = ("genre".to_string(), g.to_string());
                match existing.get(&key) {
                    Some(_) => {}
                    None => {
                        conn.execute(
                            "INSERT INTO streaming_history_labels (history_id, kind, value, name) VALUES (?1, 'genre', ?2, ?2)",
                            params![history_id, g],
                        )?;
                        history_changed = true;
                    }
                }
            }

            if history_changed {
                rows_updated += 1;
            }
        }
    }

    transaction.commit()?;
    Ok(rows_updated)
}

pub async fn refresh_provider_item_metadata(
    provider: &str,
    server_url: &str,
    api_key: &str,
    expected_server_id: &str,
    item_ids: &[String],
) -> Result<usize, StreamingMetadataError> {
    let metadata = tokio::time::timeout(
        Duration::from_secs(30),
        fetch_provider_item_metadata(
            &METADATA_HTTP_CLIENT,
            provider,
            server_url,
            api_key,
            expected_server_id,
            item_ids,
        ),
    )
    .await
    .map_err(|_| {
        StreamingMetadataError::Transport("metadata refresh budget exceeded".to_string())
    })??;

    if metadata.is_empty() {
        return Ok(0);
    }

    let provider = provider.to_string();
    let server_id = expected_server_id.to_string();
    tokio::task::spawn_blocking(move || {
        let conn =
            af_db::get_conn().map_err(|e| StreamingMetadataError::Database(e.to_string()))?;
        apply_scoped_provider_item_metadata(&conn, &provider, &server_id, &metadata, true)
    })
    .await
    .map_err(|_| StreamingMetadataError::Database("metadata worker failed".to_string()))?
}

static JELLYFIN_REFRESH_RUNNING: AtomicBool = AtomicBool::new(false);
static EMBY_REFRESH_RUNNING: AtomicBool = AtomicBool::new(false);

struct RefreshGuard(&'static AtomicBool);

impl Drop for RefreshGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

pub fn schedule_provider_item_metadata(
    provider: &str,
    server_url: &str,
    api_key: &str,
    server_id: &str,
    item_ids: &[String],
) {
    let Ok(provider) = normalize_metadata_provider(provider) else {
        return;
    };
    let item_ids: Vec<String> = item_ids
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(MAX_ACTIVE_ITEM_IDS_PER_CALL)
        .collect();
    let running = match provider.as_str() {
        "jellyfin" => &JELLYFIN_REFRESH_RUNNING,
        "emby" => &EMBY_REFRESH_RUNNING,
        _ => return,
    };
    if item_ids.is_empty()
        || running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return;
    }
    let guard = RefreshGuard(running);
    let server_url = server_url.to_string();
    let api_key = api_key.to_string();
    let server_id = server_id.trim().to_string();
    tokio::spawn(async move {
        let _guard = guard;
        let server_id = if server_id.is_empty() {
            let provider = provider.clone();
            let server_url = server_url.clone();
            match tokio::task::spawn_blocking(move || {
                let connection = af_db::get_conn().ok()?;
                connection.query_row("SELECT server_id FROM streaming_servers WHERE provider=?1 AND RTRIM(url,'/')=RTRIM(?2,'/')", params![provider, server_url], |row| row.get::<_, String>(0)).ok()
            }).await {
                Ok(Some(server_id)) if !server_id.is_empty() => server_id,
                _ => return,
            }
        } else {
            server_id
        };
        if refresh_provider_item_metadata(&provider, &server_url, &api_key, &server_id, &item_ids)
            .await
            .is_err()
        {
            tracing::debug!(provider = %provider, "streaming item metadata refresh unavailable");
        }
    });
}

pub fn clear_metadata_cache_for_test() {
    METADATA_CACHE.lock().unwrap().clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use axum::{Json, Router};
    use rusqlite::Connection;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn extract_raw_strings(mut src: &str) -> Vec<String> {
        let mut out = Vec::new();
        while let Some(pos) = src.find("r#\"") {
            let after_start = &src[pos + 3..];
            let end = after_start
                .find("\"#")
                .expect("unterminated raw string literal in af-db/src/lib.rs");
            out.push(after_start[..end].to_string());
            src = &after_start[end + 2..];
        }
        out
    }

    fn extract_quoted_ddl(block: &str, prefix: &str) -> Vec<String> {
        block
            .lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                let stripped = trimmed.strip_prefix('\"')?;
                let sql = stripped.strip_suffix("\",")?;
                if sql.starts_with(prefix) {
                    Some(sql.to_string())
                } else {
                    None
                }
            })
            .collect()
    }

    fn setup_test_db() -> Connection {
        let conn = Connection::open_in_memory().expect("open local in-memory sqlite connection");
        conn.execute_batch("PRAGMA foreign_keys=ON; PRAGMA temp_store=MEMORY;")
            .expect("pragmas");

        let lib_src = include_str!("../../af-db/src/lib.rs");

        let core_marker = "CREATE TABLE IF NOT EXISTS settings (";
        let core_idx = lib_src
            .find(core_marker)
            .expect("core marker in af-db/lib.rs");
        let raw_start = lib_src[..core_idx].rfind("r#\"").expect("core raw start");
        let raw_body = &lib_src[raw_start + 3..];
        let raw_end = raw_body.find("\"#").expect("core raw end");
        conn.execute_batch(&raw_body[..raw_end])
            .expect("execute core DDL");

        let m19_marker =
            "\"Add streaming_servers, streaming_history, and streaming_bandwidth_samples tables\"";
        let m19_start = lib_src.find(m19_marker).expect("migration 19 marker");
        let m19_tail = &lib_src[m19_start..];
        let m19_end = m19_tail
            .find("streaming::migrate_history")
            .expect("migrate_history marker");
        let m19_block = &m19_tail[..m19_end];

        for ddl in extract_raw_strings(m19_block) {
            conn.execute_batch(&ddl).expect("migration 19 table DDL");
        }
        for idx_sql in extract_quoted_ddl(m19_block, "CREATE INDEX") {
            conn.execute_batch(&idx_sql)
                .expect("migration 19 index DDL");
        }
        conn.execute(
            "INSERT OR IGNORE INTO schema_versions (version, description) VALUES (19, 'v19')",
            [],
        )
        .expect("v19 version row");

        af_db::streaming::migrate_history(&conn, ":memory:").expect("apply migration 20");
        conn.execute("INSERT OR REPLACE INTO streaming_servers(provider,name,url,server_id) VALUES ('jellyfin','Jellyfin','http://127.0.0.1:8096','srv-alpha'),('emby','Emby','http://127.0.0.1:8097','srv-alpha')", []).unwrap();
        conn
    }

    #[test]
    fn test_multiple_libraries_and_genres_persist_correctly() {
        let conn = setup_test_db();
        conn.execute(
            "INSERT INTO streaming_history (session_key, provider, server_id, item_id, item_name, provenance)
             VALUES ('sess-1', 'jellyfin', 'srv-alpha', 'item-matrix', 'The Matrix', 'observed_session')",
            [],
        )
        .unwrap();

        let meta = vec![ProviderItemMetadata {
            item_id: "item-matrix".to_string(),
            item_name: Some("The Matrix".to_string()),
            libraries: vec![
                ItemLibraryLabel {
                    id: "lib-scifi".to_string(),
                    name: "Sci-Fi Collection".to_string(),
                },
                ItemLibraryLabel {
                    id: "lib-vault".to_string(),
                    name: "Archive Vault".to_string(),
                },
            ],
            genres: vec![
                "Action".to_string(),
                "Cyberpunk".to_string(),
                "Sci-Fi".to_string(),
            ],
        }];

        let changed = apply_provider_item_metadata(&conn, "jellyfin", "srv-alpha", &meta).unwrap();
        assert_eq!(changed, 1);

        let history_id: i64 = conn
            .query_row(
                "SELECT id FROM streaming_history WHERE session_key = 'sess-1'",
                [],
                |r| r.get(0),
            )
            .unwrap();

        let labels: Vec<(String, String, String)> = conn
            .prepare("SELECT kind, value, name FROM streaming_history_labels WHERE history_id = ?1 ORDER BY kind, value")
            .unwrap()
            .query_map([history_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .map(|r| r.unwrap())
            .collect();

        assert_eq!(
            labels,
            vec![
                (
                    "genre".to_string(),
                    "Action".to_string(),
                    "Action".to_string()
                ),
                (
                    "genre".to_string(),
                    "Cyberpunk".to_string(),
                    "Cyberpunk".to_string()
                ),
                (
                    "genre".to_string(),
                    "Sci-Fi".to_string(),
                    "Sci-Fi".to_string()
                ),
                (
                    "library".to_string(),
                    "lib-scifi".to_string(),
                    "Sci-Fi Collection".to_string()
                ),
                (
                    "library".to_string(),
                    "lib-vault".to_string(),
                    "Archive Vault".to_string()
                ),
            ]
        );
    }

    #[test]
    fn test_background_labels_only_recent_observations() {
        let conn = setup_test_db();
        conn.execute_batch("INSERT INTO streaming_history(session_key,provider,server_id,item_id,provenance,last_seen_at) VALUES ('old-label','jellyfin','srv-alpha','recent-item','observed_session','2020-01-01 00:00:00'),('recent-label','jellyfin','srv-alpha','recent-item','observed_session',datetime('now'));").unwrap();
        let metadata = vec![ProviderItemMetadata {
            item_id: "recent-item".to_string(),
            item_name: None,
            libraries: vec![],
            genres: vec!["Drama".to_string()],
        }];
        assert_eq!(
            apply_scoped_provider_item_metadata(&conn, "jellyfin", "srv-alpha", &metadata, true)
                .unwrap(),
            1
        );
        let labeled: String = conn.query_row("SELECT h.session_key FROM streaming_history h JOIN streaming_history_labels l ON l.history_id=h.id", [], |row| row.get(0)).unwrap();
        assert_eq!(labeled, "recent-label");
        assert_eq!(
            apply_scoped_provider_item_metadata(&conn, "jellyfin", "srv-alpha", &metadata, true)
                .unwrap(),
            0
        );
        assert_eq!(
            apply_provider_item_metadata(&conn, "jellyfin", "srv-alpha", &metadata).unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn test_transient_folder_and_ancestor_failures_do_not_poison_success_cache() {
        let folder_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let ancestor_calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let folder_counter = folder_calls.clone();
        let ancestor_counter = ancestor_calls.clone();
        let app = Router::new()
            .route("/Library/MediaFolders", get(move || {
                let counter = folder_counter.clone();
                async move {
                    if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                        (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({})))
                    } else {
                        (StatusCode::OK, Json(serde_json::json!({"Items":[{"Id":"root","Name":"Films"}]})))
                    }
                }
            }))
            .route("/Items/retry-item", get(|| async { Json(serde_json::json!({"Id":"retry-item","Genres":["Drama"]})) }))
            .route("/Items/retry-item/Ancestors", get(move || {
                let counter = ancestor_counter.clone();
                async move {
                    if counter.fetch_add(1, Ordering::SeqCst) == 0 {
                        (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({})))
                    } else {
                        (StatusCode::OK, Json(serde_json::json!([{"Id":"root","Name":"Films","Type":"CollectionFolder"}])))
                    }
                }
            }))
            .route("/Items/forbidden", get(|| async { StatusCode::FORBIDDEN }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", listener.local_addr().unwrap());
        let server_id = format!("retry-{}", uuid::Uuid::new_v4());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = Client::new();
        let now = Instant::now();
        assert!(
            fetch_server_media_folders(&client, &base_url, "jellyfin", &server_id, "key", now)
                .await
                .is_err()
        );
        let folders =
            fetch_server_media_folders(&client, &base_url, "jellyfin", &server_id, "key", now)
                .await
                .unwrap();
        assert_eq!(folders.get("root").map(String::as_str), Some("Films"));
        assert!(fetch_single_item_metadata(
            &client,
            &base_url,
            "jellyfin",
            &server_id,
            "key",
            "retry-item",
            &folders,
            now
        )
        .await
        .is_err());
        let metadata = fetch_single_item_metadata(
            &client,
            &base_url,
            "jellyfin",
            &server_id,
            "key",
            "retry-item",
            &folders,
            now,
        )
        .await
        .unwrap();
        assert_eq!(metadata.libraries[0].id, "root");
        for _attempt in 0..2 {
            assert!(matches!(
                fetch_single_item_metadata(
                    &client,
                    &base_url,
                    "jellyfin",
                    &server_id,
                    "key",
                    "forbidden",
                    &folders,
                    now
                )
                .await,
                Err(StreamingMetadataError::UpstreamStatus { status: 403, .. })
            ));
        }
        assert_eq!(folder_calls.load(Ordering::SeqCst), 2);
        assert_eq!(ancestor_calls.load(Ordering::SeqCst), 2);
        task.abort();
    }

    #[test]
    fn test_metadata_transaction_rolls_back_all_labels_and_revision() {
        let conn = setup_test_db();
        conn.execute_batch("INSERT INTO streaming_history(session_key,provider,server_id,item_id,provenance) VALUES ('atomic-meta','jellyfin','srv-alpha','atomic-item','observed_session'); CREATE TRIGGER reject_metadata_genre BEFORE INSERT ON streaming_history_labels WHEN NEW.kind='genre' BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
        let revision: i64 = conn
            .query_row(
                "SELECT revision FROM streaming_history_revision WHERE id=1",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let metadata = ProviderItemMetadata {
            item_id: "atomic-item".to_string(),
            item_name: None,
            libraries: vec![ItemLibraryLabel {
                id: "films".to_string(),
                name: "Films".to_string(),
            }],
            genres: vec!["Drama".to_string()],
        };
        assert!(apply_provider_item_metadata(&conn, "jellyfin", "srv-alpha", &[metadata]).is_err());
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM streaming_history_labels", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
        assert_eq!(
            conn.query_row(
                "SELECT revision FROM streaming_history_revision WHERE id=1",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            revision
        );
        assert!(apply_provider_item_metadata(&conn, "jellyfin", "", &[]).is_err());
        conn.execute(
            "DELETE FROM streaming_servers WHERE provider='jellyfin'",
            [],
        )
        .unwrap();
        assert!(apply_provider_item_metadata(&conn, "jellyfin", "srv-alpha", &[]).is_err());
    }

    #[tokio::test]
    async fn test_metadata_requires_remote_identity_and_ignores_virtual_libraries() {
        let app = Router::new()
            .route("/System/Info/Public", get(|| async { Json(serde_json::json!({})) }))
            .route("/Items/wrong", get(|| async { Json(serde_json::json!({"Id":"different","Genres":["Drama"]})) }))
            .route("/Items/right", get(|| async { Json(serde_json::json!({"Id":"right","Genres":["Drama"]})) }))
            .route("/Items/right/Ancestors", get(|| async { Json(serde_json::json!([
                {"Id":"aggregate","Name":"All media","Type":"AggregateFolder","CollectionType":"movies"},
                {"Id":"view","Name":"Virtual view","Type":"UserView"},
                {"Id":"root","Name":"Films","Type":"CollectionFolder"}
            ])) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let base_url = format!("http://{address}");
        let client = Client::new();
        assert!(verify_remote_server_identity(
            &client,
            &base_url,
            "jellyfin",
            "key",
            "proof-server"
        )
        .await
        .is_err());
        assert!(fetch_single_item_metadata(
            &client,
            &base_url,
            "jellyfin",
            "proof-server",
            "key",
            "wrong",
            &HashMap::new(),
            Instant::now()
        )
        .await
        .is_err());
        let metadata = fetch_single_item_metadata(
            &client,
            &base_url,
            "jellyfin",
            "proof-server",
            "key",
            "right",
            &HashMap::new(),
            Instant::now(),
        )
        .await
        .unwrap();
        assert_eq!(
            metadata.libraries,
            vec![ItemLibraryLabel {
                id: "root".to_string(),
                name: "Films".to_string()
            }]
        );
        assert_eq!(
            validate_and_clean_server_url("http://[::1]:8096/").unwrap(),
            "http://[::1]:8096"
        );
        assert_eq!(sanitize_header_token("abc\"\\\r\ndef"), "abcdef");
        task.abort();
    }

    #[tokio::test]
    async fn test_background_refresh_guard_is_singleton_and_released_on_cancellation() {
        static TEST_RUNNING: AtomicBool = AtomicBool::new(true);
        drop(RefreshGuard(&TEST_RUNNING));
        assert!(!TEST_RUNNING.load(Ordering::Acquire));
        let provider = "jellyfin";
        let item_ids = vec!["bounded-item".to_string()];
        schedule_provider_item_metadata(
            provider,
            "http://127.0.0.1:1",
            "key",
            "guard-server",
            &item_ids,
        );
        assert!(JELLYFIN_REFRESH_RUNNING.load(Ordering::Acquire));
        schedule_provider_item_metadata(
            provider,
            "http://127.0.0.1:1",
            "key",
            "guard-server",
            &item_ids,
        );
        tokio::task::yield_now().await;
    }

    #[test]
    fn test_identity_isolation_only_touches_matching_observed_sessions() {
        let conn = setup_test_db();
        conn.execute(
            "INSERT INTO streaming_history (session_key, provider, server_id, item_id, provenance)
             VALUES ('obs-alpha', 'jellyfin', 'srv-alpha', 'item-target', 'observed_session')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO streaming_history (session_key, provider, server_id, item_id, provenance)
             VALUES ('obs-beta', 'jellyfin', 'srv-beta', 'item-target', 'observed_session')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO streaming_history (session_key, provider, server_id, item_id, provenance)
             VALUES ('obs-emby', 'emby', 'srv-alpha', 'item-target', 'observed_session')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO streaming_history (session_key, provider, server_id, item_id, provenance)
             VALUES ('imp-alpha', 'jellyfin', 'srv-alpha', 'item-target', 'imported_event')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO streaming_history (session_key, provider, server_id, item_id, provenance)
             VALUES ('leg-alpha', 'jellyfin', 'srv-alpha', 'item-target', 'legacy_unverified')",
            [],
        )
        .unwrap();

        let meta = vec![ProviderItemMetadata {
            item_id: "item-target".to_string(),
            item_name: Some("Isolated Target".to_string()),
            libraries: vec![ItemLibraryLabel {
                id: "lib-1".to_string(),
                name: "Main Movies".to_string(),
            }],
            genres: vec!["Drama".to_string()],
        }];

        let changed = apply_provider_item_metadata(&conn, "jellyfin", "srv-alpha", &meta).unwrap();
        assert_eq!(changed, 1);

        let obs_alpha_id: i64 = conn
            .query_row(
                "SELECT id FROM streaming_history WHERE session_key = 'obs-alpha'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let obs_beta_id: i64 = conn
            .query_row(
                "SELECT id FROM streaming_history WHERE session_key = 'obs-beta'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let obs_emby_id: i64 = conn
            .query_row(
                "SELECT id FROM streaming_history WHERE session_key = 'obs-emby'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let imp_id: i64 = conn
            .query_row(
                "SELECT id FROM streaming_history WHERE session_key = 'imp-alpha'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        let leg_id: i64 = conn
            .query_row(
                "SELECT id FROM streaming_history WHERE session_key = 'leg-alpha'",
                [],
                |r| r.get(0),
            )
            .unwrap();

        let alpha_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM streaming_history_labels WHERE history_id = ?1",
                [obs_alpha_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(alpha_count, 2);

        for other_id in [obs_beta_id, obs_emby_id, imp_id, leg_id] {
            let cnt: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM streaming_history_labels WHERE history_id = ?1",
                    [other_id],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                cnt, 0,
                "history_id {other_id} should not have received labels"
            );
        }
    }

    #[test]
    fn test_failed_or_missing_metadata_preserves_existing_labels_no_deletion() {
        let conn = setup_test_db();
        conn.execute(
            "INSERT INTO streaming_history (session_key, provider, server_id, item_id, provenance)
             VALUES ('sess-preserve', 'jellyfin', 'srv-alpha', 'item-404', 'observed_session')",
            [],
        )
        .unwrap();

        let history_id: i64 = conn
            .query_row(
                "SELECT id FROM streaming_history WHERE session_key = 'sess-preserve'",
                [],
                |r| r.get(0),
            )
            .unwrap();

        conn.execute(
            "INSERT INTO streaming_history_labels (history_id, kind, value, name)
             VALUES (?1, 'library', 'lib-orig', 'Original Library')",
            [history_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO streaming_history_labels (history_id, kind, value, name)
             VALUES (?1, 'genre', 'Thriller', 'Thriller')",
            [history_id],
        )
        .unwrap();

        let empty_meta = vec![ProviderItemMetadata {
            item_id: "item-404".to_string(),
            item_name: None,
            libraries: vec![],
            genres: vec![],
        }];

        let changed =
            apply_provider_item_metadata(&conn, "jellyfin", "srv-alpha", &empty_meta).unwrap();
        assert_eq!(changed, 0);

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM streaming_history_labels WHERE history_id = ?1",
                [history_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn test_unchanged_labels_avoid_revision_churn() {
        let conn = setup_test_db();
        conn.execute(
            "INSERT INTO streaming_history (session_key, provider, server_id, item_id, provenance)
             VALUES ('sess-rev', 'jellyfin', 'srv-alpha', 'item-steady', 'observed_session')",
            [],
        )
        .unwrap();

        let meta = vec![ProviderItemMetadata {
            item_id: "item-steady".to_string(),
            item_name: Some("Steady Item".to_string()),
            libraries: vec![ItemLibraryLabel {
                id: "lib-steady".to_string(),
                name: "Steady Lib".to_string(),
            }],
            genres: vec!["Comedy".to_string()],
        }];

        let first_apply =
            apply_provider_item_metadata(&conn, "jellyfin", "srv-alpha", &meta).unwrap();
        assert_eq!(first_apply, 1);

        let rev_after_first: i64 = conn
            .query_row(
                "SELECT revision FROM streaming_history_revision WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(rev_after_first > 0);

        let second_apply =
            apply_provider_item_metadata(&conn, "jellyfin", "srv-alpha", &meta).unwrap();
        assert_eq!(second_apply, 0);

        let rev_after_second: i64 = conn
            .query_row(
                "SELECT revision FROM streaming_history_revision WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(rev_after_first, rev_after_second);
    }

    #[test]
    fn test_configured_server_change_rejects_and_prevents_label_attachment() {
        let conn = setup_test_db();
        conn.execute(
            "INSERT OR REPLACE INTO streaming_servers (provider, name, url, server_id)
             VALUES ('jellyfin', 'Jellyfin Alpha', 'http://127.0.0.1:8096', 'srv-active')",
            [],
        )
        .unwrap();

        conn.execute(
            "INSERT INTO streaming_history (session_key, provider, server_id, item_id, provenance)
             VALUES ('sess-old', 'jellyfin', 'srv-old', 'item-any', 'observed_session')",
            [],
        )
        .unwrap();

        let meta = vec![ProviderItemMetadata {
            item_id: "item-any".to_string(),
            item_name: Some("Any Item".to_string()),
            libraries: vec![ItemLibraryLabel {
                id: "lib-any".to_string(),
                name: "Any Lib".to_string(),
            }],
            genres: vec!["Action".to_string()],
        }];

        let err = apply_provider_item_metadata(&conn, "jellyfin", "srv-old", &meta).unwrap_err();
        assert!(matches!(
            err,
            StreamingMetadataError::ServerIdMismatch { .. }
        ));

        let label_count: i64 = conn
            .query_row("SELECT COUNT(*) FROM streaming_history_labels", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(label_count, 0);
    }

    #[test]
    fn test_url_validation_rejects_malformed_credentials_queries_and_fragments() {
        assert!(validate_and_clean_server_url("ftp://example.com").is_err());
        assert!(validate_and_clean_server_url("http://user:pass@127.0.0.1:8096").is_err());
        assert!(validate_and_clean_server_url("http://127.0.0.1:8096?api_key=secret").is_err());
        assert!(validate_and_clean_server_url("http://127.0.0.1:8096#section").is_err());
        assert_eq!(
            validate_and_clean_server_url("http://127.0.0.1:8096/extra/prefix/").unwrap(),
            "http://127.0.0.1:8096/extra/prefix"
        );
        assert!(validate_and_clean_server_url("http://169.254.169.254").is_err());

        let clean = validate_and_clean_server_url("http://127.0.0.1:8096/").unwrap();
        assert_eq!(clean, "http://127.0.0.1:8096");
    }

    #[tokio::test]
    async fn test_mock_http_redirect_rejection() {
        let app = Router::new().route(
            "/System/Info/Public",
            get(|| async {
                (
                    StatusCode::FOUND,
                    [(header::LOCATION, "http://127.0.0.1:9999/evil")],
                    "redirected",
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let err = verify_remote_server_identity(
            &client,
            &format!("http://{addr}"),
            "jellyfin",
            "dummy_key",
            "srv-any",
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            StreamingMetadataError::RedirectDisallowed(302)
        ));
    }

    #[tokio::test]
    async fn test_mock_http_payload_too_large_rejection() {
        let app = Router::new().route(
            "/System/Info/Public",
            get(|| async {
                let large_blob = vec![b'a'; MAX_METADATA_JSON_PAYLOAD_BYTES + 1024];
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    large_blob,
                )
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let err = verify_remote_server_identity(
            &client,
            &format!("http://{addr}"),
            "jellyfin",
            "dummy_key",
            "srv-any",
        )
        .await
        .unwrap_err();

        assert!(matches!(
            err,
            StreamingMetadataError::PayloadTooLarge { .. }
        ));
    }

    #[tokio::test]
    async fn test_mock_http_server_identity_mismatch() {
        let app = Router::new().route(
            "/System/Info/Public",
            get(|| async {
                Json(serde_json::json!({
                    "Id": "srv-actual-456"
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let err = verify_remote_server_identity(
            &client,
            &format!("http://{addr}"),
            "jellyfin",
            "dummy_key",
            "srv-expected-123",
        )
        .await
        .unwrap_err();

        assert_eq!(
            err,
            StreamingMetadataError::ServerIdMismatch {
                expected: "srv-expected-123".to_string(),
                actual: "srv-actual-456".to_string(),
            }
        );
    }

    #[tokio::test]
    async fn test_mock_http_item_metadata_extraction_and_caching() {
        clear_metadata_cache_for_test();

        struct MockState {
            item_hits: AtomicUsize,
            ancestor_hits: AtomicUsize,
            media_folder_hits: AtomicUsize,
        }

        let state = Arc::new(MockState {
            item_hits: AtomicUsize::new(0),
            ancestor_hits: AtomicUsize::new(0),
            media_folder_hits: AtomicUsize::new(0),
        });

        let st_item = Arc::clone(&state);
        let st_anc = Arc::clone(&state);
        let st_mf = Arc::clone(&state);

        let app = Router::new()
            .route(
                "/System/Info/Public",
                get(|| async {
                    Json(serde_json::json!({
                        "Id": "srv-jf-mock"
                    }))
                }),
            )
            .route(
                "/Library/MediaFolders",
                get(move || {
                    let st = Arc::clone(&st_mf);
                    async move {
                        st.media_folder_hits.fetch_add(1, Ordering::SeqCst);
                        Json(serde_json::json!({
                            "Items": [
                                {
                                    "Id": "lib-film-1",
                                    "Name": "Feature Films",
                                    "CollectionType": "movies"
                                },
                                {
                                    "Id": "lib-anime-2",
                                    "Name": "Anime Series",
                                    "CollectionType": "tvshows"
                                }
                            ]
                        }))
                    }
                }),
            )
            .route(
                "/Items/:item_id",
                get(
                    move |axum::extract::Path(item_id): axum::extract::Path<String>| {
                        let st = Arc::clone(&st_item);
                        async move {
                            st.item_hits.fetch_add(1, Ordering::SeqCst);
                            if item_id == "missing-id" {
                                return (
                                    StatusCode::NOT_FOUND,
                                    Json(serde_json::json!({"error": "not found"})),
                                );
                            }
                            (
                                StatusCode::OK,
                                Json(serde_json::json!({
                                    "Id": item_id,
                                    "Name": "Spirited Away",
                                    "Type": "Movie",
                                    "Genres": ["Animation", "Fantasy", "Adventure"]
                                })),
                            )
                        }
                    },
                ),
            )
            .route(
                "/Items/:item_id/Ancestors",
                get(
                    move |axum::extract::Path(_item_id): axum::extract::Path<String>| {
                        let st = Arc::clone(&st_anc);
                        async move {
                            st.ancestor_hits.fetch_add(1, Ordering::SeqCst);
                            Json(serde_json::json!([
                                {
                                    "Id": "subfolder-studio-ghibli",
                                    "Name": "Studio Ghibli",
                                    "Type": "Folder"
                                },
                                {
                                    "Id": "lib-anime-2",
                                    "Name": "Anime Series",
                                    "Type": "CollectionFolder",
                                    "CollectionType": "tvshows"
                                }
                            ]))
                        }
                    },
                ),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let server_url = format!("http://{addr}");
        let item_ids = vec!["item-spirited-away".to_string(), "missing-id".to_string()];

        let first_fetch = fetch_provider_item_metadata(
            &client,
            "jellyfin",
            &server_url,
            "secret_key",
            "srv-jf-mock",
            &item_ids,
        )
        .await
        .unwrap();

        assert_eq!(first_fetch.len(), 1);
        let meta = &first_fetch[0];
        assert_eq!(meta.item_id, "item-spirited-away");
        assert_eq!(meta.item_name.as_deref(), Some("Spirited Away"));
        assert_eq!(meta.genres, vec!["Animation", "Fantasy", "Adventure"]);
        assert_eq!(
            meta.libraries,
            vec![ItemLibraryLabel {
                id: "lib-anime-2".to_string(),
                name: "Anime Series".to_string(),
            }]
        );

        assert_eq!(state.item_hits.load(Ordering::SeqCst), 2);
        assert_eq!(state.ancestor_hits.load(Ordering::SeqCst), 1);
        assert_eq!(state.media_folder_hits.load(Ordering::SeqCst), 1);

        let second_fetch = fetch_provider_item_metadata(
            &client,
            "jellyfin",
            &server_url,
            "secret_key",
            "srv-jf-mock",
            &item_ids,
        )
        .await
        .unwrap();

        assert_eq!(second_fetch.len(), 1);
        assert_eq!(state.item_hits.load(Ordering::SeqCst), 2);
        assert_eq!(state.ancestor_hits.load(Ordering::SeqCst), 1);
        assert_eq!(state.media_folder_hits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_batch_item_limit_enforced() {
        let client = Client::new();
        let oversized: Vec<String> = (0..MAX_ACTIVE_ITEM_IDS_PER_CALL + 1)
            .map(|i| format!("item-{i}"))
            .collect();

        let err = fetch_provider_item_metadata(
            &client,
            "emby",
            "http://127.0.0.1:8096",
            "key",
            "srv-emby",
            &oversized,
        )
        .await
        .unwrap_err();

        assert_eq!(
            err,
            StreamingMetadataError::TooManyItems {
                count: MAX_ACTIVE_ITEM_IDS_PER_CALL + 1,
                max: MAX_ACTIVE_ITEM_IDS_PER_CALL,
            }
        );
    }
}
