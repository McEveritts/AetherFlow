use super::*;

// ─────────────────────────────────────────────────────────────────────────────
// App Credential & Runtime Metadata Discovery
// ─────────────────────────────────────────────────────────────────────────────

pub use af_models::AppRuntimeMeta;

const APP_META_BUDGET: Duration = Duration::from_millis(1500);
const MAX_APP_META_PROBES: usize = 4;
const MAX_RUNNER_RESPONSE_BYTES: u64 = 64 * 1024;

#[derive(Default)]
struct AppMetaState {
    generation: u64,
    cached: HashMap<String, (AppRuntimeMeta, Instant)>,
    in_flight: BTreeSet<String>,
}

static APP_META_CACHE: Lazy<(Mutex<AppMetaState>, Condvar)> =
    Lazy::new(|| (Mutex::new(AppMetaState::default()), Condvar::new()));

pub fn clear_app_runtime_meta_cache() {
    let mut state = APP_META_CACHE
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    state.generation = state.generation.wrapping_add(1);
    state.cached.clear();
    drop(state);
    crate::service_observations::invalidate();
}

pub(crate) fn app_runtime_meta_epoch() -> u64 {
    APP_META_CACHE
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .generation
}

pub(crate) fn cached_app_runtime_meta(app_name: &str) -> AppRuntimeMeta {
    let state = APP_META_CACHE
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    state
        .cached
        .get(&normalize_app_key_name(app_name))
        .filter(|(_, expires)| Instant::now() < *expires)
        .map(|(meta, _)| meta.clone())
        .unwrap_or_default()
}

struct AppMetaFlight(String);

impl Drop for AppMetaFlight {
    fn drop(&mut self) {
        let mut state = APP_META_CACHE
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.in_flight.remove(&self.0);
        APP_META_CACHE.1.notify_all();
    }
}

pub(crate) fn qbittorrent_web_bind_address() -> Option<String> {
    for config in [
        "/var/lib/qbittorrent/.config/qBittorrent/qBittorrent.conf",
        "/var/lib/qbittorrent/.config/qBittorrent/config/qBittorrent.conf",
        "/var/lib/qbittorrent/qBittorrent.conf",
    ] {
        if let Ok(text) = read_metadata_config(resolve_config_path(config)) {
            if let Some(address) = extract_ini_value(&text, &[r"WebUI\Address"]) {
                return Some(address);
            }
        }
    }
    None
}

pub use af_models::app_metadata::normalize_app_slug as normalize_app_key_name;

#[cfg(unix)]
fn query_runner_app_meta_unix(canonical_app: &str, deadline: Instant) -> Option<AppRuntimeMeta> {
    let response = request_runner_unix_until(
        "/v1/app-meta",
        json!({ "app_name": canonical_app }),
        deadline,
    )?;
    parse_runner_app_meta(&response)
}

#[cfg(unix)]
pub(super) fn request_runner_unix(
    route: &str,
    payload: Value,
    timeout: Duration,
) -> Option<String> {
    request_runner_unix_until(route, payload, Instant::now() + timeout)
}

#[cfg(unix)]
pub(super) fn request_runner_unix_until(
    route: &str,
    payload: Value,
    deadline: Instant,
) -> Option<String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    if ["AETHERFLOW_CONFIG_ROOT", "AETHERFLOW_FS_ROOT"]
        .iter()
        .any(|key| {
            env::var(key)
                .ok()
                .is_some_and(|value| !value.trim().is_empty())
        })
    {
        return None;
    }
    let sock_path = af_runner::runner_socket_path();
    if Instant::now() >= deadline {
        return None;
    }

    let body = serde_json::to_string(&payload).ok()?;
    let req = format!(
        "POST {} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        route,
        body.len(),
        body
    );
    if req.len() > MAX_RUNNER_RESPONSE_BYTES as usize {
        return None;
    }
    let bytes = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .ok()?;
                runtime.block_on(async {
                    tokio::time::timeout_at(deadline.into(), async {
                        let mut stream = tokio::net::UnixStream::connect(&sock_path).await.ok()?;
                        stream.write_all(req.as_bytes()).await.ok()?;
                        let mut bytes = Vec::new();
                        stream
                            .take(MAX_RUNNER_RESPONSE_BYTES + 1)
                            .read_to_end(&mut bytes)
                            .await
                            .ok()?;
                        (bytes.len() <= MAX_RUNNER_RESPONSE_BYTES as usize).then_some(bytes)
                    })
                    .await
                    .ok()
                    .flatten()
                })
            })
            .join()
            .ok()
            .flatten()
    })?;
    let resp = String::from_utf8(bytes).ok()?;
    let (headers, json_body) = resp.split_once("\r\n\r\n")?;
    if !headers.starts_with("HTTP/1.1 200 ") && !headers.starts_with("HTTP/1.0 200 ") {
        return None;
    }
    Some(json_body.to_string())
}

pub(super) fn parse_runner_app_meta(json_body: &str) -> Option<AppRuntimeMeta> {
    let response: Value = serde_json::from_str(json_body).ok()?;
    let success = response.get("ok").or_else(|| response.get("success"));
    if success.and_then(Value::as_bool) != Some(true) {
        return None;
    }
    let mut meta: AppRuntimeMeta = if let Some(data) = response.get("data") {
        serde_json::from_value(data.clone()).ok()?
    } else {
        serde_json::from_str(response.get("output")?.as_str()?).ok()?
    };
    meta.url_base =
        af_models::app_metadata::validate_app_web_path(&meta.url_base).unwrap_or_default();
    Some(meta)
}

/// Discovers runtime API key, configured port, and validated native URL base from an
/// application's native config files.
pub fn get_app_runtime_meta(app_name: &str) -> AppRuntimeMeta {
    get_app_runtime_meta_until(app_name, Instant::now() + APP_META_BUDGET)
}

pub(crate) fn collect_native_url_base_meta(
    app_names: &[String],
) -> HashMap<String, AppRuntimeMeta> {
    let mut targets: Vec<String> = app_names
        .iter()
        .map(|name| normalize_app_key_name(name))
        .filter(|name| af_models::app_metadata::supports_native_url_base(name))
        .collect();
    targets.sort();
    targets.dedup();
    if targets.is_empty() {
        return HashMap::new();
    }
    let deadline = Instant::now() + APP_META_BUDGET;
    if targets.len() == 1 {
        let app = targets.remove(0);
        let meta = get_app_runtime_meta_until(&app, deadline);
        return HashMap::from([(app, meta)]);
    }
    let next = std::sync::atomic::AtomicUsize::new(0);
    let results = Mutex::new(HashMap::with_capacity(targets.len()));
    let workers = MAX_APP_META_PROBES.min(targets.len());
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let idx = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let Some(app) = targets.get(idx) else {
                    break;
                };
                if Instant::now() >= deadline {
                    break;
                }
                let meta = get_app_runtime_meta_until(app, deadline);
                results
                    .lock()
                    .unwrap_or_else(|error| error.into_inner())
                    .insert(app.clone(), meta);
            });
        }
    });
    results
        .into_inner()
        .unwrap_or_else(|error| error.into_inner())
}

pub(crate) fn get_app_runtime_meta_until(app_name: &str, deadline: Instant) -> AppRuntimeMeta {
    let canonical = normalize_app_key_name(app_name);
    if canonical.is_empty() {
        return AppRuntimeMeta::default();
    }

    let deadline = deadline.min(Instant::now() + APP_META_BUDGET);
    let mut state = APP_META_CACHE
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    loop {
        if let Some((meta, expires)) = state.cached.get(&canonical) {
            if Instant::now() < *expires {
                return meta.clone();
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return AppRuntimeMeta::default();
        }
        if !state.in_flight.contains(&canonical) && state.in_flight.len() < MAX_APP_META_PROBES {
            break;
        }
        state = APP_META_CACHE
            .1
            .wait_timeout(state, remaining)
            .unwrap_or_else(|error| error.into_inner())
            .0;
    }
    state.in_flight.insert(canonical.clone());
    let generation = state.generation;
    drop(state);
    let _flight = AppMetaFlight(canonical.clone());

    let mut meta = af_runner::extract_app_runtime_meta_local_until(&canonical, deadline);

    let mut confirmed =
        !meta.api_key.is_empty() || meta.configured_port > 0 || !meta.url_base.is_empty();
    #[cfg(unix)]
    if meta.configured_port <= 0 {
        if let Some(runner_meta) = query_runner_app_meta_unix(&canonical, deadline) {
            if meta.api_key.is_empty() {
                meta.api_key = runner_meta.api_key;
            }
            if meta.url_base.is_empty() {
                meta.url_base = runner_meta.url_base;
            }
            meta.configured_port = runner_meta.configured_port;
            if meta.secondary_port <= 0 {
                meta.secondary_port = runner_meta.secondary_port;
            }
            confirmed = true;
        }
    }

    let mut state = APP_META_CACHE
        .0
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    if state.generation != generation {
        return AppRuntimeMeta::default();
    }
    let ttl = Duration::from_secs(if confirmed { 15 } else { 3 });
    state
        .cached
        .insert(canonical, (meta.clone(), Instant::now() + ttl));
    meta
}
