//! Bounded 5 MiB chunk uploads with explicit publication acknowledgements.
use super::types::*;
use crate::tabs::l10n::{tt, tt_with};
use af_web_core::api::ApiClient;
use leptos::prelude::*;
#[cfg(target_arch = "wasm32")]
use wasm_bindgen::JsCast;
use wasm_bindgen::JsValue;
pub(super) const CHUNK_BYTES: u64 = 5 * 1024 * 1024;
pub(super) const MAX_UPLOAD_BYTES: u64 = 50 * 1024 * 1024;
pub(super) fn chunk_count(size: u64) -> u64 {
    size.div_ceil(CHUNK_BYTES).max(1)
}
// Bind WebCrypto locally so this tab does not need to change the shared
// web-sys feature manifest owned by the parallel builder.
#[cfg(target_arch = "wasm32")]
#[wasm_bindgen::prelude::wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_name = Crypto)]
    type UploadCrypto;
    #[wasm_bindgen(method, catch, js_name = getRandomValues)]
    fn get_random_values_with_u8_array(
        this: &UploadCrypto,
        bytes: &mut [u8],
    ) -> Result<JsValue, JsValue>;
}
#[cfg(target_arch = "wasm32")]
pub(crate) fn upload_id() -> Result<String, String> {
    let mut random = [0u8; 16];
    let window = web_sys::window().ok_or("Browser unavailable")?;
    let crypto = js_sys::Reflect::get(window.as_ref(), &JsValue::from_str("crypto"))
        .map_err(|_| "Secure randomness is unavailable")?
        .dyn_into::<UploadCrypto>()
        .map_err(|_| "Secure randomness is unavailable")?;
    crypto
        .get_random_values_with_u8_array(&mut random)
        .map_err(|_| "Secure randomness is unavailable")?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}
#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn upload_id() -> Result<String, String> {
    Err("Browser uploads require WebAssembly".into())
}
pub(super) fn browser_error(error: JsValue) -> String {
    error
        .as_string()
        .unwrap_or_else(|| "Browser file operation failed".into())
}

pub(super) async fn stream_upload(
    context: crate::state::AppContext,
    file: &web_sys::File,
    path: &str,
    id: &str,
    signal: &web_sys::AbortSignal,
    progress: RwSignal<u32>,
) -> Result<(), String> {
    let epoch = context.session_epoch.get_untracked();
    let server_epoch = context.server_epoch.get_untracked();
    if signal.aborted() {
        return Err("Upload cancelled.".into());
    }
    let size = file.size() as u64;
    let chunks = chunk_count(size);
    let file_name = file.name();
    let encoded_path = af_web_core::api::percent_encode_header_component(path);
    let encoded_name = af_web_core::api::percent_encode_header_component(&file_name);
    let total_chunks = chunks.to_string();
    for index in 0..chunks {
        if signal.aborted()
            || context.session_epoch.try_get_untracked() != Some(epoch)
            || context.server_epoch.try_get_untracked() != Some(server_epoch)
        {
            return Err("Upload cancelled.".into());
        }
        let start = index * CHUNK_BYTES;
        let end = (start + CHUNK_BYTES).min(size);
        let chunk = file
            .slice_with_f64_and_f64(start as f64, end as f64)
            .map_err(browser_error)?;
        let form_data = web_sys::FormData::new().map_err(browser_error)?;
        form_data
            .append_with_blob_and_filename("file", &chunk, &file_name)
            .map_err(browser_error)?;
        let chunk_index = index.to_string();
        let mut headers = vec![
            ("X-Upload-ID", id),
            ("X-Chunk-Index", chunk_index.as_str()),
            ("X-Total-Chunks", total_chunks.as_str()),
            ("X-Target-Path-Encoded", encoded_path.as_str()),
            ("X-File-Name-Encoded", encoded_name.as_str()),
        ];
        if path.is_ascii() {
            headers.push(("X-Target-Path", path));
        }
        if file_name.is_ascii() {
            headers.push(("X-File-Name", file_name.as_str()));
        }
        // Leave Content-Type to the browser so it includes the multipart boundary.
        let response = ApiClient
            .fetch_raw_body_with_signal(
                "/api/v1/admin/fileshare/upload",
                "POST",
                Some(form_data.as_ref()),
                None,
                &headers,
                Some(signal),
            )
            .await
            .map_err(|error| error.message)?;
        if !response.ok() {
            let status = response.status();
            let message = response
                .json()
                .await
                .ok()
                .and_then(|value| js_sys::JSON::stringify(&value).ok())
                .and_then(|value| {
                    serde_json::from_str::<ChunkUploadResponse>(&String::from(value)).ok()
                })
                .and_then(ChunkUploadResponse::failure_message);
            return Err(message.unwrap_or_else(|| {
                tt_with(
                    context,
                    "Chunk upload failed (HTTP {status})",
                    &[("status", &(tt(context, &status.to_string())).to_string())],
                )
            }));
        }
        let acknowledgement = response.json().await.map_err(|error| error.message)?;
        let acknowledgement = js_sys::JSON::stringify(&acknowledgement).map_err(browser_error)?;
        let acknowledgement: ChunkUploadResponse =
            serde_json::from_str(&String::from(acknowledgement))
                .map_err(|_| "Invalid chunk upload response".to_owned())?;
        if acknowledgement.complete != Some(index + 1 == chunks) {
            return Err("Unexpected chunk upload completion state".into());
        }
        if progress.try_get_untracked().is_none() || signal.aborted() {
            return Err("Upload cancelled.".into());
        }
        progress.set(((index + 1) * 100 / chunks) as u32);
    }
    Ok(())
}
