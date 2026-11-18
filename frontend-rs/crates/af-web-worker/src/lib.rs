//! Dedicated worker dispatch, shared by the browser entry point and native tests.
use af_web_core::worker::{execute_worker_request, WorkerEnvelope, WorkerRequest, WorkerResponse};

pub fn dispatch(request: WorkerEnvelope<WorkerRequest>) -> WorkerEnvelope<WorkerResponse> {
    WorkerEnvelope {
        id: request.id,
        message: execute_worker_request(request.message),
    }
}

#[cfg(target_arch = "wasm32")]
pub fn start() {
    use wasm_bindgen::{closure::Closure, JsCast, JsValue};
    let global = js_sys::global().unchecked_into::<web_sys::DedicatedWorkerGlobalScope>();
    let scope = global.clone();
    let handler =
        Closure::<dyn FnMut(web_sys::MessageEvent)>::new(move |event: web_sys::MessageEvent| {
            let data = event.data();
            let kind = js_sys::Reflect::get(&data, &"type".into())
                .ok()
                .and_then(|kind| kind.as_string());
            let response = if matches!(
                kind.as_deref(),
                Some("Sha256ChunkTransfer" | "Sha256BatchTransfer")
            ) {
                let Some(id) = js_sys::Reflect::get(&data, &"id".into())
                    .ok()
                    .and_then(|id| id.as_f64())
                    .filter(|id| {
                        id.is_finite()
                            && *id >= 0.0
                            && *id <= 9_007_199_254_740_991.0
                            && id.fract() == 0.0
                    })
                else {
                    return;
                };
                let message = if kind.as_deref() == Some("Sha256BatchTransfer") {
                    match js_sys::Reflect::get(&data, &"buffers".into())
                        .and_then(|value| value.dyn_into::<js_sys::Array>())
                        .and_then(|buffers| {
                            buffers
                                .iter()
                                .map(|buffer| {
                                    buffer
                                        .dyn_into::<js_sys::ArrayBuffer>()
                                        .map(|buffer| js_sys::Uint8Array::new(&buffer))
                                })
                                .collect::<Result<Vec<_>, JsValue>>()
                        }) {
                        Ok(chunks) => {
                            let (hashes, combined) =
                                af_web_core::worker::sha256_array_batch(&chunks);
                            WorkerResponse::HashBatch { hashes, combined }
                        }
                        Err(_) => WorkerResponse::Error {
                            message: "Expected transferred ArrayBuffers".into(),
                        },
                    }
                } else {
                    match js_sys::Reflect::get(&data, &"buffer".into())
                        .and_then(|buffer| buffer.dyn_into::<js_sys::ArrayBuffer>())
                    {
                        Ok(buffer) => WorkerResponse::Hash {
                            hex: af_web_core::worker::sha256_array(&js_sys::Uint8Array::new(
                                &buffer,
                            )),
                        },
                        Err(_) => WorkerResponse::Error {
                            message: "Expected a transferred ArrayBuffer".into(),
                        },
                    }
                };
                WorkerEnvelope {
                    id: id as u64,
                    message,
                }
            } else {
                let Ok(request) =
                    serde_wasm_bindgen::from_value::<WorkerEnvelope<WorkerRequest>>(data)
                else {
                    return;
                };
                dispatch(request)
            };
            if let Ok(value) = serde_wasm_bindgen::to_value(&response) {
                let _ = scope.post_message(&value);
            }
        });
    global.set_onmessage(Some(handler.as_ref().unchecked_ref()));
    handler.forget(); // Worker owns the listener until Worker::terminate.
    let _ = global.post_message(&JsValue::from_str("af-worker-ready"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_web_core::worker::{SearchItem, MAX_EDITOR_BYTES};
    use std::collections::BTreeMap;

    fn run(message: WorkerRequest) -> WorkerResponse {
        let response = dispatch(WorkerEnvelope { id: 73, message });
        assert_eq!(response.id, 73, "dispatch must preserve the routing ID");
        response.message
    }
    #[test]
    fn dispatch_hashes_binary_data_and_known_sha256_vector() {
        assert!(
            matches!(run(WorkerRequest::Sha256Chunk { bytes: b"abc".to_vec() }), WorkerResponse::Hash { hex }
            if hex == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
        assert!(
            matches!(run(WorkerRequest::Sha256Chunk { bytes: vec![0, 255, 128] }), WorkerResponse::Hash { hex }
            if hex == af_web_core::worker::sha256_hex(&[0, 255, 128]))
        );
    }
    #[test]
    fn dispatch_fuzzy_search_ranks_matches_and_obeys_limit() {
        let items = vec![
            SearchItem {
                id: "logs".into(),
                text: "Service Logs".into(),
            },
            SearchItem {
                id: "services".into(),
                text: "Services".into(),
            },
        ];
        assert!(
            matches!(run(WorkerRequest::FuzzySearch { query: "services".into(), items, limit: 1 }),
            WorkerResponse::SearchResults { items } if items.len() == 1 && items[0].id == "services")
        );
    }
    #[test]
    fn dispatch_syntax_highlighting_is_utf8_safe_and_bounded() {
        let code = "let café = \"世界\"; // comment";
        let WorkerResponse::Tokens { spans } = run(WorkerRequest::TokenizeCode {
            code: code.into(),
            language: "rust".into(),
        }) else {
            panic!("expected tokens");
        };
        assert!(spans
            .iter()
            .all(|span| code.get(span.start..span.end).is_some()));
        assert!(spans.iter().any(|span| span.kind == "keyword"));
        assert!(spans.iter().any(|span| span.kind == "comment"));
        assert!(matches!(
            run(WorkerRequest::TokenizeCode {
                code: "x".repeat(MAX_EDITOR_BYTES + 1),
                language: "rust".into()
            }),
            WorkerResponse::Error { .. }
        ));
    }
    #[test]
    fn dispatch_renders_commonmark_mathml_and_removes_images() {
        let WorkerResponse::RenderedMarkdown { html } = run(WorkerRequest::RenderMarkdown {
            source: "# café\n\n$\\frac{1}{2}$\n\n![beacon](https://evil.example/p.png)\n\n<img src=\"/api/action\">".into(),
        }) else {
            panic!("expected rendered markdown");
        };
        assert!(html.contains("<h1>café</h1>"));
        assert!(html.contains("<math"));
        assert!(html.contains("<mfrac>"));
        assert!(!html.contains("<img"));
    }
    #[test]
    fn dispatch_regex_supports_utf8_wildcards_and_negated_classes() {
        for pattern in ["fn .*", "\"[^\"]+\"", "CAFÉ", r"\w+", r"\d+"] {
            let code = "fn café() { \"café\"; 42 }";
            let response = run(WorkerRequest::FindReplace {
                code: code.into(),
                pattern: pattern.into(),
                replacement: None,
                regex: true,
                case_sensitive: false,
            });
            let WorkerResponse::FindResult { ranges, .. } = response else {
                panic!("expected regex matches: {response:?}");
            };
            assert!(!ranges.is_empty(), "{pattern}");
            assert!(ranges
                .iter()
                .all(|&(start, end)| code.get(start..end).is_some()));
        }
    }
    #[test]
    fn dispatch_csv_and_json_exports_keep_content_and_mime() {
        let rows = vec![BTreeMap::from([(
            "name".into(),
            "=danger(\"quoted\")".into(),
        )])];
        assert!(
            matches!(run(WorkerRequest::BuildExportPayload { rows: rows.clone(), format: "csv".into() }),
            WorkerResponse::Export { content, mime, extension } if content.contains("'=danger(\"\"quoted\"\")") && mime.starts_with("text/csv") && extension == "csv")
        );
        assert!(
            matches!(run(WorkerRequest::BuildExportPayload { rows, format: "json".into() }),
            WorkerResponse::Export { content, mime, extension } if content.contains("name") && content.contains("danger") && mime == "application/json" && extension == "json")
        );
        assert!(matches!(
            run(WorkerRequest::BuildExportPayload {
                rows: vec![],
                format: "exe".into()
            }),
            WorkerResponse::Error { .. }
        ));
    }
}
