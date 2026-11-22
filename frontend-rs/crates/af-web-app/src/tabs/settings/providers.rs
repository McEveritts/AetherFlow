use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApiKeyFieldState {
    Unconfigured,
    StoredPreserved,
    ReplacementEntered,
    MarkedForClear,
}

fn is_masked_or_encrypted_key(value: &str) -> bool {
    value.starts_with("****") || value.starts_with("enc:v1:")
}

fn api_key_field_state(baseline: &Value, current: &Value, field: &str) -> ApiKeyFieldState {
    let base = text(baseline, field);
    let curr = text(current, field);
    if base.is_empty() {
        if curr.is_empty() {
            ApiKeyFieldState::Unconfigured
        } else {
            ApiKeyFieldState::ReplacementEntered
        }
    } else if curr.is_empty() {
        ApiKeyFieldState::MarkedForClear
    } else if is_masked_or_encrypted_key(&curr) {
        ApiKeyFieldState::StoredPreserved
    } else {
        ApiKeyFieldState::ReplacementEntered
    }
}

fn model_matches_provider(provider: &str, model: &str) -> bool {
    let lower = model.trim().to_ascii_lowercase();
    match provider {
        "openai" => {
            lower.starts_with("gpt-")
                || lower == "o3"
                || lower.starts_with("o3-")
                || lower == "o4"
                || lower.starts_with("o4-")
        }
        "anthropic" => lower.starts_with("claude-"),
        "gemini" => lower.starts_with("gemini-"),
        _ => false,
    }
}

fn build_test_ai_payload(provider: &str, value: &Value) -> Value {
    let mut payload = json!({
        "provider": provider,
        "gemini_api_key": value["geminiApiKey"],
        "openai_api_key": value["openaiApiKey"],
        "anthropic_api_key": value["anthropicApiKey"],
    });
    match provider {
        "ollama" => {
            payload["endpoint"] = value["ollamaEndpoint"].clone();
            let local_model = text(value, "localModel");
            let local_model = local_model.trim();
            if !local_model.is_empty() {
                payload["model"] = json!(local_model);
            }
        }
        "lm-studio" => {
            payload["endpoint"] = value["lmStudioEndpoint"].clone();
            let local_model = text(value, "localModel");
            let local_model = local_model.trim();
            if !local_model.is_empty() {
                payload["model"] = json!(local_model);
            }
        }
        "anthropic-local" => {
            payload["endpoint"] = value["anthropicEndpoint"].clone();
            payload["anthropic_endpoint"] = value["anthropicEndpoint"].clone();
            let local_model = text(value, "localModel");
            let local_model = local_model.trim();
            if !local_model.is_empty() {
                payload["model"] = json!(local_model);
            }
        }
        "anthropic" => {
            payload["anthropic_endpoint"] = value["anthropicEndpoint"].clone();
            let ai_model = text(value, "aiModel");
            let ai_model = ai_model.trim();
            if model_matches_provider(provider, ai_model) {
                payload["model"] = json!(ai_model);
            }
        }
        _ => {
            let ai_model = text(value, "aiModel");
            let ai_model = ai_model.trim();
            if model_matches_provider(provider, ai_model) {
                payload["model"] = json!(ai_model);
            }
        }
    }
    payload
}

#[component]
pub(super) fn ProviderSettings(
    draft: JsonDraft,
    busy: RwSignal<bool>,
    on_save: Callback<()>,
) -> impl IntoView {
    let context = app();
    let testing = RwSignal::new(false);
    let test_provider = RwSignal::new("gemini".to_string());
    let test = move || {
        if testing.get_untracked() {
            return;
        }
        let value = draft_value(draft);
        let provider = test_provider.get_untracked();
        let payload = build_test_ai_payload(&provider, &value);
        testing.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(testing);
        spawn_local(async move {
            match ApiClient
                .post("/api/v1/admin/settings/test-ai", Some(&payload))
                .await
            {
                Ok(data) => context.toast(
                    tt(
                        context,
                        data["message"].as_str().unwrap_or("Provider connected"),
                    ),
                    false,
                ),
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            if testing.try_get_untracked().is_some() {
                busy_guard.release();
            }
        });
    };
    view! {
        <ObsCard>
            <h2 class="text-lg font-semibold mb-4">
                {move || tt(context, "Settings.flowAIEngine")}
            </h2>
            <div class="grid sm:grid-cols-2 gap-5">
                <label class="block text-sm space-y-2">
                    <span>{move || tt(context, "Settings.defaultModel")}</span>
                    <input class="glass-input w-full px-3 py-2" list="settings-model-presets"
                        prop:value=move || text(&draft_value(draft), "aiModel")
                        on:input=move |e| edit(draft, "aiModel", json!(event_target_value(&e))) />
                </label>
                <datalist id="settings-model-presets">
                    {crate::tabs::ai_chat::MODEL_PRESETS.into_iter().map(|id| view! { <option value=id /> }).collect_view()}
                </datalist>
                <DraftSelect
                    draft
                    field="localProvider"
                    label="Local runtime"
                    options=vec![
                        ("", "Cloud provider"),
                        ("ollama", "Ollama"),
                        ("lm-studio", "LM Studio"),
                        ("anthropic-local", "Claude-compatible local"),
                    ]
                />
                <DraftInput
                    draft
                    field="localModel"
                    label="Local model"
                    placeholder="Installed model identifier"
                />
                <DraftInput draft field="ollamaEndpoint" label="Ollama endpoint" kind="url" />
                <DraftInput draft field="lmStudioEndpoint" label="LM Studio endpoint" kind="url" />
                <DraftInput
                    draft
                    field="anthropicEndpoint"
                    label="Claude / Anthropic endpoint"
                    kind="url"
                />
                {[
                    ("geminiApiKey", "Gemini API key"),
                    ("anthropicApiKey", "Claude API key"),
                    ("openaiApiKey", "OpenAI API key"),
                ]
                    .into_iter()
                    .map(move |(field, label)| {
                        let visible = RwSignal::new(false);
                        let key_state = Signal::derive(move || {
                            draft.with(|d| {
                                api_key_field_state(
                                    d.baseline(),
                                    &d.value().unwrap_or(Value::Null),
                                    field,
                                )
                            })
                        });
                        let has_saved_key = Signal::derive(move || {
                            draft.with(|d| !text(d.baseline(), field).is_empty())
                        });
                        view! {
                            <div class="block text-sm space-y-2">
                                <label class="block space-y-2">
                                    <span>
                                        {move || {
                                            if field == "geminiApiKey" {
                                                tt(context, "Settings.apiKeyTitle")
                                            } else {
                                                tt(context, label)
                                            }
                                        }}
                                    </span>
                                    <input
                                        type=move || if visible.get() { "text" } else { "password" }
                                        autocomplete="new-password"
                                        class="glass-input w-full px-3 py-2"
                                        placeholder=move || {
                                            if field == "geminiApiKey" {
                                                tt(context, "Settings.apiKeyPlaceholder")
                                            } else {
                                                tt(context, "Leave unchanged to keep the stored key")
                                            }
                                        }
                                        prop:value=move || {
                                            let value = text(&draft_value(draft), field);
                                            if is_masked_or_encrypted_key(&value) {
                                                String::new()
                                            } else {
                                                value
                                            }
                                        }
                                        on:input=move |event| edit(
                                            draft,
                                            field,
                                            json!(event_target_value(&event)),
                                        )
                                    />
                                </label>
                                <div class="flex flex-wrap gap-2">
                                    <button
                                        type="button"
                                        aria-pressed=move || visible.get().to_string()
                                        class="glass-button px-2 py-1"
                                        on:click=move |_| visible.update(|v| *v = !*v)
                                    >
                                        {move || tt(context, "Show entered key")}
                                    </button>
                                    <Show when=move || has_saved_key.get()>
                                        {move || {
                                            if key_state.get() == ApiKeyFieldState::MarkedForClear {
                                                view! {
                                                    <button
                                                        type="button"
                                                        class="glass-button px-2 py-1 text-amber-200"
                                                        disabled=move || busy.get()
                                                        on:click=move |_| {
                                                            let saved = draft.with_untracked(|d| {
                                                                text(d.baseline(), field)
                                                            });
                                                            edit(draft, field, json!(saved));
                                                        }
                                                    >
                                                        {move || tt(context, "Keep saved key")}
                                                    </button>
                                                }
                                                .into_any()
                                            } else {
                                                view! {
                                                    <button
                                                        type="button"
                                                        class="glass-button px-2 py-1 text-rose-300"
                                                        disabled=move || busy.get()
                                                        on:click=move |_| edit(draft, field, json!(""))
                                                    >
                                                        {move || tt(context, "Clear saved key")}
                                                    </button>
                                                }
                                                .into_any()
                                            }
                                        }}
                                    </Show>
                                </div>
                                <span
                                    class=move || {
                                        if key_state.get() == ApiKeyFieldState::MarkedForClear {
                                            "block text-xs text-amber-300"
                                        } else {
                                            "block text-xs text-slate-400"
                                        }
                                    }
                                >
                                    {move || match key_state.get() {
                                        ApiKeyFieldState::Unconfigured => tt(context, "No saved key"),
                                        ApiKeyFieldState::MarkedForClear => {
                                            tt(context, "Saved key will be cleared on save")
                                        }
                                        ApiKeyFieldState::StoredPreserved
                                        | ApiKeyFieldState::ReplacementEntered => {
                                            tt(context, "enc:v1: encrypted key configured")
                                        }
                                    }}
                                </span>
                            </div>
                        }
                    })
                    .collect_view()}
            </div>
            <label class="block text-sm space-y-2 mt-5">
                <span>{move || tt(context, "Settings.defaultPrompt")}</span>
                <textarea
                    rows="4"
                    class="glass-input w-full px-3 py-2"
                    prop:value=move || text(&draft_value(draft), "systemPrompt")
                    on:input=move |event| edit(
                        draft,
                        "systemPrompt",
                        json!(event_target_value(&event)),
                    )
                ></textarea>
            </label>
            <p class="text-xs text-slate-400 mt-4">
                {move || tt(
                    context,
                    "Gemini and OpenAI use their provider APIs. Local runtimes and Claude support the endpoints above.",
                )}
            </p>
            <div class="flex flex-wrap gap-3 items-end mt-5">
                <label class="text-sm space-y-2">
                    <span>{move || tt(context, "Test provider")}</span>
                    <select
                        class="glass-input block px-3 py-2"
                        prop:value=move || test_provider.get()
                        on:change=move |e| test_provider.set(event_target_value(&e))
                    >
                        <option value="gemini">{move || tt(context, "Gemini")}</option>
                        <option value="anthropic">{move || tt(context, "Claude")}</option>
                        <option value="openai">{move || tt(context, "OpenAI")}</option>
                        <option value="ollama">{move || tt(context, "Ollama")}</option>
                        <option value="lm-studio">{move || tt(context, "LM Studio")}</option>
                        <option value="anthropic-local">
                            {move || tt(context, "Claude-compatible local")}
                        </option>
                    </select>
                </label>
                <button
                    type="button"
                    class="glass-button px-4 py-2"
                    disabled=move || testing.get()
                    on:click=move |_| test()
                >
                    {move || {
                        if testing.get() {
                            tt(context, "Settings.testing")
                        } else {
                            tt(context, "Settings.testApi")
                        }
                    }}
                </button>
            </div>
            <DraftButtons
                draft
                busy
                on_save
                label=move || tt(context, "Settings.saveConfig")
                saving_label=move || tt(context, "Settings.saving")
            />
        </ObsCard>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn provider_api_keys_can_be_preserved_replaced_or_explicitly_cleared() {
        let baseline = json!({
            "geminiApiKey": "****1234",
            "openaiApiKey": "****5678",
            "anthropicApiKey": ""
        });
        let mut draft = FormDraft::new(baseline.clone());

        assert_eq!(
            api_key_field_state(draft.baseline(), &draft.value().unwrap(), "geminiApiKey"),
            ApiKeyFieldState::StoredPreserved
        );
        assert_eq!(
            api_key_field_state(draft.baseline(), &draft.value().unwrap(), "openaiApiKey"),
            ApiKeyFieldState::StoredPreserved
        );
        assert_eq!(
            api_key_field_state(draft.baseline(), &draft.value().unwrap(), "anthropicApiKey"),
            ApiKeyFieldState::Unconfigured
        );
        assert!(!draft.is_dirty());

        // Clearing geminiApiKey marks only geminiApiKey dirty with "" while preserving openaiApiKey
        draft.edit("geminiApiKey", json!("")).unwrap();
        assert!(draft.is_dirty());
        let val = draft.value().unwrap();
        assert_eq!(val["geminiApiKey"], "");
        assert_eq!(val["openaiApiKey"], "****5678");
        assert_eq!(
            api_key_field_state(draft.baseline(), &val, "geminiApiKey"),
            ApiKeyFieldState::MarkedForClear
        );
        assert_eq!(
            api_key_field_state(draft.baseline(), &val, "openaiApiKey"),
            ApiKeyFieldState::StoredPreserved
        );
        assert_eq!(
            draft.dirty_fields().collect::<Vec<_>>(),
            vec!["/geminiApiKey"]
        );

        // Reverting back to baseline keeps the stored key untouched and cleans the draft
        let saved_gemini = text(draft.baseline(), "geminiApiKey");
        draft.edit("geminiApiKey", json!(saved_gemini)).unwrap();
        assert!(!draft.is_dirty());
        assert_eq!(
            api_key_field_state(draft.baseline(), &draft.value().unwrap(), "geminiApiKey"),
            ApiKeyFieldState::StoredPreserved
        );

        // Entering a fresh anthropicApiKey transitions to ReplacementEntered
        draft
            .edit("anthropicApiKey", json!("sk-ant-fresh"))
            .unwrap();
        assert_eq!(
            api_key_field_state(draft.baseline(), &draft.value().unwrap(), "anthropicApiKey"),
            ApiKeyFieldState::ReplacementEntered
        );
    }

    #[test]
    fn test_ai_payload_strips_mismatched_cloud_models_and_keeps_matching_ones() {
        let base_settings = |ai_model: &str| {
            json!({
                "aiModel": ai_model,
                "localModel": "qwen2.5-coder:7b",
                "geminiApiKey": "gem-key",
                "openaiApiKey": "oai-key",
                "anthropicApiKey": "ant-key",
                "ollamaEndpoint": "http://127.0.0.1:11434",
                "lmStudioEndpoint": "http://127.0.0.1:1234",
                "anthropicEndpoint": "https://api.anthropic.com",
            })
        };

        for matching_openai in ["gpt-6.1-sol", "gpt-4o", "o3", "o3-mini", "o4", "o4-mini"] {
            let payload = build_test_ai_payload("openai", &base_settings(matching_openai));
            assert_eq!(payload["provider"], "openai");
            assert_eq!(payload["model"], matching_openai);
        }
        for mismatched_openai in [
            "gemini-4-argon",
            "claude-sonnet-5-5",
            "llama3.2:latest",
            "o300",
            "",
        ] {
            let payload = build_test_ai_payload("openai", &base_settings(mismatched_openai));
            assert_eq!(payload["provider"], "openai");
            assert!(
                payload.get("model").is_none(),
                "expected OpenAI test payload to omit mismatched model {mismatched_openai:?}"
            );
        }

        let matching_anthropic =
            build_test_ai_payload("anthropic", &base_settings("claude-sonnet-5-5"));
        assert_eq!(matching_anthropic["model"], "claude-sonnet-5-5");
        assert_eq!(
            matching_anthropic["anthropic_endpoint"],
            "https://api.anthropic.com"
        );
        for mismatched_anthropic in ["gemini-4-argon", "gpt-6.1-sol", "o3", "o4-mini", ""] {
            let payload = build_test_ai_payload("anthropic", &base_settings(mismatched_anthropic));
            assert_eq!(payload["anthropic_endpoint"], "https://api.anthropic.com");
            assert!(
                payload.get("model").is_none(),
                "expected Anthropic test payload to omit mismatched model {mismatched_anthropic:?}"
            );
        }

        let matching_gemini = build_test_ai_payload("gemini", &base_settings("gemini-4-argon"));
        assert_eq!(matching_gemini["model"], "gemini-4-argon");
        for mismatched_gemini in ["gpt-6.1-sol", "o3", "o4-mini", "claude-opus-5-6", ""] {
            let payload = build_test_ai_payload("gemini", &base_settings(mismatched_gemini));
            assert!(
                payload.get("model").is_none(),
                "expected Gemini test payload to omit mismatched model {mismatched_gemini:?}"
            );
        }
    }

    #[test]
    fn test_ai_payload_builds_anthropic_local_and_other_local_runtimes() {
        let settings = json!({
            "aiModel": "gemini-4-argon",
            "localModel": "claude-local-7b",
            "geminiApiKey": "",
            "openaiApiKey": "",
            "anthropicApiKey": "local-token",
            "ollamaEndpoint": "http://127.0.0.1:11434",
            "lmStudioEndpoint": "http://127.0.0.1:1234",
            "anthropicEndpoint": "http://127.0.0.1:8080",
        });

        let anth_local = build_test_ai_payload("anthropic-local", &settings);
        assert_eq!(anth_local["provider"], "anthropic-local");
        assert_eq!(anth_local["model"], "claude-local-7b");
        assert_eq!(anth_local["endpoint"], "http://127.0.0.1:8080");
        assert_eq!(anth_local["anthropic_endpoint"], "http://127.0.0.1:8080");
        assert_eq!(anth_local["anthropic_api_key"], "local-token");

        let mut empty_local_model = settings.clone();
        empty_local_model["localModel"] = json!("   ");
        let anth_local_default = build_test_ai_payload("anthropic-local", &empty_local_model);
        assert_eq!(anth_local_default["endpoint"], "http://127.0.0.1:8080");
        assert!(anth_local_default.get("model").is_none());

        let ollama = build_test_ai_payload("ollama", &settings);
        assert_eq!(ollama["endpoint"], "http://127.0.0.1:11434");
        assert_eq!(ollama["model"], "claude-local-7b");

        let lm_studio = build_test_ai_payload("lm-studio", &settings);
        assert_eq!(lm_studio["endpoint"], "http://127.0.0.1:1234");
        assert_eq!(lm_studio["model"], "claude-local-7b");
    }
}
