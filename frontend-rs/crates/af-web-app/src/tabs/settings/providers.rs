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
        let mut payload = json!({
            "provider":provider, "model":value["aiModel"],
            "gemini_api_key":value["geminiApiKey"], "openai_api_key":value["openaiApiKey"],
            "anthropic_api_key":value["anthropicApiKey"]
        });
        match provider.as_str() {
            "ollama" => {
                payload["endpoint"] = value["ollamaEndpoint"].clone();
                payload["model"] = value["localModel"].clone();
            }
            "lm-studio" => {
                payload["endpoint"] = value["lmStudioEndpoint"].clone();
                payload["model"] = value["localModel"].clone();
            }
            "anthropic" => {
                payload["anthropic_endpoint"] = value["anthropicEndpoint"].clone();
            }
            _ => {}
        }
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
}
