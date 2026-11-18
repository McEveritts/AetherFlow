use super::*;

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
                <DraftInput
                    draft
                    field="aiModel"
                    label=move || tt(context, "Settings.defaultModel")
                    placeholder="Installed model identifier"
                />
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
                        view! {
                            <label class="block text-sm space-y-2">
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
                                    type="password"
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
                                        if value.starts_with("****") || value.starts_with("enc:v1:")
                                        {
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
                                <span class="block text-xs text-slate-400">
                                    {move || {
                                        draft
                                            .with(|d| {
                                                if text(d.baseline(), field).is_empty() {
                                                    tt(context, "No saved key")
                                                } else {
                                                    tt(context, "enc:v1: encrypted key configured")
                                                }
                                            })
                                    }}
                                </span>
                            </label>
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
