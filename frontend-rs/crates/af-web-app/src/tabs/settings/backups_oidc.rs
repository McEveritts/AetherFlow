use super::*;

fn backup_authorization_error(
    context: crate::state::AppContext,
    status: u16,
    text: &str,
) -> String {
    if let Ok(body) = serde_json::from_str::<Value>(text) {
        if let Some(message) = [
            body["error"]["message"].as_str(),
            body["message"].as_str(),
            body["error"].as_str(),
        ]
        .into_iter()
        .flatten()
        .find(|message| !message.trim().is_empty())
        {
            return tt(context, message);
        }
    }
    tt_with(
        context,
        "Backup authorization failed (HTTP {status})",
        &[("status", &status.to_string())],
    )
}

#[component]
pub(super) fn BackupsSettings() -> impl IntoView {
    let context = app();
    let backups = use_api("/api/v1/admin/backup/list".to_string());
    let schedule = use_api("/api/v1/admin/ai/backup/optimal-window".to_string());
    let schedule_busy = RwSignal::new(false);
    let timer = StoredValue::new_local(Some(gloo_timers::callback::Interval::new(
        30_000,
        move || {
            if !schedule_busy.get_untracked() && !schedule.loading.get_untracked() {
                schedule.refresh();
            }
        },
    )));
    on_cleanup(move || timer.set_value(None));
    let change_schedule = move |mode: &'static str| {
        if schedule_busy.get_untracked() || !context.is_admin() {
            return;
        }
        let epoch = context.session_epoch.get_untracked();
        schedule_busy.set(true);
        let mut guard = crate::tabs::busy::BusyGuard::new(schedule_busy);
        spawn_local(async move {
            let result = ApiClient
                .post(
                    "/api/v1/admin/ai/backup/schedule",
                    Some(&json!({"mode":mode})),
                )
                .await;
            if schedule_busy.try_get_untracked().is_none()
                || context.session_epoch.try_get_untracked() != Some(epoch)
            {
                return;
            }
            match result {
                Ok(receipt) => {
                    // Keep the reported window until the authoritative refresh completes.
                    schedule.data.update(|current| {
                        if let Some(fields) = receipt.as_object() {
                            for (key, value) in fields {
                                current[key] = value.clone();
                            }
                        }
                    });
                    schedule.refresh();
                    context.toast(tt(context, "Backup schedule updated"), false);
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            guard.release();
        });
    };
    let selected = RwSignal::new(Value::Null);
    let download_open = RwSignal::new(false);
    let password = RwSignal::new(FormDraft::new(json!({"password":""})));
    let busy = RwSignal::new(false);
    let upload = StoredValue::new_local(None::<web_sys::File>);
    let upload_name = RwSignal::new(String::new());
    let upload_open = RwSignal::new(false);
    let progress = RwSignal::new(0u32);
    let create = move || {
        if busy.get_untracked() {
            return;
        }
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            match ApiClient.post("/api/v1/admin/backup/run", None).await {
                Ok(value) => {
                    if busy.try_get_untracked().is_none() {
                        return;
                    }
                    context.toast(
                        tt(
                            context,
                            value["message"].as_str().unwrap_or("Snapshot created"),
                        ),
                        false,
                    );
                    backups.refresh();
                }
                Err(error) => context.toast(tt(context, &error.message), true),
            }
            if busy.try_get_untracked().is_some() {
                busy_guard.release();
            }
        });
    };
    let download = move || {
        if busy.get_untracked() {
            return;
        }
        let value = selected.get_untracked();
        let sent = draft_value(password);
        let filename = text(&value, "filename");
        let path = format!("/api/v1/admin/backup/download/{}", encode(&filename));
        busy.set(true);
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            let result = async {
                let pass = text(&sent, "password");
                let body = serde_json::to_vec(&json!({"password": pass}))
                    .map_err(|error| error.to_string())?;
                let body: wasm_bindgen::JsValue = js_sys::Uint8Array::from(body.as_slice()).into();
                let mut headers = vec![];
                if pass.is_ascii() {
                    headers.push(("X-Reauth-Password", pass.as_str()));
                }
                let response = ApiClient
                    .fetch_raw_body(
                        &path,
                        "POST",
                        Some(&body),
                        Some("application/json"),
                        &headers,
                    )
                    .await
                    .map_err(|e| e.message)?;
                if !response.ok() {
                    let status = response.status();
                    let text = response.text().await.unwrap_or_default();
                    return Err(backup_authorization_error(context, status, &text));
                }
                // The one-use HttpOnly ticket authorizes the native download.
                // Large archives stream in the browser instead of filling Wasm memory.
                drop(response);
                if download_open.try_get_untracked() == Some(true) {
                    click_download(&path, &filename)
                } else {
                    Err("Backup download was closed".to_string())
                }
            }
            .await;
            if busy.try_get_untracked().is_none() {
                return;
            }
            match result {
                Ok(()) => {
                    download_open.set(false);
                    password.update(|d| d.mark_saved(json!({"password":""})));
                    context.toast(tt(context, "Verified archive download started"), false);
                }
                Err(error) => context.toast(tt(context, &error), true),
            }
            busy_guard.release();
        });
    };
    let stage = Callback::new(move |()| {
        if busy.get_untracked() {
            return;
        }
        let Some(file) = upload.get_value() else {
            return;
        };
        busy.set(true);
        progress.set(0);
        let mut busy_guard = crate::tabs::busy::BusyGuard::new(busy);
        spawn_local(async move {
            let result=async {
                let chunk_size=4.0*1024.0*1024.0;
                let chunks=(file.size()/chunk_size).ceil() as u32;
                if chunks==0{return Err("Choose a non-empty SQLite backup".to_string());}
                let upload_id=format!("wasm-{}",crate::tabs::fileshare::upload_id()?);
                for index in 0..chunks {
                    let chunk=file.slice_with_f64_and_f64(index as f64*chunk_size,((index+1)as f64*chunk_size).min(file.size()))
                        .map_err(|_|"Could not read backup chunk".to_string())?;
                    let path=format!("/api/v1/admin/backup/upload/{}?chunk={index}&total={chunks}&upload_id={upload_id}",encode(&file.name()));
                    let response=ApiClient.fetch_raw_body(&path,"POST",Some(chunk.as_ref()),Some("application/octet-stream"),&[]).await.map_err(|e|e.message)?;
                    let status=response.status();
                    let ok=response.ok();
                    let body=response.text().await.map_err(|_|"Could not read staging response")?;
                    let value:Value=serde_json::from_str(&body).map_err(|_|"Invalid staging response")?;
                    if !ok{return Err(value["error"].as_str().or_else(||value["message"].as_str()).map(str::to_string).unwrap_or_else(||tt_with(context, "Backup staging failed (HTTP {status})", &[("status", &(tt(context, &(status).to_string())).to_string())])));}
                    if index+1==chunks && value["complete"]!=true{return Err("Backup verification has not confirmed completion".into());}
                    if progress.try_get_untracked().is_none(){return Ok(());}
                    progress.set((index+1)*100/chunks);
                }
                Ok(())
            }.await;
            if busy.try_get_untracked().is_none() {
                return;
            }
            match result {
                Ok(()) => {
                    upload_open.set(false);
                    upload.set_value(None);
                    upload_name.set(String::new());
                    backups.refresh();
                    context.toast(
                        tt(
                            context,
                            "Backup staged and verified. The live database was not restored.",
                        ),
                        false,
                    );
                }
                Err(error) => context.toast(tt(context, &error), true),
            }
            busy_guard.release();
        });
    });
    Effect::new(move |_| {
        if !download_open.get() {
            password.update(|d| d.mark_saved(json!({"password":""})));
        }
    });
    view! {
        <ObsCard title=Signal::derive(move || tt(context, "Settings.backupsRestore"))>
            <p class="text-sm text-slate-400 mb-4">
                {move || tt(
                    context,
                    "Create a WAL-safe database snapshot with a verified SHA-256 manifest. Uploads stage and validate backups; live restore requires the host recovery workflow.",
                )}
            </p>
            <section class="rounded-xl border border-white/10 p-4 mb-5 space-y-3" aria-label=move || tt(context, "Automatic backup schedule")>
                <h3 class="font-semibold">{move || tt(context, "Automatic backup schedule")}</h3>
                <ResourceFeedback resource=schedule />
                <Show when=move || schedule.data.with(|data| matches!(data["mode"].as_str(), Some("manual" | "smart")))>
                    <p class="text-sm" role="status">
                        {move || if schedule.data.with(|data| data["mode"] == "smart") {
                            tt(context, "Schedule mode: Smart")
                        } else { tt(context, "Schedule mode: Manual") }}
                    </p>
                    {move || {
                        let (window, minutes, confidence, reason, next) = schedule.data.with(|data| {
                        let window = &data["optimal_window"];
                        let hour = window["optimal_hour"].as_i64().or_else(|| window["hour"].as_i64());
                        let timezone = window["timezone"].as_str().unwrap_or("UTC");
                        let day = window["day_of_week"].as_str().unwrap_or("");
                        let reason = window["reasoning"].as_str().or_else(|| window["reason"].as_str()).unwrap_or("").to_string();
                        let minutes = window["duration_mins"].as_u64().filter(|n| *n > 0).map(|n| n.to_string());
                        let confidence = window["confidence"].as_f64().filter(|n| (0.0..=1.0).contains(n)).map(|n| format!("{:.0}", n * 100.0));
                        let next = data["next_backup_at"].as_str().unwrap_or("").to_string();
                        let window_label = hour.map(|hour| format!("{day} {hour:02}:00 {timezone}").trim().to_string());
                            (window_label, minutes, confidence, reason, next)
                        });
                        view! {
                            {window.map(|window| view! { <p class="text-sm text-slate-400">{move || tt_with(context, "Suggested window: {window}", &[("window", &window)])}</p> })}
                            {minutes.map(|minutes| view! { <p class="text-sm text-slate-400">{move || tt_with(context, "Window duration: {minutes} minutes", &[("minutes", &minutes)])}</p> })}
                            {confidence.map(|percent| view! { <p class="text-sm text-slate-400">{move || tt_with(context, "Confidence: {percent}%", &[("percent", &percent)])}</p> })}
                            {(!reason.is_empty()).then(|| view! { <p class="text-sm text-slate-400">{reason}</p> })}
                            {(!next.is_empty()).then(|| view! { <p class="text-sm text-slate-400">{move || tt_with(context, "Next backup: {time}", &[("time", &next)])}</p> })}
                        }
                    }}
                    <button type="button" class="glass-button px-4 py-2" disabled=move || schedule_busy.get() || schedule.loading.get() || schedule.error.with(Option::is_some)
                        on:click=move |_| {
                            let mode = if schedule.data.with_untracked(|data| data["mode"] == "smart") { "manual" } else { "smart" };
                            change_schedule(mode);
                        }>
                        {move || if schedule.data.with(|data| data["mode"] == "smart") { tt(context, "Disable automatic backups") } else { tt(context, "Enable automatic backups") }}
                    </button>
                </Show>
            </section>
            <div class="flex flex-wrap gap-3 mb-5">
                <button
                    type="button"
                    class="glass-button-primary px-4 py-2"
                    disabled=move || busy.get()
                    on:click=move |_| create()
                >
                    {move || tt(context, "Create database snapshot")}
                </button>
                <button
                    type="button"
                    class="glass-button px-4 py-2"
                    on:click=move |_| backups.refresh()
                    aria-label=move || tt(context, "Refresh manifests")
                >
                    {move || tt(context, "Common.refresh")}
                </button>
                <label class="glass-button px-4 py-2 cursor-pointer">
                    {move || tt(context, "Stage backup")}
                    <input
                        type="file"
                        accept=".sqlite"
                        class="block mt-2 max-w-full"
                        disabled=move || busy.get()
                        on:change=move |event| {
                            let input = event_target::<web_sys::HtmlInputElement>(&event);
                            if let Some(file) = input.files().and_then(|files| files.get(0)) {
                                upload_name.set(file.name());
                                upload.set_value(Some(file));
                                upload_open.set(true);
                            }
                            input.set_value("");
                        }
                    />
                </label>
            </div>
            <ResourceFeedback resource=backups />
            <DataGrid
                label="Verified backup manifests"
                columns=vec![
                    GridColumn::new("filename", "Archive"),
                    GridColumn::numeric("size", "Bytes"),
                    GridColumn::new("checksum", "SHA-256"),
                    GridColumn::new("timestamp", "Created"),
                ]
                rows=Signal::derive(move || json_rows(&backups.data.get()))
                on_select=Callback::new(move |row: Value| {
                    selected.set(row);
                    download_open.set(true);
                })
            />
            <p class="text-xs text-slate-400 mt-3">
                {move || tt(context, "Select a manifest to download its verified archive.")}
            </p>
            <Show when=move || { busy.get() && progress.get() > 0 }>
                <progress max="100" value=move || progress.get() class="w-full" />
                <p role="status">{move || tt_with(context, "Staging: {pct}%", &[("pct", &(progress.get()).to_string())])}</p>
            </Show>
        </ObsCard>
        <Modal open=download_open title="Download verified backup">
            <p class="text-sm break-all mb-4">{move || selected.with(|v| text(v, "filename"))}</p>
            <form
                class="space-y-4"
                on:submit=move |event| {
                    event.prevent_default();
                    download();
                }
            >
                <DraftInput
                    draft=password
                    field="password"
                    label="Current password"
                    kind="password"
                    required=true
                />
                <button
                    type="submit"
                    class="glass-button-primary px-4 py-2"
                    disabled=move || busy.get()
                >
                    {move || tt(context, "Download archive")}
                </button>
            </form>
        </Modal>
        <ConfirmDialog
            open=upload_open
            title="Stage and verify this backup?"
            message="Upload the selected backup in chunks and verify its integrity. This stages an archive and does not replace the live database."
            busy
            on_confirm=stage
        />
        <p class="text-xs text-slate-400 break-all">{move || upload_name.get()}</p>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backup_authorization_errors_use_localized_server_messages_and_status_fallbacks() {
        let owner = Owner::new();
        owner.with(|| {
            let context = crate::state::AppContext::new();
            context.locale.set("fr".into());
            for body in [
                json!({"error":{"message":"Re-authentication failed or attempt limit reached"}}),
                json!({"message":"Re-authentication failed or attempt limit reached"}),
                json!({"error":"Re-authentication failed or attempt limit reached"}),
            ] {
                assert_eq!(
                    backup_authorization_error(context, 403, &body.to_string()),
                    "Échec de la réauthentification ou limite de tentatives atteinte"
                );
            }
            assert_eq!(
                backup_authorization_error(
                    context,
                    429,
                    &json!({"error":{"message":"Download authorizations busy; retry shortly"}})
                        .to_string()
                ),
                "Les autorisations de téléchargement sont occupées ; réessayez dans un instant"
            );
            for body in ["<html>busy</html>", "{}", "{\"error\":\"\"}"] {
                let message = backup_authorization_error(context, 503, body);
                assert!(message.contains("503"));
                assert!(!message.contains("Backup authorization failed"));
            }
        });
    }
}
