use super::*;
use af_web_core::api::active_server;

fn plugin_sandbox_is_local() -> bool {
    active_server().is_none()
}

pub(super) fn message_value(value: JsValue) -> Result<Value, String> {
    js_sys::JSON::stringify(&value)
        .map_err(|_| "Invalid plugin message".into())
        .and_then(|s| serde_json::from_str(&String::from(s)).map_err(|e| e.to_string()))
}
fn proxy_error(plugin_id: &str, request_id: Value, status: u16, error: &str) -> Value {
    json!({"type":"AF_PLUGIN_PROXY_RESPONSE","pluginId":plugin_id,"requestId":request_id,"ok":false,"status":status,"error":error})
}

/// HTML sandboxing gives `sandbox="allow-scripts"` frames an opaque origin,
/// serialized as `"null"`, so postMessage must use `"*"` to address them.
/// Replies go only to this frame's Window. The listener checks both that opaque
/// origin and strict `event.source == iframe.contentWindow` identity before
/// accepting requests, then validates the plugin ID and proxies scoped API calls.
pub(super) fn post_plugin(frame: &web_sys::Window, value: Value) {
    if let Ok(value) = js_sys::JSON::parse(&value.to_string()) {
        let _ = frame.post_message(&value, "*");
    }
}
#[component]
pub(super) fn PluginCatalog(resource: ApiResource) -> impl IntoView {
    let context = app();
    let mounted = RwSignal::new(None::<Value>);
    let sandbox = RwSignal::new(false);
    let busy = RwSignal::new(String::new());
    let iframe = NodeRef::<leptos::html::Iframe>::new();
    let in_flight = Rc::new(Cell::new(0usize));
    let listener = StoredValue::new_local(None::<EventListener>);
    if let Some(window) = web_sys::window() {
        listener.set_value(Some(EventListener::new(&window,"message",move|event|{
            if !plugin_sandbox_is_local() || !sandbox.get_untracked(){return;}
            let Some(event)=event.dyn_ref::<web_sys::MessageEvent>()else{return;};
            let Some(frame)=iframe.get().and_then(|iframe|iframe.content_window())else{return;};
            if event.origin() != "null" || !event.source().is_some_and(|source|js_sys::Object::is(&source,&frame)){return;}
            let data=event.data();
            let Ok(message)=message_value(data.clone())else{return;};
            let Some(plugin)=mounted.get_untracked()else{return;};
            if message["pluginId"]!=plugin["id"]{return;}
            let id=field(&plugin,&["id"]);
            if message["type"]=="AF_PLUGIN_READY"{
                post_plugin(&frame,json!({"type":"AF_PLUGIN_INIT","pluginId":id,"capabilities":plugin["capabilities"],"scopes":plugin["granted_scopes"]}));return;
            }
            if message["type"]!="AF_PLUGIN_PROXY_REQUEST"{return;}
            let request_id=message.get("requestId").cloned().unwrap_or(Value::Null);
            let path=message["path"].as_str().unwrap_or_default().trim_start_matches('/');
            let method=message["method"].as_str().unwrap_or("GET").to_ascii_uppercase();
            if path.contains("..")||path.contains(['\\','%','?','#',':'])||path.chars().any(char::is_control){
                post_plugin(&frame,proxy_error(&id,request_id,400,"Invalid proxy path"));return;
            }
            if !matches!(method.as_str(),"GET"|"POST"|"PUT"|"DELETE"){
                post_plugin(&frame,proxy_error(&id,request_id,405,"Unsupported HTTP method"));return;
            }
            let endpoint=format!("/api/v1/auth/plugins/{}/proxy{}",js_sys::encode_uri_component(&id),if path.is_empty(){String::new()}else{format!("/{path}")});
            let body=if matches!(method.as_str(),"POST"|"PUT") {
                match js_sys::Reflect::get(&data,&JsValue::from_str("body")) {
                    Ok(value) if !value.is_null() && !value.is_undefined() => match message_value(value) {
                        Ok(body) => Some(body),
                        Err(error) => {post_plugin(&frame,proxy_error(&id,request_id,400,&error));return;}
                    },
                    _ => None,
                }
            } else { None };
            let Some(permit)=InFlightRequest::acquire(&in_flight) else {
                post_plugin(&frame,proxy_error(&id,request_id,429,"Too many concurrent plugin requests"));return;
            };
            spawn_local(async move{
                let _permit=permit;
                if !plugin_sandbox_is_local(){return;}
                let reply=match ApiClient.request(&endpoint,&method,body.as_ref()).await{
                    Ok(payload)=>json!({"type":"AF_PLUGIN_PROXY_RESPONSE","pluginId":id,"requestId":request_id,"ok":true,"status":200,"payload":payload}),
                    Err(e)=>proxy_error(&id,request_id,e.status,&e.message),
                };
                if plugin_sandbox_is_local() && mounted.try_with_untracked(|p|p.as_ref().is_some_and(|p|p["id"]==id)).unwrap_or(false)&&sandbox.try_get_untracked()==Some(true){post_plugin(&frame,reply);}
            });
        })));
    }
    on_cleanup(move || listener.set_value(None));
    Effect::new(move |_| {
        if !sandbox.get() {
            mounted.set(None);
        }
    });
    Effect::new(move |_| {
        let data = resource.data.get();
        if let Some(plugin) = mounted.get_untracked() {
            if data["plugins"].as_array().is_some_and(|plugins| {
                !plugins
                    .iter()
                    .any(|p| p["id"] == plugin["id"] && p["enabled"] == true)
            }) {
                sandbox.set(false);
            }
        }
    });
    let toggle = move |plugin: Value| {
        if !context.is_admin() || !busy.get_untracked().is_empty() {
            return;
        }
        let id = field(&plugin, &["id"]);
        let action = if plugin["enabled"] == true {
            "stop"
        } else {
            "start"
        };
        busy.set(id.clone());
        spawn_local(async move {
            let result = ApiClient
                .post(
                    &format!(
                        "/api/v1/admin/plugins/{}/control",
                        js_sys::encode_uri_component(&id)
                    ),
                    Some(&json!({"action":action})),
                )
                .await;
            if busy.is_disposed() {
                return;
            }
            match result {
                Ok(_) => resource.refresh(),
                Err(e) => context.toast(tt(context, &e.message), true),
            }
            busy.set(String::new());
        });
    };
    view! {
        <section
            data-testid="installed-plugins-section"
            class="pt-6 border-t border-white/10 space-y-4"
        >
            <div class="flex flex-wrap gap-3 justify-between items-center">
                <h2 class="text-xl font-semibold">
                    {move || tt(context, "Marketplace.installedPlugins")}
                </h2>
                <button
                    type="button"
                    class="glass-button px-4 py-2 min-h-11"
                    disabled=move || resource.loading.get()
                    on:click=move |_| resource.refresh()
                    aria-label=move || tt(context, "Refresh Plugins")
                >
                    {move || tt(context, "Common.refresh")}
                </button>
            </div>
            <Show when=move || resource.error.get().is_some()>
                <p role="alert" class="text-sm text-amber-300">
                    {move || resource.error.get().map(|e| tt(context, &e.message))}
                </p>
            </Show>
            {move || {
                resource
                    .data
                    .with(|data| data["rejected"].as_array().cloned().unwrap_or_default())
                    .into_iter()
                    .map(|item| {
                        view! {
                            <p role="status" class="text-xs text-amber-300">
                                {move || tt_with(context, "Rejected manifest {id}: {reason}", &[("id", &(field(&item, &["id"])).to_string()), ("reason", &(field(&item, &["error"])).to_string())])}
                            </p>
                        }
                    })
                    .collect_view()
            }}
            <div class="grid md:grid-cols-2 xl:grid-cols-3 gap-4">
                {move || {
                    resource
                        .data
                        .with(|data| {
                            data["plugins"].as_array().cloned().unwrap_or_else(|| json_rows(data))
                        })
                        .into_iter()
                        .map(|plugin| {
                            let id = field(&plugin, &["id"]);
                            let name = field(&plugin, &["name", "id"]);
                            let enabled = plugin["enabled"] == true;
                            let control = plugin.clone();
                            let open_plugin = plugin.clone();
                            let description = field(&plugin, &["description"]);
                            view! {
                                <article
                                    data-testid=format!("plugin-card-{id}")
                                    class="glass-card p-5 min-w-0 space-y-4"
                                >
                                    <div class="flex flex-wrap justify-between gap-3">
                                        <div>
                                            <h3 class="font-semibold">{name}</h3>
                                            <p class="text-xs text-slate-500 mt-1">
                                                {format!("{} · {}", id, field(&plugin, &["version"]))}
                                            </p>
                                        </div>
                                        <Badge
                                            label=if !enabled {
                                                "Stopped"
                                            } else if plugin["healthy"] == true {
                                                "Healthy"
                                            } else {
                                                "Degraded"
                                            }
                                            tone=if !enabled {
                                                "muted"
                                            } else if plugin["healthy"] == true {
                                                "success"
                                            } else {
                                                "warning"
                                            }
                                        />
                                    </div>
                                    <p class="text-sm text-slate-400">
                                        {move || tt(context, &description)}
                                    </p>
                                    <div class="text-xs text-slate-500">
                                        <p>{move || tt(context, "Granted scopes")}</p>
                                        {plugin["granted_scopes"]
                                            .as_array()
                                            .into_iter()
                                            .flatten()
                                            .map(|scope| {
                                                view! {
                                                    <p class="text-indigo-300 mt-1 break-all">
                                                        {format!(
                                                            "{} {}",
                                                            field(scope, &["method"]),
                                                            field(scope, &["route"]),
                                                        )}
                                                    </p>
                                                }
                                            })
                                            .collect_view()}
                                    </div>
                                    <div class="flex flex-wrap gap-2">
                                        <button
                                            type="button"
                                            data-testid=format!("toggle-plugin-{id}")
                                            class="glass-button px-4 py-2 min-h-11"
                                            disabled=move || {
                                                !busy.get().is_empty() || resource.loading.get()
                                                    || !context.is_admin()
                                            }
                                            on:click=move |_| toggle(control.clone())
                                        >
                                            {move || tt(
                                                context,
                                                if enabled { "Stop" } else { "Start" },
                                            )}
                                        </button>
                                        <button
                                            type="button"
                                            data-testid=format!("open-plugin-ui-{id}")
                                            class="glass-button-primary px-4 py-2 min-h-11"
                                            disabled=move || !enabled || !plugin_sandbox_is_local()
                                            on:click=move |_| {
                                                if plugin_sandbox_is_local() {
                                                    mounted.set(Some(open_plugin.clone()));
                                                    sandbox.set(true);
                                                }
                                            }
                                        >
                                            {move || tt(context, "Open UI")}
                                        </button>
                                    </div>
                                </article>
                            }
                        })
                        .collect_view()
                }}
            </div>
            <Show when=move || {
                !resource.loading.get()
                    && resource.data.with(|d| d["plugins"].as_array().is_some_and(Vec::is_empty))
            }>
                <EmptyState
                    title="No installed plugins"
                    description="Validated runtime extensions appear here."
                />
            </Show>
            <Modal open=sandbox title="Plugin Sandbox">
                <button
                    type="button"
                    data-testid="close-plugin-sandbox"
                    class="glass-button px-4 py-2 min-h-11 mb-3"
                    on:click=move |_| sandbox.set(false)
                >
                    {move || tt(context, "Close Sandbox")}
                </button>
                {move || {
                    if !plugin_sandbox_is_local() {
                        return None;
                    }
                    mounted
                        .get()
                        .map(|plugin| {
                            let sandbox_name = field(&plugin, &["name", "id"]);
                            view! {
                                <iframe
                                    node_ref=iframe
                                    data-testid="plugin-sandbox-iframe"
                                    sandbox="allow-scripts"
                                    referrerpolicy="no-referrer"
                                    title=move || tt_with(context, "Plugin Sandbox: {name}", &[("name", &sandbox_name)])
                                    src=format!(
                                        "/api/v1/auth/plugins/{}/ui",
                                        js_sys::encode_uri_component(&field(&plugin, &["id"])),
                                    )
                                    class="w-full h-[65vh] rounded-xl bg-slate-950 border border-white/10"
                                ></iframe>
                            }
                        })
                }}
            </Modal>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_sandbox_is_available_only_on_the_local_server() {
        use af_web_core::api::set_active_server;

        assert!(plugin_sandbox_is_local());
        set_active_server(Some("media-2".into()));
        let available_on_peer = plugin_sandbox_is_local();
        set_active_server(None);
        assert!(!available_on_peer);
        assert!(plugin_sandbox_is_local());
    }

    #[test]
    fn proxy_failures_preserve_request_identity_and_status() {
        for request_id in [Value::Null, json!("request-a"), json!(17)] {
            for status in [400, 405, 429, 503] {
                let reply =
                    proxy_error("inspector", request_id.clone(), status, "Rejected request");
                assert_eq!(
                    reply,
                    json!({
                        "type": "AF_PLUGIN_PROXY_RESPONSE", "pluginId": "inspector",
                        "requestId": request_id, "ok": false, "status": status,
                        "error": "Rejected request"
                    })
                );
            }
        }
    }
}
