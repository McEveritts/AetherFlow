use super::*;
#[derive(Clone, Copy)]
pub(super) struct ToolbarState {
    pub(super) path: RwSignal<String>,
    pub(super) filter: RwSignal<String>,
    pub(super) grid: RwSignal<bool>,
    pub(super) sort: RwSignal<String>,
    pub(super) descending: RwSignal<bool>,
    pub(super) search_query: RwSignal<String>,
    pub(super) search_type: RwSignal<String>,
    pub(super) search_data: RwSignal<Option<Value>>,
    pub(super) search_busy: RwSignal<bool>,
    pub(super) search_error: RwSignal<String>,
    pub(super) search_generation: RwSignal<u64>,
    pub(super) conflict: RwSignal<String>,
    pub(super) selected: RwSignal<BTreeSet<String>>,
    pub(super) actions: Actions,
    pub(super) share_open: RwSignal<bool>,
    pub(super) share_path: RwSignal<String>,
    pub(super) file_input: NodeRef<leptos::html::Input>,
    pub(super) policy: ApiResource,
    pub(super) sorted: Memo<Vec<Value>>,
    pub(super) search: Callback<web_sys::SubmitEvent>,
    pub(super) upload_files: Callback<web_sys::FileList>,
}
#[component]
pub(super) fn WorkspaceToolbar(state: ToolbarState) -> impl IntoView {
    let context = app();
    let ToolbarState {
        path,
        filter,
        grid,
        sort,
        descending,
        search_query,
        search_type,
        search_data,
        search_busy,
        search_error,
        search_generation,
        conflict,
        selected,
        actions,
        share_open,
        share_path,
        file_input,
        policy,
        sorted,
        search,
        upload_files,
    } = state;
    let can = move |permission: &str| {
        crate::tabs::contracts::decode::<crate::tabs::contracts::McBrowserPolicy>(
            &policy.data.get(),
        )
        .permissions
        .get(permission)
        .copied()
        .unwrap_or(false)
    };
    let run_selected = move |kind: &str| {
        actions.show(
            kind,
            selected.with_untracked(|selection| selection.iter().cloned().collect()),
            path.get_untracked(),
        )
    };
    view! {
        <div class="flex flex-wrap gap-3 items-center mb-3">
            <div class="flex-1 min-w-48">
                <SearchInput value=filter placeholder="Instant filter (worker powered)" />
            </div>
            <button
                type="button"
                class="glass-button px-3 py-2"
                aria-pressed=move || (!grid.get()).to_string()
                on:click=move |_| grid.set(false)
            >
                {move || tt(context, "McBrowser.list")}
            </button>
            <button
                type="button"
                class="glass-button px-3 py-2"
                aria-pressed=move || grid.get().to_string()
                on:click=move |_| grid.set(true)
            >
                {move || tt(context, "McBrowser.grid")}
            </button>
            <label class="inline-flex items-center gap-2 text-xs text-slate-400">
                {move || tt(context, "Sort")}
                <select
                    class="glass-input px-3 py-2"
                    prop:value=move || sort.get()
                    on:change=move |event| sort.set(event_target_value(&event))
                >
                    <option value="name">{move || tt(context, "Name")}</option>
                    <option value="size">{move || tt(context, "Size")}</option>
                    <option value="modified">{move || tt(context, "Modified")}</option>
                    <option value="kind">{move || tt(context, "Type")}</option>
                </select>
            </label>
            <button
                type="button"
                class="glass-button px-3 py-2"
                on:click=move |_| descending.update(|value| *value = !*value)
            >
                {move || {
                    if descending.get() {
                        tt(context, "McBrowser.descending")
                    } else {
                        tt(context, "McBrowser.ascending")
                    }
                }}
            </button>
        </div>
        <form class="flex flex-wrap gap-2 mb-3" on:submit=move |event| search.run(event)>
            <div class="w-full basis-full sm:w-auto sm:basis-auto sm:flex-1 min-w-0">
                <SearchInput
                    value=search_query
                    placeholder="FlowAI: find PDFs modified this week…"
                />
            </div>
            <select
                aria-label=move || tt(context, "Search entry type")
                class="glass-input px-3 py-2"
                prop:value=move || search_type.get()
                on:change=move |event| search_type.set(event_target_value(&event))
            >
                <option value="">{move || tt(context, "All types")}</option>
                <option value="file">{move || tt(context, "Files")}</option>
                <option value="directory">{move || tt(context, "Directories")}</option>
            </select>
            <button
                type="submit"
                class="glass-button-primary px-4 py-2"
                disabled=move || {
                    search_busy.get() || search_query.get().trim().is_empty() || !can("read")
                }
            >
                {move || {
                    if search_busy.get() {
                        tt(context, "McBrowser.searching")
                    } else {
                        tt(context, "McBrowser.searchRecursively")
                    }
                }}
            </button>
            <button
                type="button"
                class="glass-button px-3 py-2"
                on:click=move |_| {
                    search_generation.update(|generation| *generation += 1);
                    search_busy.set(false);
                    search_data.set(None);
                    selected.set(BTreeSet::new());
                }
            >
                {move || tt(context, "McBrowser.clearSearch")}
            </button>
        </form>
        <p class="text-xs text-cyan-200 mb-3">
            {move || {
                search_data
                    .get()
                    .and_then(|data| { data["ai_interpretation"].as_str().map(str::to_owned) })
            }}
        </p>
        <Show when=move || { search_data.get().is_some_and(|data| data["truncated"] == true) }>
            <p class="text-xs text-amber-200">
                {move || tt(context, "Search results were truncated. Narrow the query.")}
            </p>
        </Show>
        <p role="alert" class="text-sm text-rose-300">
            {move || tt(context, &search_error.get())}
        </p>
        <div class="flex flex-wrap gap-2 my-4">
            <button
                type="button"
                class="glass-button px-3 py-2"
                disabled=move || !can("create") || actions.busy.get()
                on:click=move |_| actions.show("folder", vec![], path.get_untracked())
            >
                {move || tt(context, "McBrowser.newFolder")}
            </button>
            <button
                type="button"
                class="glass-button px-3 py-2"
                disabled=move || !can("create") || actions.busy.get()
                on:click=move |_| actions.show("file", vec![], path.get_untracked())
            >
                {move || tt(context, "McBrowser.newFile")}
            </button>
            <button
                type="button"
                class="glass-button-primary px-3 py-2"
                disabled=move || !can("create")
                on:click=move |_| {
                    if let Some(input) = file_input.get() {
                        input.click();
                    }
                }
            >
                {move || tt(context, "McBrowser.uploadFiles")}
            </button>
            <input
                node_ref=file_input
                type="file"
                multiple
                class="hidden"
                aria-label=move || tt(context, "Choose files to upload")
                on:change=move |event| {
                    let input = event_target::<web_sys::HtmlInputElement>(&event);
                    if let Some(files) = input.files() {
                        upload_files.run(files);
                    }
                    input.set_value("");
                }
            />
            <label class="text-xs self-center">
                {move || tt(context, "Large upload conflicts")}
                <select
                    class="glass-input px-2 py-1 ml-2"
                    prop:value=move || conflict.get()
                    on:change=move |event| conflict.set(event_target_value(&event))
                >
                    <option value="error">{move || tt(context, "Reject existing")}</option>
                    <option value="skip">{move || tt(context, "Skip existing")}</option>
                    <option value="overwrite">{move || tt(context, "Overwrite")}</option>
                    <option value="resume">{move || tt(context, "Resume existing")}</option>
                </select>
            </label>
        </div>
        <div class="flex flex-wrap gap-2 mb-4 items-center">
            <label class="flex gap-2 text-xs">
                <input
                    type="checkbox"
                    prop:checked=move || {
                        !sorted.get().is_empty()
                            && sorted
                                .with(|rows| {
                                    rows.iter()
                                        .all(|row| {
                                            selected
                                                .with(|selection| selection.contains(&text(row, "path")))
                                        })
                                })
                    }
                    on:change=move |event| {
                        let checked = event_target_checked(&event);
                        selected
                            .update(|selection| {
                                for row in sorted.get_untracked() {
                                    let target = text(&row, "path");
                                    if checked {
                                        selection.insert(target);
                                    } else {
                                        selection.remove(&target);
                                    }
                                }
                            });
                    }
                />
                {move || tt(context, "Select visible")}
            </label>
            <span class="text-xs text-slate-400">
                {move || tt_with(
                    context,
                    "{count} selected",
                    &[("count", &selected.with(BTreeSet::len).to_string())],
                )}
            </span>
            {["rename", "move", "copy", "delete", "archive", "extract", "checksums", "info"]
                .into_iter()
                .map(|kind| {
                    view! {
                        <button
                            type="button"
                            class="glass-button px-3 py-2 capitalize"
                            disabled=move || {
                                let count = selected.with(BTreeSet::len);
                                count == 0 || actions.busy.get()
                                    || (matches!(kind, "rename" | "extract" | "checksums" | "info")
                                        && count != 1)
                                    || !match kind {
                                        "rename" | "move" => can("rename"),
                                        "copy" => can("read") && can("create"),
                                        "delete" => can("delete"),
                                        "archive" => {
                                            can("execute") && can("read") && can("create")
                                                && can("download")
                                        }
                                        "extract" => can("execute") && can("read") && can("create"),
                                        "checksums" => can("execute") && can("read"),
                                        _ => can("read"),
                                    }
                            }
                            on:click=move |_| run_selected(kind)
                        >
                            {move || action_label(context, kind)}
                        </button>
                    }
                })
                .collect_view()}
            <button
                type="button"
                class="glass-button px-3 py-2"
                disabled=move || selected.with(BTreeSet::len) != 1 || !can("share")
                on:click=move |_| {
                    share_path
                        .set(
                            selected
                                .with_untracked(|selection| {
                                    selection.first().cloned().unwrap_or_default()
                                }),
                        );
                    share_open.set(true);
                }
            >
                {move || tt(context, "Share…")}
            </button>
        </div>
    }
}
