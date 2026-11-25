use crate::{charts::use_element_size, ui_t, ui_t_with, SearchInput};
use af_web_core::{
    worker::{SearchItem, WorkerRequest, WorkerResponse},
    worker_pool::WorkerPool,
};
use leptos::prelude::*;
use serde_json::Value;
use std::sync::atomic::{AtomicUsize, Ordering};
use wasm_bindgen::JsCast;
use wasm_bindgen_futures::spawn_local;

static NEXT_GRID: AtomicUsize = AtomicUsize::new(1);

/// Shared worker-backed filtering for tab cards and virtual ledgers. Empty
/// queries are synchronous; responses to obsolete queries cannot replace data.
pub fn use_worker_rows(
    rows: Signal<Vec<Value>>,
    query: Signal<String>,
    fields: Vec<String>,
) -> RwSignal<Vec<Value>> {
    use_worker_rows_with_fields(rows, query, fields.into())
}

fn use_worker_rows_with_fields(
    rows: Signal<Vec<Value>>,
    query: Signal<String>,
    fields: Signal<Vec<String>>,
) -> RwSignal<Vec<Value>> {
    let filtered = RwSignal::new(Vec::new());
    let pool = StoredValue::new_local(WorkerPool::shared());
    let generation = RwSignal::new(0u64);
    Effect::new(move |_| {
        let rows = rows.get();
        let query = query.get();
        let fields = fields.get();
        generation.update(|g| *g += 1);
        let ticket = generation.get_untracked();
        if query.trim().is_empty() {
            filtered.set(rows);
            return;
        }
        let items = rows
            .iter()
            .enumerate()
            .map(|(index, row)| SearchItem {
                id: index.to_string(),
                text: fields
                    .iter()
                    .map(|key| cell_text(row, key))
                    .collect::<Vec<_>>()
                    .join(" "),
            })
            .collect();
        let pool = pool.get_value();
        let limit = rows.len();
        spawn_local(async move {
            if let WorkerResponse::SearchResults { items } = pool
                .execute(WorkerRequest::FuzzySearch {
                    query,
                    items,
                    limit,
                })
                .await
            {
                if generation.try_get_untracked() == Some(ticket) {
                    filtered.set(
                        items
                            .into_iter()
                            .filter_map(|item| {
                                item.id
                                    .parse::<usize>()
                                    .ok()
                                    .and_then(|index| rows.get(index).cloned())
                            })
                            .collect(),
                    );
                }
            }
        });
    });
    filtered
}

#[derive(Clone, Debug)]
pub struct GridColumn {
    pub key: String,
    pub label: String,
    pub numeric: bool,
}
impl GridColumn {
    pub fn new(key: &str, label: &str) -> Self {
        Self {
            key: key.into(),
            label: label.into(),
            numeric: false,
        }
    }
    pub fn numeric(key: &str, label: &str) -> Self {
        Self {
            key: key.into(),
            label: label.into(),
            numeric: true,
        }
    }
}
pub fn cell_text(row: &Value, key: &str) -> String {
    match row.get(key) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => String::new(),
        Some(value) => value.to_string(),
    }
}
/// Reserve enough width per header; the enclosing viewport owns horizontal scroll.
pub fn grid_min_width(columns_len: usize) -> usize {
    columns_len.max(4).saturating_mul(136)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wide_domain_grids_reserve_header_space_and_small_grids_keep_a_floor() {
        assert_eq!(grid_min_width(0), 544);
        assert_eq!(grid_min_width(3), 544);
        for columns in [5, 8, 12] {
            assert!(grid_min_width(columns) >= columns * 136);
            assert!(grid_min_width(columns) > 640);
        }
        assert!(grid_min_width(usize::MAX) >= grid_min_width(16));
    }
    #[test]
    fn cells_preserve_sortable_numbers_and_do_not_show_null_literals() {
        let row = serde_json::json!({"name":"Cluster alpha", "count":12, "empty":null});
        assert_eq!(cell_text(&row, "name"), "Cluster alpha");
        assert_eq!(cell_text(&row, "count"), "12");
        assert_eq!(cell_text(&row, "empty"), "");
        assert_eq!(cell_text(&row, "missing"), "");
        assert!(GridColumn::numeric("count", "Instances").numeric);
    }
}
#[component]
pub fn DataGrid(
    #[prop(into)] columns: Signal<Vec<GridColumn>>,
    #[prop(into)] rows: Signal<Vec<Value>>,
    #[prop(optional)] on_select: Option<Callback<Value>>,
    #[prop(optional, into)] label: Signal<String>,
    #[prop(optional, default = true)] searchable: bool,
) -> impl IntoView {
    let scroll = RwSignal::new(0.0f64);
    let sort = RwSignal::new((String::new(), false));
    let focused = RwSignal::new(0usize);
    let query = RwSignal::new(String::new());
    let grid_id = NEXT_GRID.fetch_add(1, Ordering::Relaxed);
    let filtered = use_worker_rows_with_fields(
        rows,
        query.into(),
        Signal::derive(move || {
            columns.with(|columns| columns.iter().map(|column| column.key.clone()).collect())
        }),
    );
    let viewport = NodeRef::<leptos::html::Div>::new();
    let keyboard_target = NodeRef::<leptos::html::Table>::new();
    let size = use_element_size(viewport, (800.0, 440.0));
    let sorted = Memo::new(move |_| {
        let (key, descending) = sort.get();
        let mut data = filtered.get();
        let numeric = columns.with(|columns| {
            columns
                .iter()
                .find(|column| column.key == key)
                .is_some_and(|column| column.numeric)
        });
        if !key.is_empty() {
            data.sort_by(|a, b| {
                let order = if numeric {
                    a[&key]
                        .as_f64()
                        .unwrap_or_default()
                        .total_cmp(&b[&key].as_f64().unwrap_or_default())
                } else {
                    cell_text(a, &key)
                        .to_lowercase()
                        .cmp(&cell_text(b, &key).to_lowercase())
                };
                if descending {
                    order.reverse()
                } else {
                    order
                }
            });
        }
        data
    });
    Effect::new(move |_| {
        let len = sorted.with(Vec::len);
        if len == 0 {
            focused.set(0);
        } else if focused.get_untracked() >= len {
            focused.set(len - 1);
        }
    });
    let window = Memo::new(move |_| {
        let len = sorted.with(Vec::len);
        let start = ((scroll.get() / 44.0).floor() as usize)
            .saturating_sub(5)
            .min(len);
        let end = (start + (size.get().1 / 44.0).ceil() as usize + 12).min(len);
        (start, end)
    });
    view! {
        <div class="min-w-0 max-w-full space-y-3">
            <Show when=move || searchable>
                <SearchInput value=query placeholder="Grid.filterRows"/>
            </Show>
            <div
                node_ref=viewport
                class="af-grid obs-scroller max-w-full h-[440px] overflow-auto rounded-xl border border-white/10"
                on:scroll=move |_| {
                    if let Some(node) = viewport.get() { scroll.set(node.scroll_top() as f64); }
                }
            >
                <table
                    node_ref=keyboard_target
                    class=move || format!("w-full text-sm border-collapse af-grid-cols-{}", columns.with(Vec::len).min(16))
                    role="grid"
                    aria-label=move || ui_t(&label.get())
                    aria-rowcount=move || sorted.with(Vec::len) + 1
                    aria-activedescendant=move || {
                        let total = sorted.with(Vec::len);
                        let idx = focused.get();
                        let (start, end) = window.get();
                        (total > 0 && idx >= start && idx < end)
                            .then(|| format!("af-grid-{grid_id}-row-{idx}"))
                    }
                    tabindex="0"
                    on:keydown=move |event| {
                        let Some(target) = event.target() else { return; };
                        let Some(table) = keyboard_target.get() else { return; };
                        // Delegation leaves currentTarget on the global listener.
                        if &target != table.unchecked_ref::<web_sys::EventTarget>() { return; }
                        let len = sorted.with(Vec::len);
                        if len == 0 { return; }
                        let current = focused.get_untracked().min(len - 1);
                        let next = match event.key().as_str() {
                            "ArrowDown" => (current + 1).min(len - 1),
                            "ArrowUp" => current.saturating_sub(1),
                            "Home" => 0,
                            "End" => len - 1,
                            "Enter" => {
                                if event.cancelable() { event.prevent_default(); }
                                if let Some(callback) = on_select {
                                    if let Some(row) = sorted.with(|rows| rows.get(current).cloned()) {
                                        callback.run(row);
                                    }
                                }
                                return;
                            }
                            _ => return,
                        };
                        if event.cancelable() { event.prevent_default(); }
                        focused.set(next);
                        if let Some(node) = viewport.get() {
                            let y = next as i32 * 44;
                            if y < node.scroll_top() {
                                node.set_scroll_top(y);
                            } else if y + 88 > node.scroll_top() + node.client_height() {
                                node.set_scroll_top(y + 88 - node.client_height());
                            }
                        }
                    }
                >
                    <thead class="sticky top-0 z-10 bg-[var(--af-bg-chrome)] border-b border-[var(--af-border-hairline)]">
                        <tr role="row">{move || columns.get().into_iter().map(|column| {
                            let key = column.key.clone();
                            let sort_key = column.key.clone();
                            view! {
                                <th
                                    role="columnheader"
                                    scope="col"
                                    class="text-left px-4 py-3 whitespace-nowrap overflow-hidden text-ellipsis"
                                    aria-sort=move || {
                                        let (current, descending) = sort.get();
                                        if current != key { "none" } else if descending { "descending" } else { "ascending" }
                                    }
                                >
                                    <button
                                        class="max-w-full overflow-hidden text-ellipsis flex items-center gap-1"
                                        on:click=move |_| sort.update(|(current, descending)| {
                                            if *current == sort_key { *descending = !*descending; }
                                            else { *current = sort_key.clone(); *descending = false; }
                                        })
                                    >
                                        <span class="truncate">{move || ui_t(&column.label)}</span>
                                        <span class="shrink-0" aria-hidden="true">"↕"</span>
                                    </button>
                                </th>
                            }
                        }).collect_view()}</tr>
                    </thead>
                    <tbody>
                        <tr role="row" aria-hidden="true" data-grid-spacer="true">
                            <td role="gridcell" colspan=move || columns.with(Vec::len) class="p-0 border-0">
                                <svg width="1" height=move || (window.get().0 * 44).to_string() class="block" aria-hidden="true"></svg>
                            </td>
                        </tr>
                        {move || {
                            let (start, end) = window.get();
                            sorted.with(|data| data[start..end].iter().cloned().enumerate().map(|(offset, row)| {
                                let index = start + offset;
                                let selected = row.clone();
                                view! {
                                    <tr
                                        role="row"
                                        id=format!("af-grid-{grid_id}-row-{index}")
                                        aria-rowindex=index + 2
                                        aria-selected=move || (focused.get() == index).to_string()
                                        class="h-11 border-t border-white/5 hover:bg-indigo-500/5 cursor-pointer"
                                        class=("bg-indigo-500/10", move || focused.get() == index)
                                        on:click=move |_| {
                                            focused.set(index);
                                            if let Some(callback) = on_select { callback.run(selected.clone()); }
                                        }
                                    >
                                        {columns.get().into_iter().map(|column| view! {
                                            <td role="gridcell" class="px-4 py-2 max-w-xs truncate" title=cell_text(&row, &column.key)>
                                                {cell_text(&row, &column.key)}
                                            </td>
                                        }).collect_view()}
                                    </tr>
                                }
                            }).collect_view())
                        }}
                        <tr role="row" aria-hidden="true" data-grid-spacer="true">
                            <td role="gridcell" colspan=move || columns.with(Vec::len) class="p-0 border-0">
                                <svg width="1" height=move || (sorted.with(Vec::len).saturating_sub(window.get().1) * 44).to_string() class="block" aria-hidden="true"></svg>
                            </td>
                        </tr>
                    </tbody>
                </table>
                <Show when=move || sorted.with(Vec::is_empty)>
                    <crate::EmptyState title="Grid.noMatchingRows"/>
                </Show>
            </div>
            <p class="text-xs text-slate-400">
                {move || ui_t_with("Grid.footerSummary", &[("count", &sorted.with(Vec::len).to_string())])}
            </p>
        </div>
    }
}
