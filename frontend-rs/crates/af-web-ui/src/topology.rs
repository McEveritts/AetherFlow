use crate::{ui_t, ui_t_with};
use af_web_core::{
    markdown::render_qr_svg,
    topology::{
        compute_tiered_topology_layout, matches_topology_query, ServiceGroup, TopologyCardNode,
        TopologyEdgeKind, TopologyIconKind, TopologyTier,
    },
};
use gloo_events::{EventListener, EventListenerOptions};
use leptos::prelude::*;
use serde_json::Value;
use std::collections::HashSet;
use wasm_bindgen::JsCast;

#[component]
pub fn QrCodeSvg(
    #[prop(into)] payload: Signal<String>,
    #[prop(optional, into)] label: String,
) -> impl IntoView {
    view! {
        <div
            role="img"
            aria-label=move || ui_t(&label)
            class="af-qr w-48 max-w-full"
            inner_html=move || render_qr_svg(&payload.get())
        ></div>
    }
}

/// Sleek segmented Map | List switcher matching the T3 Environments Map header bar.
/// Uses the `"graph"` / `"list"` tab IDs (`topology-tab-graph` / `topology-tab-list`)
/// so ARIA panel controls and existing selectors stay consistent.
#[component]
pub fn TopologyModeSwitcher(active: RwSignal<String>) -> impl IntoView {
    let tabs: [(&'static str, &'static str); 2] = [("graph", "Map"), ("list", "List")];
    view! {
        <div
            role="tablist"
            aria-label=move || ui_t("Service topology graph")
            class="af-topo-segmented"
            on:keydown=move |event| {
                let target_id = match event.key().as_str() {
                    "ArrowRight" | "ArrowLeft" => {
                        if active.get_untracked() == "graph" {
                            "list"
                        } else {
                            "graph"
                        }
                    }
                    "Home" => "graph",
                    "End" => "list",
                    _ => return,
                };
                event.prevent_default();
                active.set(target_id.to_string());
                let dom_id = format!("topology-tab-{target_id}");
                if let Some(element) = web_sys::window()
                    .and_then(|window| window.document())
                    .and_then(|document| document.get_element_by_id(&dom_id))
                    .and_then(|element| element.dyn_into::<web_sys::HtmlElement>().ok())
                {
                    let _ = element.focus();
                }
            }
        >
            {tabs
                .into_iter()
                .map(|(id, label)| {
                    view! {
                        <button
                            type="button"
                            id=format!("topology-tab-{id}")
                            role="tab"
                            class="af-topo-segmented-tab"
                            class:af-topo-segmented-tab-active=move || active.get() == id
                            aria-selected=move || (active.get() == id).to_string()
                            aria-controls=move || {
                                (active.get() == id).then(|| format!("topology-tabpanel-{id}"))
                            }
                            tabindex=move || if active.get() == id { 0 } else { -1 }
                            on:click=move |_| active.set(id.to_string())
                        >
                            {move || ui_t(label)}
                        </button>
                    }
                })
                .collect_view()}
        </div>
    }
}

#[component]
pub fn AppTopologyMap(
    #[prop(into)] services: Signal<Vec<(String, Value)>>,
    #[prop(into)] links: Signal<Vec<(String, String)>>,
    #[prop(optional)] mode: Option<RwSignal<String>>,
) -> impl IntoView {
    let external_mode = mode.is_some();
    let mode = mode.unwrap_or_else(|| RwSignal::new("graph".to_string()));
    let zoom = RwSignal::new(1.0f64);
    let pan = RwSignal::new((0.0f64, 0.0f64));
    // Tracks (start_x, start_y, last_x, last_y) during pointer drag.
    let drag = RwSignal::new(None::<(f64, f64, f64, f64)>);
    let did_drag = RwSignal::new(false);
    let search = RwSignal::new(String::new());
    let hovered_node = RwSignal::new(None::<String>);
    let help_open = RwSignal::new(false);
    let selected_id = RwSignal::new(None::<String>);
    let inspector = RwSignal::new(false);

    let layout = Memo::new(move |_| compute_tiered_topology_layout(&services.get(), &links.get()));
    let matching_ids = Memo::new(move |_| {
        let query = search.get();
        let trimmed = query.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(layout.with(|layout| {
                layout
                    .nodes
                    .iter()
                    .filter(|node| matches_topology_query(node, trimmed))
                    .map(|node| node.id.clone())
                    .collect::<HashSet<_>>()
            }))
        }
    });

    let svg_ref = NodeRef::<leptos::svg::Svg>::new();
    let wheel_listener = StoredValue::new_local(None::<EventListener>);
    Effect::new(move |_| {
        // Replace the listener if the graph remounts after switching views.
        wheel_listener.set_value(svg_ref.get().map(|svg| {
            EventListener::new_with_options(
                svg.as_ref(),
                "wheel",
                EventListenerOptions::enable_prevent_default(),
                move |event| {
                    if let Some(event) = event.dyn_ref::<web_sys::WheelEvent>() {
                        event.prevent_default();
                        zoom.update(|zoom| {
                            *zoom = (*zoom * if event.delta_y() < 0.0 { 1.1 } else { 0.9 })
                                .clamp(0.4, 3.0);
                        });
                    }
                },
            )
        }));
    });
    on_cleanup(move || wheel_listener.set_value(None));

    let open_inspector = move |id: String| {
        selected_id.set(Some(id));
        inspector.set(true);
    };

    view! {
        <div class="min-w-0 max-w-full">
            <Show when=move || !external_mode>
                <div class="flex flex-wrap items-center justify-between gap-3 mb-3">
                    <TopologyModeSwitcher active=mode />
                </div>
            </Show>

            <div class="af-topology-frame">
                // Top toolbar bar: search filter + status/reset + help toggle
                <div class="af-topology-toolbar">
                    <div class="af-topology-search-wrap">
                        <svg
                            class="pointer-events-none absolute left-2.5 text-[var(--af-topo-subtitle-fg)]"
                            width="15"
                            height="15"
                            viewBox="0 0 24 24"
                            fill="none"
                            stroke="currentColor"
                            stroke-width="1.9"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                            aria-hidden="true"
                        >
                            <circle cx="10.5" cy="10.5" r="6.5" />
                            <path d="m16 16 4.5 4.5" />
                        </svg>
                        <input
                            type="search"
                            class="af-topology-search obs-search-input"
                            aria-label=move || ui_t("Find a service")
                            placeholder=move || ui_t("Find a service")
                            prop:value=move || search.get()
                            on:input=move |event| search.set(event_target_value(&event))
                        />
                        <Show when=move || !search.get().is_empty()>
                            <button
                                type="button"
                                class="af-topology-search-clear obs-inline-action"
                                aria-label=move || ui_t("Clear search")
                                on:click=move |_| search.set(String::new())
                            >
                                "×"
                            </button>
                        </Show>
                    </div>

                    <div class="flex items-center gap-2">
                        <Show when=move || matching_ids.get().is_some()>
                            <button
                                type="button"
                                class="af-btn px-2.5 py-1 text-xs min-h-8"
                                on:click=move |_| search.set(String::new())
                            >
                                {move || ui_t("Show all")}
                            </button>
                        </Show>
                        <button
                            type="button"
                            class="af-topology-help-btn obs-inline-action"
                            aria-label=move || {
                                if help_open.get() {
                                    ui_t("Hide map help")
                                } else {
                                    ui_t("Show map help")
                                }
                            }
                            aria-expanded=move || help_open.get().to_string()
                            on:click=move |_| help_open.update(|open| *open = !*open)
                        >
                            "?"
                        </button>
                    </div>
                </div>

                <crate::TabPanel id=mode id_prefix="topology">
                    <Show
                        when=move || mode.get() == "graph"
                        fallback=move || {
                            view! {
                                <div class="p-4 space-y-5 bg-[var(--af-topo-canvas-bg)] min-h-[340px]">
                                    <Show
                                        when=move || {
                                            let matches = matching_ids.get();
                                            layout.with(|layout| {
                                                layout.nodes.iter().any(|node| {
                                                    matches
                                                        .as_ref()
                                                        .is_none_or(|set| set.contains(&node.id))
                                                })
                                            })
                                        }
                                        fallback=move || {
                                            view! {
                                                <div class="py-12 text-center space-y-3">
                                                    <p class="text-sm text-[var(--af-topo-subtitle-fg)]">
                                                        {move || ui_t("No matching services")}
                                                    </p>
                                                    <Show when=move || !search.get().is_empty()>
                                                        <button
                                                            type="button"
                                                            class="af-btn px-3.5 py-1.5 text-xs min-h-9"
                                                            on:click=move |_| search.set(String::new())
                                                        >
                                                            {move || ui_t("Show all")}
                                                        </button>
                                                    </Show>
                                                </div>
                                            }
                                        }
                                    >
                                        {[
                                            TopologyTier::Gateway,
                                            TopologyTier::Service,
                                            TopologyTier::Dependency,
                                        ]
                                            .into_iter()
                                            .map(|tier| {
                                                view! {
                                                    <Show when=move || {
                                                        let matches = matching_ids.get();
                                                        layout.with(|layout| {
                                                            layout.nodes.iter().any(|node| {
                                                                node.tier == tier
                                                                    && matches
                                                                        .as_ref()
                                                                        .is_none_or(|set| set.contains(&node.id))
                                                            })
                                                        })
                                                    }>
                                                        <section class="space-y-2">
                                                            <h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--af-topo-subtitle-fg)]">
                                                                {move || ui_t(tier.label_key())}
                                                            </h3>
                                                            <div class="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
                                                                {move || {
                                                                    let matches = matching_ids.get();
                                                                    layout
                                                                        .get()
                                                                        .nodes
                                                                        .into_iter()
                                                                        .filter(|node| {
                                                                            node.tier == tier
                                                                                && matches
                                                                                    .as_ref()
                                                                                    .is_none_or(|set| {
                                                                                        set.contains(&node.id)
                                                                                    })
                                                                        })
                                                                        .map(|node| {
                                                                            let id = node.id.clone();
                                                                            let label = node.label.clone();
                                                                            let subtitle = localize_card_subtitle(&node);
                                                                            let link_total =
                                                                                node.incoming_count + node.outgoing_count;
                                                                            let status_color = node_status_color(&node);
                                                                            let icon = node.icon;
                                                                            let group = node.group;
                                                                            view! {
                                                                                <button
                                                                                    type="button"
                                                                                    class="af-topo-list-row"
                                                                                    on:click=move |_| open_inspector(id.clone())
                                                                                >
                                                                                    <div class="flex items-center gap-3 min-w-0">
                                                                                        <div class="relative flex items-center justify-center w-9 h-9 rounded-lg border border-[var(--af-topo-icon-well-border)] bg-[var(--af-topo-icon-well-bg)] shrink-0">
                                                                                            <svg
                                                                                                width="18"
                                                                                                height="18"
                                                                                                viewBox="0 0 18 18"
                                                                                                aria-hidden="true"
                                                                                            >
                                                                                                {render_topology_icon(icon)}
                                                                                            </svg>
                                                                                            <svg
                                                                                                width="10"
                                                                                                height="10"
                                                                                                viewBox="0 0 10 10"
                                                                                                class="absolute -bottom-1 -right-1"
                                                                                                aria-hidden="true"
                                                                                            >
                                                                                                <circle
                                                                                                    cx="5"
                                                                                                    cy="5"
                                                                                                    r="4"
                                                                                                    fill=status_color
                                                                                                    stroke="var(--af-topo-card-bg)"
                                                                                                    stroke-width="1.5"
                                                                                                />
                                                                                            </svg>
                                                                                        </div>
                                                                                        <div class="min-w-0">
                                                                                            <p class="text-sm font-semibold truncate">
                                                                                                {label}
                                                                                            </p>
                                                                                            <p class="text-xs text-[var(--af-topo-subtitle-fg)] truncate">
                                                                                                {subtitle}
                                                                                            </p>
                                                                                        </div>
                                                                                    </div>
                                                                                    <div class="flex items-center gap-2 shrink-0">
                                                                                        <crate::Badge
                                                                                            label=group_key(group)
                                                                                            tone=group_badge_tone(group)
                                                                                        />
                                                                                        <span class="text-xs tabular-nums text-[var(--af-topo-subtitle-fg)]">
                                                                                            {format!("{link_total}")}
                                                                                        </span>
                                                                                    </div>
                                                                                </button>
                                                                            }
                                                                        })
                                                                        .collect_view()
                                                                }}
                                                            </div>
                                                        </section>
                                                    </Show>
                                                }
                                            })
                                            .collect_view()}
                                    </Show>
                                </div>
                            }
                        }
                    >
                        <div class="af-topology-canvas-wrap">
                            <Show when=move || help_open.get()>
                                <div
                                    role="region"
                                    aria-label=move || ui_t("Service map shortcuts")
                                    class="af-popover af-topo-help-popover"
                                >
                                    <div class="flex items-center justify-between gap-2 mb-1.5">
                                        <p class="font-semibold text-[var(--af-fg-primary)]">
                                            {move || ui_t("Service map shortcuts")}
                                        </p>
                                        <button
                                            type="button"
                                            class="af-topology-search-clear static obs-inline-action"
                                            aria-label=move || ui_t("Hide map help")
                                            on:click=move |_| help_open.set(false)
                                        >
                                            "×"
                                        </button>
                                    </div>
                                    <ul class="space-y-1 text-[var(--af-fg-secondary)] list-disc pl-4">
                                        <li>
                                            {move || {
                                                ui_t(
                                                    "Click a service card to inspect details and connections.",
                                                )
                                            }}
                                        </li>
                                        <li>
                                            {move || {
                                                ui_t(
                                                    "Scroll to zoom, drag the canvas to pan, or press Reset view.",
                                                )
                                            }}
                                        </li>
                                        <li>
                                            {move || {
                                                ui_t(
                                                    "Type in the search box to filter and highlight matching services.",
                                                )
                                            }}
                                        </li>
                                    </ul>
                                </div>
                            </Show>

                            <svg
                                node_ref=svg_ref
                                viewBox=move || {
                                    let current = layout.get();
                                    format!("0 0 {} {}", current.width, current.height)
                                }
                                preserveAspectRatio="xMidYMid meet"
                                class=move || {
                                    if drag.get().is_some() {
                                        "af-topology-map is-dragging touch-none"
                                    } else {
                                        "af-topology-map touch-none"
                                    }
                                }
                                aria-label=move || ui_t("Service topology graph")
                                role="group"
                                on:pointerdown=move |event| {
                                    let x = event.client_x() as f64;
                                    let y = event.client_y() as f64;
                                    did_drag.set(false);
                                    drag.set(Some((x, y, x, y)));
                                }
                                on:pointerup=move |_| drag.set(None)
                                on:pointerleave=move |_| drag.set(None)
                                on:pointermove=move |event| {
                                    if let Some((sx, sy, lx, ly)) = drag.get_untracked() {
                                        let nx = event.client_x() as f64;
                                        let ny = event.client_y() as f64;
                                        if did_drag.get_untracked()
                                            || (nx - sx).hypot(ny - sy) > 4.0
                                        {
                                            did_drag.set(true);
                                            let scale = zoom.get_untracked().max(0.4);
                                            pan.update(|pan| {
                                                pan.0 += (nx - lx) / scale;
                                                pan.1 += (ny - ly) / scale;
                                            });
                                            drag.set(Some((sx, sy, nx, ny)));
                                        }
                                    }
                                }
                            >
                                <defs>
                                    <marker
                                        id="af-topo-arrow-active"
                                        viewBox="0 0 10 10"
                                        refX="8.5"
                                        refY="5"
                                        markerWidth="6.5"
                                        markerHeight="6.5"
                                        orient="auto-start-reverse"
                                    >
                                        <path
                                            d="M 1 1.5 L 9 5 L 1 8.5 Z"
                                            fill="var(--af-topo-active-edge)"
                                        />
                                    </marker>
                                    <marker
                                        id="af-topo-arrow-standby"
                                        viewBox="0 0 10 10"
                                        refX="8.5"
                                        refY="5"
                                        markerWidth="6.5"
                                        markerHeight="6.5"
                                        orient="auto-start-reverse"
                                    >
                                        <path
                                            d="M 1 1.5 L 9 5 L 1 8.5 Z"
                                            fill="var(--af-topo-standby-edge)"
                                        />
                                    </marker>
                                    <marker
                                        id="af-topo-arrow-exception"
                                        viewBox="0 0 10 10"
                                        refX="8.5"
                                        refY="5"
                                        markerWidth="6.5"
                                        markerHeight="6.5"
                                        orient="auto-start-reverse"
                                    >
                                        <path
                                            d="M 1 1.5 L 9 5 L 1 8.5 Z"
                                            fill="var(--af-topo-exception-edge)"
                                        />
                                    </marker>
                                    <marker
                                        id="af-topo-arrow-twoway"
                                        viewBox="0 0 10 10"
                                        refX="8.5"
                                        refY="5"
                                        markerWidth="6"
                                        markerHeight="6"
                                        orient="auto-start-reverse"
                                    >
                                        <path
                                            d="M 1 1.5 L 9 5 L 1 8.5 Z"
                                            fill="var(--af-topo-twoway-edge)"
                                        />
                                    </marker>
                                </defs>

                                <g transform=move || {
                                    let current = layout.get();
                                    let cx = current.width / 2.0;
                                    let cy = current.height / 2.0;
                                    let (x, y) = pan.get();
                                    let z = zoom.get();
                                    format!(
                                        "translate({x},{y}) translate({cx},{cy}) scale({z}) translate(-{cx},-{cy})"
                                    )
                                }>
                                    // Layer 1: Column headers
                                    {move || {
                                        layout
                                            .get()
                                            .columns
                                            .into_iter()
                                            .map(|col| {
                                                view! {
                                                    <text
                                                        x=col.x
                                                        y=col.y
                                                        text-anchor="start"
                                                        fill="var(--af-topo-subtitle-fg)"
                                                        font-size="12.5"
                                                        font-weight="500"
                                                    >
                                                        {move || ui_t(col.label_key)}
                                                    </text>
                                                }
                                            })
                                            .collect_view()
                                    }}

                                    // Layer 2: Curved cubic Bézier edges
                                    {move || {
                                        let matches = matching_ids.get();
                                        let hovered = hovered_node.get();
                                        layout
                                            .get()
                                            .edges
                                            .into_iter()
                                            .map(|edge| {
                                                let stroke = edge_stroke_color(edge.kind);
                                                let is_incident = hovered.as_deref().is_some_and(
                                                    |hid| hid == edge.source || hid == edge.target,
                                                );
                                                let dimmed_by_hover =
                                                    hovered.is_some() && !is_incident;
                                                let dimmed_by_search =
                                                    matches.as_ref().is_some_and(|set| {
                                                        !set.contains(&edge.source)
                                                            && !set.contains(&edge.target)
                                                    });
                                                let dimmed = dimmed_by_hover || dimmed_by_search;
                                                let base_width = edge_stroke_width(edge.kind);
                                                let stroke_width = if is_incident {
                                                    base_width + 0.6
                                                } else {
                                                    base_width
                                                };
                                                let dash = if edge.kind == TopologyEdgeKind::Exception
                                                {
                                                    Some("6 4")
                                                } else {
                                                    None
                                                };
                                                let marker_end = if edge.is_two_way {
                                                    Some("url(#af-topo-arrow-twoway)")
                                                } else if edge.has_arrow {
                                                    Some(edge_arrow_marker(edge.kind))
                                                } else {
                                                    None
                                                };
                                                let marker_start = if edge.is_two_way {
                                                    Some("url(#af-topo-arrow-twoway)")
                                                } else {
                                                    None
                                                };
                                                let opacity = if dimmed { "0.26" } else { "1" };

                                                view! {
                                                    <path
                                                        class="af-topo-edge"
                                                        data-source=edge.source
                                                        data-target=edge.target
                                                        data-edge-kind=edge.kind.as_str()
                                                        d=edge.path_d
                                                        fill="none"
                                                        stroke=stroke
                                                        stroke-width=stroke_width
                                                        stroke-dasharray=dash
                                                        stroke-linecap="round"
                                                        marker-start=marker_start
                                                        marker-end=marker_end
                                                        opacity=opacity
                                                    />
                                                }
                                            })
                                            .collect_view()
                                    }}

                                    // Layer 3: Inline rounded pill labels on edges
                                    {move || {
                                        let matches = matching_ids.get();
                                        let hovered = hovered_node.get();
                                        layout
                                            .get()
                                            .edges
                                            .into_iter()
                                            .filter(|edge| !edge.label.is_empty())
                                            .map(|edge| {
                                                let display_label = ui_t(&edge.label);
                                                let pill_width =
                                                    ((display_label.chars().count() as f64) * 7.2
                                                        + 22.0)
                                                        .max(54.0);
                                                let pill_border = edge_stroke_color(edge.kind);
                                                let is_incident = hovered.as_deref().is_some_and(
                                                    |hid| hid == edge.source || hid == edge.target,
                                                );
                                                let dimmed = (hovered.is_some() && !is_incident)
                                                    || matches.as_ref().is_some_and(|set| {
                                                        !set.contains(&edge.source)
                                                            && !set.contains(&edge.target)
                                                    });

                                                view! {
                                                    <g
                                                        class="af-topo-edge-pill"
                                                        class:af-topo-edge-pill-dimmed=dimmed
                                                        transform=format!(
                                                            "translate({},{})",
                                                            edge.label_x, edge.label_y
                                                        )
                                                    >
                                                        <rect
                                                            x=-pill_width / 2.0
                                                            y="-11"
                                                            width=pill_width
                                                            height="22"
                                                            rx="11"
                                                            fill="var(--af-topo-pill-bg)"
                                                            stroke=pill_border
                                                            stroke-width="1.15"
                                                        />
                                                        <text
                                                            x="0"
                                                            y="0.5"
                                                            text-anchor="middle"
                                                            dominant-baseline="central"
                                                            fill="var(--af-topo-pill-fg)"
                                                            font-size="12"
                                                            font-weight="500"
                                                        >
                                                            {display_label}
                                                        </text>
                                                    </g>
                                                }
                                            })
                                            .collect_view()
                                    }}

                                    // Layer 4: Rich T3-style SVG node cards
                                    {move || {
                                        let matches = matching_ids.get();
                                        layout
                                            .get()
                                            .nodes
                                            .into_iter()
                                            .map(|node| {
                                                let click_id = node.id.clone();
                                                let key_id = node.id.clone();
                                                let enter_id = node.id.clone();
                                                let leave_id = node.id.clone();
                                                let is_matched = matches
                                                    .as_ref()
                                                    .is_some_and(|set| set.contains(&node.id));
                                                let is_dimmed = matches
                                                    .as_ref()
                                                    .is_some_and(|set| !set.contains(&node.id));
                                                let card_body = render_node_card(&node);

                                                view! {
                                                    <g
                                                        role="button"
                                                        tabindex="0"
                                                        aria-label=node.label.clone()
                                                        data-node-id=node.id.clone()
                                                        data-tier=node.tier.as_str()
                                                        class="af-topo-node"
                                                        class:af-topo-node-dimmed=is_dimmed
                                                        class:af-topo-node-matched=is_matched
                                                        transform=format!("translate({},{})", node.x, node.y)
                                                        on:pointerdown=move |event| {
                                                            event.stop_propagation();
                                                        }
                                                        on:mouseenter=move |_| {
                                                            hovered_node.set(Some(enter_id.clone()));
                                                        }
                                                        on:mouseleave=move |_| {
                                                            if hovered_node.get_untracked().as_deref()
                                                                == Some(leave_id.as_str())
                                                            {
                                                                hovered_node.set(None);
                                                            }
                                                        }
                                                        on:click=move |event| {
                                                            event.stop_propagation();
                                                            did_drag.set(false);
                                                            open_inspector(click_id.clone());
                                                        }
                                                        on:keydown=move |event| {
                                                            if matches!(
                                                                event.key().as_str(),
                                                                "Enter" | " " | "Spacebar"
                                                            ) {
                                                                event.prevent_default();
                                                                open_inspector(key_id.clone());
                                                            }
                                                        }
                                                    >
                                                        {card_body}
                                                    </g>
                                                }
                                            })
                                            .collect_view()
                                    }}
                                </g>
                            </svg>
                        </div>

                        // Bottom legend & segmented zoom bar inside the map frame
                        <div class="af-topology-footer">
                            <div class="af-topo-legend" aria-label=move || ui_t("Connections")>
                                <span class="af-topo-legend-item">
                                    <svg width="18" height="10" viewBox="0 0 18 10" aria-hidden="true">
                                        <line
                                            x1="1"
                                            y1="5"
                                            x2="17"
                                            y2="5"
                                            stroke="var(--af-topo-active-edge)"
                                            stroke-width="2"
                                            stroke-linecap="round"
                                        />
                                    </svg>
                                    {move || ui_t("Active")}
                                </span>
                                <span class="af-topo-legend-item">
                                    <svg width="18" height="10" viewBox="0 0 18 10" aria-hidden="true">
                                        <line
                                            x1="1"
                                            y1="5"
                                            x2="17"
                                            y2="5"
                                            stroke="var(--af-topo-standby-edge)"
                                            stroke-width="1.6"
                                            stroke-linecap="round"
                                        />
                                    </svg>
                                    {move || ui_t("Standby")}
                                </span>
                                <span class="af-topo-legend-item">
                                    <svg width="18" height="10" viewBox="0 0 18 10" aria-hidden="true">
                                        <line
                                            x1="1"
                                            y1="5"
                                            x2="17"
                                            y2="5"
                                            stroke="var(--af-topo-exception-edge)"
                                            stroke-width="1.8"
                                            stroke-dasharray="4 3"
                                            stroke-linecap="round"
                                        />
                                    </svg>
                                    {move || ui_t("Exceptions")}
                                </span>
                                <span class="af-topo-legend-item">
                                    <svg width="20" height="10" viewBox="0 0 20 10" aria-hidden="true">
                                        <line
                                            x1="1"
                                            y1="5"
                                            x2="14"
                                            y2="5"
                                            stroke="var(--af-topo-subtitle-fg)"
                                            stroke-width="1.6"
                                            stroke-linecap="round"
                                        />
                                        <path
                                            d="M 12 2 L 18 5 L 12 8 Z"
                                            fill="var(--af-topo-subtitle-fg)"
                                        />
                                    </svg>
                                    {move || ui_t("Link")}
                                </span>
                                <span class="af-topo-legend-item">
                                    <svg width="22" height="10" viewBox="0 0 22 10" aria-hidden="true">
                                        <path
                                            d="M 7 2 L 1.5 5 L 7 8 Z"
                                            fill="var(--af-topo-twoway-edge)"
                                        />
                                        <line
                                            x1="6"
                                            y1="5"
                                            x2="16"
                                            y2="5"
                                            stroke="var(--af-topo-twoway-edge)"
                                            stroke-width="1.6"
                                        />
                                        <path
                                            d="M 15 2 L 20.5 5 L 15 8 Z"
                                            fill="var(--af-topo-twoway-edge)"
                                        />
                                    </svg>
                                    {move || ui_t("Two-way")}
                                </span>
                            </div>

                            <div class="af-topo-zoom-group">
                                <button
                                    type="button"
                                    class="af-topo-zoom-btn obs-inline-action"
                                    aria-label=move || ui_t("Zoom out")
                                    title=move || ui_t("Zoom out")
                                    on:click=move |_| zoom.update(|z| *z = (*z / 1.2).max(0.4))
                                >
                                    "−"
                                </button>
                                <button
                                    type="button"
                                    class="af-topo-zoom-btn obs-inline-action"
                                    aria-label=move || ui_t("Zoom in")
                                    title=move || ui_t("Zoom in")
                                    on:click=move |_| zoom.update(|z| *z = (*z * 1.2).min(3.0))
                                >
                                    "+"
                                </button>
                                <button
                                    type="button"
                                    class="af-topo-zoom-btn obs-inline-action"
                                    aria-label=move || ui_t("Reset view")
                                    title=move || ui_t("Reset view")
                                    on:click=move |_| {
                                        zoom.set(1.0);
                                        pan.set((0.0, 0.0));
                                    }
                                >
                                    <svg
                                        width="14"
                                        height="14"
                                        viewBox="0 0 16 16"
                                        fill="none"
                                        stroke="currentColor"
                                        stroke-width="1.6"
                                        stroke-linecap="round"
                                        stroke-linejoin="round"
                                        aria-hidden="true"
                                    >
                                        <path d="M 2.5 6 L 2.5 2.5 L 6 2.5" />
                                        <path d="M 10 2.5 L 13.5 2.5 L 13.5 6" />
                                        <path d="M 13.5 10 L 13.5 13.5 L 10 13.5" />
                                        <path d="M 6 13.5 L 2.5 13.5 L 2.5 10" />
                                    </svg>
                                </button>
                            </div>
                        </div>
                    </Show>
                </crate::TabPanel>
            </div>

            // Compact footer metadata caption below the map frame (like "4 machines · 8 links")
            <p class="text-xs text-[var(--af-fg-muted)] mt-2.5 tabular-nums">
                {move || {
                    let current = layout.get();
                    let total = current.nodes.len();
                    let edge_count = current.edges.len();
                    let total_s = total.to_string();
                    let links_s = edge_count.to_string();
                    if let Some(matches) = matching_ids.get() {
                        let shown_s = matches.len().to_string();
                        ui_t_with(
                            "{shown} of {total} services · {links} links",
                            &[
                                ("shown", shown_s.as_str()),
                                ("total", total_s.as_str()),
                                ("links", links_s.as_str()),
                            ],
                        )
                    } else {
                        ui_t_with(
                            "{services} services · {links} links",
                            &[("services", total_s.as_str()), ("links", links_s.as_str())],
                        )
                    }
                }}
            </p>

            // Upgraded Service Inspector modal with status badge, tier, links, and raw payload
            <crate::Modal open=inspector title="Service inspector">
                {move || {
                    let target_id = selected_id.get()?;
                    let current = layout.get();
                    let node = current
                        .nodes
                        .iter()
                        .find(|candidate| candidate.id == target_id)?
                        .clone();
                    let incoming_peers: Vec<(String, String)> = current
                        .edges
                        .iter()
                        .filter_map(|edge| {
                            if edge.target == node.id {
                                let label = current
                                    .nodes
                                    .iter()
                                    .find(|n| n.id == edge.source)
                                    .map(|n| n.label.clone())
                                    .unwrap_or_else(|| edge.source.clone());
                                Some((edge.source.clone(), label))
                            } else if edge.is_two_way && edge.source == node.id {
                                let label = current
                                    .nodes
                                    .iter()
                                    .find(|n| n.id == edge.target)
                                    .map(|n| n.label.clone())
                                    .unwrap_or_else(|| edge.target.clone());
                                Some((edge.target.clone(), label))
                            } else {
                                None
                            }
                        })
                        .collect();
                    let outgoing_peers: Vec<(String, String)> = current
                        .edges
                        .iter()
                        .filter_map(|edge| {
                            if edge.source == node.id {
                                let label = current
                                    .nodes
                                    .iter()
                                    .find(|n| n.id == edge.target)
                                    .map(|n| n.label.clone())
                                    .unwrap_or_else(|| edge.target.clone());
                                Some((edge.target.clone(), label))
                            } else if edge.is_two_way && edge.target == node.id {
                                let label = current
                                    .nodes
                                    .iter()
                                    .find(|n| n.id == edge.source)
                                    .map(|n| n.label.clone())
                                    .unwrap_or_else(|| edge.source.clone());
                                Some((edge.source.clone(), label))
                            } else {
                                None
                            }
                        })
                        .collect();
                    let payload = services.with(|rows| {
                        rows.iter()
                            .find(|(key, _)| *key == node.id)
                            .map(|(_, value)| {
                                serde_json::to_string_pretty(value).unwrap_or_default()
                            })
                            .unwrap_or_default()
                    });
                    let has_connections = !incoming_peers.is_empty() || !outgoing_peers.is_empty();
                    let details_text = if node.details.is_empty() {
                        localize_card_subtitle(&node)
                    } else {
                        node.details.clone()
                    };

                    Some(view! {
                        <div class="space-y-4">
                            <div class="flex flex-wrap items-start justify-between gap-3">
                                <div class="min-w-0">
                                    <p class="text-base font-semibold text-[var(--af-fg-primary)]">
                                        {node.label.clone()}
                                    </p>
                                    <p class="text-xs text-[var(--af-fg-muted)] mt-0.5">
                                        {format!("{} · {}", node.service_id, node.status)}
                                    </p>
                                </div>
                                <div class="flex flex-wrap items-center gap-1.5">
                                    <crate::Badge
                                        label=group_key(node.group)
                                        tone=group_badge_tone(node.group)
                                    />
                                    <crate::Badge label=node.tier.label_key() tone="neutral" />
                                </div>
                            </div>

                            <div class="grid gap-3 sm:grid-cols-2 text-xs af-surface-inset p-3">
                                <div>
                                    <p class="text-[var(--af-fg-muted)]">{move || ui_t("Tier")}</p>
                                    <p class="font-medium text-[var(--af-fg-primary)] mt-0.5">
                                        {move || ui_t(node.tier.label_key())}
                                    </p>
                                </div>
                                <div>
                                    <p class="text-[var(--af-fg-muted)]">{move || ui_t("Details")}</p>
                                    <p class="font-medium text-[var(--af-fg-primary)] mt-0.5 break-words">
                                        {details_text}
                                    </p>
                                </div>
                            </div>

                            <div class="space-y-2">
                                <h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--af-fg-muted)]">
                                    {move || ui_t("Connections")}
                                </h3>
                                {if !has_connections {
                                    view! {
                                        <p class="text-xs text-[var(--af-fg-muted)]">
                                            {move || ui_t("No connections")}
                                        </p>
                                    }
                                        .into_any()
                                } else {
                                    view! {
                                        <div class="space-y-2 text-xs">
                                            {(!incoming_peers.is_empty()).then(|| {
                                                view! {
                                                    <div class="flex flex-wrap items-center gap-1.5">
                                                        <span class="text-[var(--af-fg-muted)] mr-1">
                                                            {move || ui_t("Incoming")} ":"
                                                        </span>
                                                        {incoming_peers
                                                            .into_iter()
                                                            .map(|(peer_id, peer_label)| {
                                                                view! {
                                                                    <button
                                                                        type="button"
                                                                        class="af-btn px-2.5 py-1 text-xs min-h-7"
                                                                        on:click=move |_| {
                                                                            selected_id.set(Some(peer_id.clone()));
                                                                        }
                                                                    >
                                                                        {peer_label}
                                                                    </button>
                                                                }
                                                            })
                                                            .collect_view()}
                                                    </div>
                                                }
                                            })}
                                            {(!outgoing_peers.is_empty()).then(|| {
                                                view! {
                                                    <div class="flex flex-wrap items-center gap-1.5">
                                                        <span class="text-[var(--af-fg-muted)] mr-1">
                                                            {move || ui_t("Outgoing")} ":"
                                                        </span>
                                                        {outgoing_peers
                                                            .into_iter()
                                                            .map(|(peer_id, peer_label)| {
                                                                view! {
                                                                    <button
                                                                        type="button"
                                                                        class="af-btn px-2.5 py-1 text-xs min-h-7"
                                                                        on:click=move |_| {
                                                                            selected_id.set(Some(peer_id.clone()));
                                                                        }
                                                                    >
                                                                        {peer_label}
                                                                    </button>
                                                                }
                                                            })
                                                            .collect_view()}
                                                    </div>
                                                }
                                            })}
                                        </div>
                                    }
                                        .into_any()
                                }}
                            </div>

                            <div class="space-y-1.5">
                                <h3 class="text-xs font-semibold uppercase tracking-wider text-[var(--af-fg-muted)]">
                                    {move || ui_t("Payload")}
                                </h3>
                                <pre class="obs-scroller text-xs p-3 rounded-lg af-surface-inset">
                                    {payload}
                                </pre>
                            </div>
                        </div>
                    })
                }}
            </crate::Modal>
        </div>
    }
}

fn render_node_card(node: &TopologyCardNode) -> AnyView {
    let half_w = node.width / 2.0;
    let half_h = node.height / 2.0;
    let is_exception = node.group == ServiceGroup::Exception;
    let status_color = node_status_color(node);

    match node.tier {
        TopologyTier::Gateway => {
            let title = truncate_label(&node.label, 20);
            let icon = node.icon;
            view! {
                <rect
                    x=-half_w
                    y=-half_h
                    width=node.width
                    height=node.height
                    rx=half_h
                    class="af-topo-card-rect"
                    class:af-topo-card-rect-exception=is_exception
                />
                <g transform=format!("translate({}, -9)", -half_w + 18.0)>
                    {render_topology_icon(icon)}
                </g>
                <text
                    x=-half_w + 44.0
                    y="0.5"
                    text-anchor="start"
                    dominant-baseline="central"
                    fill="var(--af-topo-title-fg)"
                    font-size="13"
                    font-weight="600"
                >
                    {title}
                </text>
            }
            .into_any()
        }
        TopologyTier::Service => {
            let title = truncate_label(&node.label, 19);
            let subtitle = truncate_label(&localize_card_subtitle(node), 21);
            let icon = node.icon;
            let well_x = -half_w + 14.0;
            let well_y = -18.0;
            let text_x = well_x + 48.0;
            view! {
                <rect
                    x=-half_w
                    y=-half_h
                    width=node.width
                    height=node.height
                    rx="12"
                    class="af-topo-card-rect"
                    class:af-topo-card-rect-exception=is_exception
                />
                // Left 36×36 rounded icon well + bottom-right status dot with card-bg cutout ring
                <rect
                    x=well_x
                    y=well_y
                    width="36"
                    height="36"
                    rx="8"
                    fill="var(--af-topo-icon-well-bg)"
                    stroke="var(--af-topo-icon-well-border)"
                    stroke-width="1"
                />
                <g transform=format!("translate({}, -9)", well_x + 9.0)>
                    {render_topology_icon(icon)}
                </g>
                <circle
                    cx=well_x + 35.0
                    cy=well_y + 35.0
                    r="4.4"
                    fill=status_color
                    stroke="var(--af-topo-card-bg)"
                    stroke-width="2"
                />
                <text
                    x=text_x
                    y="-7"
                    text-anchor="start"
                    dominant-baseline="central"
                    fill="var(--af-topo-title-fg)"
                    font-size="13"
                    font-weight="600"
                >
                    {title}
                </text>
                <text
                    x=text_x
                    y="13"
                    text-anchor="start"
                    dominant-baseline="central"
                    fill="var(--af-topo-subtitle-fg)"
                    font-size="12"
                    font-weight="400"
                >
                    {subtitle}
                </text>
                // Right-edge circular "+" action badge mirroring T3 Code's environment connectors
                <circle
                    cx=half_w
                    cy="0"
                    r="11"
                    class="af-topo-plus-circle"
                    stroke="var(--af-topo-canvas-bg)"
                    stroke-width="1.5"
                />
                <path
                    d=format!(
                        "M {x} -4.2 L {x} 4.2 M {x1} 0 L {x2} 0",
                        x = half_w,
                        x1 = half_w - 4.2,
                        x2 = half_w + 4.2
                    )
                    stroke="#ffffff"
                    stroke-width="1.8"
                    stroke-linecap="round"
                />
            }
            .into_any()
        }
        TopologyTier::Dependency => {
            let title = truncate_label(&node.label, 18);
            let subtitle = truncate_label(&localize_card_subtitle(node), 20);
            let dash = if node.dashed_border {
                Some("4 3")
            } else {
                None
            };
            let bars = node.signal_bars.min(4);
            let lit_color = if is_exception || bars == 1 {
                "var(--af-topo-signal-error)"
            } else if bars == 2 {
                "var(--af-topo-signal-warn)"
            } else {
                "var(--af-topo-signal-healthy)"
            };
            let ring_x = -half_w + 20.0;
            let text_x = -half_w + 36.0;
            let bar_base_x = half_w - 36.0;
            let bar_bottom_y = 9.0;
            let bar_heights = [5.0, 9.0, 13.0, 17.0];

            view! {
                <rect
                    x=-half_w
                    y=-half_h
                    width=node.width
                    height=node.height
                    rx="10"
                    stroke-dasharray=dash
                    class="af-topo-card-rect"
                    class:af-topo-card-rect-exception=is_exception
                />
                // Left hollow status ring (mirrors T3 Linked machine status ring)
                <circle
                    cx=ring_x
                    cy="0"
                    r="5.5"
                    fill="none"
                    stroke=status_color
                    stroke-width="1.8"
                />
                {(!node.dashed_border).then(|| {
                    view! { <circle cx=ring_x cy="0" r="2" fill=status_color /> }
                })}
                <text
                    x=text_x
                    y="-7"
                    text-anchor="start"
                    dominant-baseline="central"
                    fill="var(--af-topo-title-fg)"
                    font-size="13"
                    font-weight="600"
                >
                    {title}
                </text>
                <text
                    x=text_x
                    y="12"
                    text-anchor="start"
                    dominant-baseline="central"
                    fill="var(--af-topo-subtitle-fg)"
                    font-size="12"
                    font-weight="400"
                >
                    {subtitle}
                </text>
                // Right-aligned 4-bar health / signal meter
                {bar_heights
                    .into_iter()
                    .enumerate()
                    .map(|(index, h)| {
                        let fill = if (index as u8) < bars {
                            lit_color
                        } else {
                            "var(--af-topo-signal-unlit)"
                        };
                        view! {
                            <rect
                                x=bar_base_x + (index as f64) * 6.0
                                y=bar_bottom_y - h
                                width="3.6"
                                height=h
                                rx="1.4"
                                fill=fill
                            />
                        }
                    })
                    .collect_view()}
            }
            .into_any()
        }
    }
}

fn render_topology_icon(icon: TopologyIconKind) -> AnyView {
    match icon {
        TopologyIconKind::Gateway => view! {
            <g
                fill="none"
                stroke="var(--af-topo-icon-fg)"
                stroke-width="1.5"
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <rect x="1.5" y="2.5" width="15" height="13" rx="2.5" />
                <line x1="1.5" y1="6.5" x2="16.5" y2="6.5" />
                <circle cx="4.5" cy="4.5" r="0.6" fill="var(--af-topo-icon-fg)" stroke="none" />
                <circle cx="7" cy="4.5" r="0.6" fill="var(--af-topo-icon-fg)" stroke="none" />
            </g>
        }
        .into_any(),
        TopologyIconKind::Api => view! {
            <g
                fill="none"
                stroke="var(--af-topo-icon-fg)"
                stroke-width="1.45"
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <rect x="2" y="2.5" width="14" height="5.5" rx="1.5" />
                <rect x="2" y="10" width="14" height="5.5" rx="1.5" />
                <circle cx="5" cy="5.25" r="0.7" fill="var(--af-topo-icon-fg)" stroke="none" />
                <circle cx="5" cy="12.75" r="0.7" fill="var(--af-topo-icon-fg)" stroke="none" />
                <line x1="8" y1="5.25" x2="13.5" y2="5.25" />
                <line x1="8" y1="12.75" x2="13.5" y2="12.75" />
            </g>
        }
        .into_any(),
        TopologyIconKind::Runner => view! {
            <g
                fill="none"
                stroke="var(--af-topo-icon-fg)"
                stroke-width="1.5"
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <rect x="2" y="2.5" width="14" height="13" rx="2.5" />
                <path d="M 5.5 7 L 8.5 9.5 L 5.5 12" />
                <line x1="10" y1="12" x2="13" y2="12" />
            </g>
        }
        .into_any(),
        TopologyIconKind::Database => view! {
            <g
                fill="none"
                stroke="var(--af-topo-icon-fg)"
                stroke-width="1.45"
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <ellipse cx="9" cy="4.5" rx="6" ry="2.2" />
                <path d="M 3 4.5 L 3 13.5 C 3 14.7 5.7 15.7 9 15.7 C 12.3 15.7 15 14.7 15 13.5 L 15 4.5" />
                <path d="M 3 9 C 3 10.2 5.7 11.2 9 11.2 C 12.3 11.2 15 10.2 15 9" />
            </g>
        }
        .into_any(),
        TopologyIconKind::Media => view! {
            <g
                fill="none"
                stroke="var(--af-topo-icon-fg)"
                stroke-width="1.5"
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <rect x="2" y="3" width="14" height="12" rx="2.5" />
                <path d="M 7.5 6.5 L 12 9 L 7.5 11.5 Z" fill="var(--af-topo-icon-fg)" stroke="none" />
            </g>
        }
        .into_any(),
        TopologyIconKind::Network => view! {
            <g
                fill="none"
                stroke="var(--af-topo-icon-fg)"
                stroke-width="1.45"
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <circle cx="9" cy="9" r="6.5" />
                <line x1="2.8" y1="9" x2="15.2" y2="9" />
                <path d="M 9 2.5 C 11.2 4.8 11.2 13.2 9 15.5 C 6.8 13.2 6.8 4.8 9 2.5" />
            </g>
        }
        .into_any(),
        TopologyIconKind::Cloud => view! {
            <g
                fill="none"
                stroke="var(--af-topo-icon-fg)"
                stroke-width="1.45"
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <path d="M 5.2 13.8 L 13.2 13.8 C 14.9 13.8 16.2 12.5 16.2 10.9 C 16.2 9.4 15.1 8.2 13.6 8 C 13.1 5.6 11.1 4 8.7 4 C 6.1 4 4.1 6 3.9 8.5 C 2.6 8.9 1.8 10 1.8 11.3 C 1.8 12.7 3.3 13.8 5.2 13.8 Z" />
            </g>
        }
        .into_any(),
        TopologyIconKind::Service => view! {
            <g
                fill="none"
                stroke="var(--af-topo-icon-fg)"
                stroke-width="1.45"
                stroke-linecap="round"
                stroke-linejoin="round"
            >
                <path d="M 9 2.2 L 15 5.5 L 15 12.5 L 9 15.8 L 3 12.5 L 3 5.5 Z" />
                <path d="M 3 5.5 L 9 8.8 L 15 5.5 M 9 8.8 L 9 15.8" />
            </g>
        }
        .into_any(),
    }
}

fn node_status_color(node: &TopologyCardNode) -> &'static str {
    match node.group {
        ServiceGroup::Exception => "var(--af-topo-exception)",
        ServiceGroup::Stopped => "var(--af-topo-stopped)",
        ServiceGroup::Active => "var(--af-topo-active)",
        ServiceGroup::Core => {
            if matches!(
                node.status.to_lowercase().as_str(),
                "running" | "active" | "healthy" | "ok" | "online"
            ) {
                "var(--af-topo-active)"
            } else if matches!(
                node.status.to_lowercase().as_str(),
                "stopped" | "inactive" | "disabled" | "offline"
            ) {
                "var(--af-topo-stopped)"
            } else {
                "var(--af-topo-core)"
            }
        }
        ServiceGroup::Other => "var(--af-topo-stopped)",
    }
}

fn edge_stroke_color(kind: TopologyEdgeKind) -> &'static str {
    match kind {
        TopologyEdgeKind::Active => "var(--af-topo-active-edge)",
        TopologyEdgeKind::Standby => "var(--af-topo-standby-edge)",
        TopologyEdgeKind::Exception => "var(--af-topo-exception-edge)",
        TopologyEdgeKind::TwoWay => "var(--af-topo-twoway-edge)",
    }
}

fn edge_stroke_width(kind: TopologyEdgeKind) -> f64 {
    match kind {
        TopologyEdgeKind::Active => 1.85,
        TopologyEdgeKind::Standby => 1.4,
        TopologyEdgeKind::Exception => 2.0,
        TopologyEdgeKind::TwoWay => 2.2,
    }
}

fn edge_arrow_marker(kind: TopologyEdgeKind) -> &'static str {
    match kind {
        TopologyEdgeKind::Active => "url(#af-topo-arrow-active)",
        TopologyEdgeKind::Standby => "url(#af-topo-arrow-standby)",
        TopologyEdgeKind::Exception => "url(#af-topo-arrow-exception)",
        TopologyEdgeKind::TwoWay => "url(#af-topo-arrow-twoway)",
    }
}

fn localize_card_subtitle(node: &TopologyCardNode) -> String {
    if node.tier == TopologyTier::Service {
        if node.outgoing_count == 1 {
            return ui_t("1 link out");
        } else if node.outgoing_count > 1 {
            let count = node.outgoing_count.to_string();
            return ui_t_with("{count} links out", &[("count", count.as_str())]);
        } else if node.subtitle == "No links out" {
            return ui_t("No links out");
        }
    }
    if node.subtitle == "Gateway" || node.subtitle == "Degraded" {
        return ui_t(&node.subtitle);
    }
    node.subtitle.clone()
}

fn truncate_label(text: &str, max_chars: usize) -> String {
    let count = text.chars().count();
    if count <= max_chars || max_chars < 2 {
        text.to_string()
    } else {
        let mut out: String = text.chars().take(max_chars - 1).collect();
        out.push('…');
        out
    }
}

fn group_key(group: ServiceGroup) -> &'static str {
    match group {
        ServiceGroup::Core => "Overview.corePlatformCount",
        ServiceGroup::Active => "Overview.runningCount",
        ServiceGroup::Other => "Other services",
        ServiceGroup::Stopped => "Overview.stoppedCount",
        ServiceGroup::Exception => "Overview.exceptionsCount",
    }
}

fn group_badge_tone(group: ServiceGroup) -> &'static str {
    match group {
        ServiceGroup::Core => "violet",
        ServiceGroup::Active => "success",
        ServiceGroup::Stopped => "muted",
        ServiceGroup::Exception => "danger",
        ServiceGroup::Other => "neutral",
    }
}
