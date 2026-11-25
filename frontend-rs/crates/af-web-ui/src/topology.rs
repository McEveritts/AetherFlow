use crate::ui_t;
use af_web_core::{
    markdown::render_qr_svg,
    topology::{compute_topology_layout, ServiceGroup, TopologyNode},
};
use gloo_events::{EventListener, EventListenerOptions};
use leptos::prelude::*;
use serde_json::Value;
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

#[component]
pub fn AppTopologyMap(
    #[prop(into)] services: Signal<Vec<(String, Value)>>,
    #[prop(into)] links: Signal<Vec<(String, String)>>,
) -> impl IntoView {
    let mode = RwSignal::new("graph".to_string());
    let zoom = RwSignal::new(1.0f64);
    let pan = RwSignal::new((0.0f64, 0.0f64));
    let drag = RwSignal::new(None::<(f64, f64)>);
    let selected = RwSignal::new(None::<TopologyNode>);
    let inspector = RwSignal::new(false);
    let nodes = Memo::new(move |_| compute_topology_layout(&services.get(), 800.0, 400.0));
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
                                .clamp(0.3, 4.0);
                        });
                    }
                },
            )
        }));
    });
    on_cleanup(move || wheel_listener.set_value(None));

    view! {
        <div class="min-w-0 max-w-full space-y-4">
            <div class="flex flex-wrap gap-3 items-center justify-between">
                <crate::TabsBar
                    tabs=vec![("graph".into(), "Graph".into()), ("list".into(), "List".into())]
                    active=mode
                    id_prefix="topology"
                />
                <div class="flex gap-2">
                    <button
                        class="af-btn px-3"
                        aria-label=move || ui_t("Zoom out")
                        on:click=move |_| zoom.update(|zoom| *zoom = (*zoom / 1.2).max(0.3))
                    >
                        "−"
                    </button>
                    <button
                        class="af-btn px-3"
                        aria-label=move || ui_t("Zoom in")
                        on:click=move |_| zoom.update(|zoom| *zoom = (*zoom * 1.2).min(4.0))
                    >
                        "+"
                    </button>
                    <button
                        class="af-btn px-3"
                        on:click=move |_| {
                            zoom.set(1.0);
                            pan.set((0.0, 0.0));
                        }
                    >
                        {move || ui_t("Reset view")}
                    </button>
                </div>
            </div>
            <crate::TabPanel id=mode id_prefix="topology">
                <Show
                    when=move || mode.get() == "graph"
                    fallback=move || view! {
                        <div class="af-hairline-grid grid sm:grid-cols-2">
                            {[ServiceGroup::Core, ServiceGroup::Active, ServiceGroup::Stopped, ServiceGroup::Exception, ServiceGroup::Other]
                                .into_iter().map(|group| view! {
                                    <section class="p-4 min-w-0 space-y-2">
                                        <h3 class="text-sm font-semibold text-slate-200">{move || ui_t(group_key(group))}</h3>
                                        <div class="space-y-1.5">
                                            {move || nodes.get().into_iter().filter(|node| node.group == group).map(|node| {
                                                let name = node.label.clone();
                                                view! {
                                                    <button
                                                        type="button"
                                                        class="af-surface-inset block w-full text-left px-3 py-2 text-sm hover:bg-[var(--af-control-bg-hover)] transition-colors"
                                                        on:click=move |_| {
                                                            selected.set(Some(node.clone()));
                                                            inspector.set(true);
                                                        }
                                                    >
                                                        {name}
                                                    </button>
                                                }
                                            }).collect_view()}
                                        </div>
                                    </section>
                                }).collect_view()}
                        </div>
                    }
                >
                    <svg
                        node_ref=svg_ref
                        viewBox="0 0 800 400"
                        class="af-topology-map w-full h-96 rounded-xl border border-white/5 touch-none"
                        aria-label=move || ui_t("Service topology graph")
                        role="group"
                        on:pointerdown=move |event| drag.set(Some((event.client_x() as f64, event.client_y() as f64)))
                        on:pointerup=move |_| drag.set(None)
                        on:pointerleave=move |_| drag.set(None)
                        on:pointermove=move |event| {
                            if let Some((x, y)) = drag.get_untracked() {
                                let nx = event.client_x() as f64;
                                let ny = event.client_y() as f64;
                                pan.update(|pan| {
                                    pan.0 += nx - x;
                                    pan.1 += ny - y;
                                });
                                drag.set(Some((nx, ny)));
                            }
                        }
                    >
                        <g transform=move || {
                            let (x, y) = pan.get();
                            format!("translate({x},{y}) translate(400,200) scale({}) translate(-400,-200)", zoom.get())
                        }>
                            {move || nodes.with(|nodes| {
                                let positions: std::collections::HashMap<_, _> = nodes.iter().map(|node| (node.id.as_str(), (node.x,node.y))).collect();
                                links.get().into_iter().filter_map(|(source,target)| {
                                    let (x1,y1) = *positions.get(source.as_str())?;
                                    let (x2,y2) = *positions.get(target.as_str())?;
                                    Some(view! { <line data-source=source data-target=target x1=x1 y1=y1 x2=x2 y2=y2 stroke="var(--af-topo-edge)" /> })
                                }).collect_view()
                            })}
                            {move || nodes.get().into_iter().map(|node| {
                                let inspect = node.clone();
                                let keyboard = node.clone();
                                let color = match node.group {
                                    ServiceGroup::Core => "var(--af-topo-core)",
                                    ServiceGroup::Active => "var(--af-topo-active)",
                                    ServiceGroup::Other => "var(--obs-slate-400)",
                                    ServiceGroup::Stopped => "var(--af-topo-stopped)",
                                    ServiceGroup::Exception => "var(--af-topo-exception)",
                                };
                                view! {
                                        <g
                                            role="button"
                                            tabindex="0"
                                            aria-label=node.label.clone()
                                            transform=format!("translate({},{})", node.x, node.y)
                                            on:click=move |_| {
                                                selected.set(Some(inspect.clone()));
                                                inspector.set(true);
                                            }
                                            on:keydown=move |event| {
                                                if matches!(event.key().as_str(), "Enter" | " " | "Spacebar") {
                                                    event.prevent_default();
                                                    selected.set(Some(keyboard.clone()));
                                                    inspector.set(true);
                                                }
                                            }
                                        >
                                            <circle r="22" fill="var(--obs-bg-secondary)" stroke=color stroke-width="2"/>
                                            <circle r="6" fill=color/>
                                            <text y="40" text-anchor="middle" fill="var(--obs-slate-200)" font-size="12">{node.label.clone()}</text>
                                        </g>
                                }
                            }).collect_view()}
                        </g>
                    </svg>
                </Show>
            </crate::TabPanel>
            <crate::Modal open=inspector title="Service inspector">
                {move || selected.get().map(|node| {
                    let id = node.id.clone();
                    view! {
                    <p class="font-semibold">{node.label}</p>
                    <p class="text-slate-400 mt-2">{move || format!("{} · {}", node.id, ui_t(group_key(node.group)))}</p>
                    <pre class="obs-scroller text-xs mt-4">
                        {services.with(|services| services.iter().find(|(key, _)| *key == id)
                            .map(|(_, value)| serde_json::to_string_pretty(value).unwrap_or_default())
                            .unwrap_or_default())}
                    </pre>
                }})}
            </crate::Modal>
        </div>
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
