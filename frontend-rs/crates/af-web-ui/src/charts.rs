use af_web_core::charts::{
    build_area_path_in_domain, build_line_path_in_domain, build_sparkline_path,
    compute_value_scale, compute_x_domain, format_chart_axis_tick, format_chart_timestamp,
    format_chart_value, format_short_axis_time, nearest_point_index_by_x, project_x, project_y,
    target_x_for_cursor, ChartTimeFormat, ChartValueFormat, Point,
};
use leptos::prelude::*;
use wasm_bindgen::{closure::Closure, JsCast};

const PLOT_LEFT_PAD: f64 = 76.0;
const PLOT_RIGHT_PAD: f64 = 16.0;
const PLOT_TOP_PAD: f64 = 12.0;
const PLOT_BOTTOM_PAD: f64 = 32.0;

#[derive(Clone, Debug, PartialEq)]
pub struct HoverSnapshot {
    pub timestamp: f64,
    pub crosshair_x: f64,
    pub primary: Option<Point>,
    pub secondary: Option<Point>,
}

fn effective_x_domain(
    primary: &[Point],
    secondary: &[Point],
    override_domain: Option<[f64; 2]>,
) -> Option<[f64; 2]> {
    let data_domain = compute_x_domain(&[primary, secondary]);
    match (data_domain, override_domain) {
        (Some([dmin, dmax]), Some([omin, omax]))
            if omin.is_finite() && omax.is_finite() && omax >= omin =>
        {
            Some([dmin.min(omin), dmax.max(omax)])
        }
        (Some(d), _) => Some(d),
        (None, Some([omin, omax])) if omin.is_finite() && omax.is_finite() && omax >= omin => {
            Some([omin, omax])
        }
        _ => None,
    }
}

pub fn resolve_hover_snapshot(
    primary: &[Point],
    secondary: &[Point],
    target_x: f64,
    x_domain: [f64; 2],
    width: f64,
) -> Option<HoverSnapshot> {
    if !target_x.is_finite() || width <= 0.0 {
        return None;
    }
    let p_point = nearest_point_index_by_x(primary, target_x).map(|i| primary[i]);
    let s_point = nearest_point_index_by_x(secondary, target_x).map(|i| secondary[i]);
    let anchor_x = match (p_point, s_point) {
        (Some(p), Some(s)) => {
            if (p.x - target_x).abs() <= (s.x - target_x).abs() {
                p.x
            } else {
                s.x
            }
        }
        (Some(p), None) => p.x,
        (None, Some(s)) => s.x,
        (None, None) => return None,
    };
    let span = (x_domain[1] - x_domain[0]).abs();
    let max_pair_delta = (span * 0.05).max(5_000.0);
    let primary_matched = p_point.filter(|p| (p.x - anchor_x).abs() <= max_pair_delta);
    let secondary_matched = s_point.filter(|s| (s.x - anchor_x).abs() <= max_pair_delta);
    Some(HoverSnapshot {
        timestamp: anchor_x,
        crosshair_x: project_x(anchor_x, x_domain, width),
        primary: primary_matched,
        secondary: secondary_matched,
    })
}

fn x_axis_ticks(x_domain: [f64; 2], width: f64) -> Vec<(f64, f64, &'static str)> {
    let span = x_domain[1] - x_domain[0];
    if !span.is_finite() || span.abs() < f64::EPSILON {
        return vec![(width / 2.0, x_domain[0], "middle")];
    }
    if width < 260.0 {
        vec![(0.0, x_domain[0], "start"), (width, x_domain[1], "end")]
    } else {
        vec![
            (0.0, x_domain[0], "start"),
            (width / 2.0, x_domain[0] + span / 2.0, "middle"),
            (width, x_domain[1], "end"),
        ]
    }
}

fn current_ui_locale() -> String {
    use_context::<crate::primitives::UiLocale>()
        .map(|locale| locale.0.get())
        .unwrap_or_else(|| "en".to_string())
}

fn visible_dots(points: &[Point], show_all_dots: bool, gap_threshold_x: Option<f64>) -> Vec<Point> {
    let finite: Vec<Point> = points
        .iter()
        .copied()
        .filter(|p| p.x.is_finite() && p.y.is_finite())
        .collect();
    if finite.is_empty() {
        return vec![];
    }
    if show_all_dots && finite.len() <= 120 {
        return finite;
    }
    if finite.len() == 1 {
        return finite;
    }
    // Always highlight isolated single points separated by gaps on both sides.
    let Some(limit) = gap_threshold_x.filter(|v| v.is_finite() && *v > 0.0) else {
        return vec![];
    };
    let mut isolated = Vec::new();
    for i in 0..finite.len() {
        let left_gap = i == 0 || (finite[i].x - finite[i - 1].x) > limit;
        let right_gap = i + 1 == finite.len() || (finite[i + 1].x - finite[i].x) > limit;
        if left_gap && right_gap {
            isolated.push(finite[i]);
        }
    }
    isolated
}

/// Observer lifetime follows the component owner; callback storage is thread-local.
pub fn use_element_size(
    node: NodeRef<leptos::html::Div>,
    initial: (f64, f64),
) -> RwSignal<(f64, f64)> {
    let size = RwSignal::new(initial);
    let handle = StoredValue::new_local(
        None::<(web_sys::ResizeObserver, Closure<dyn FnMut(js_sys::Array)>)>,
    );
    Effect::new(move |_| {
        if let Some(element) = node.get() {
            if handle.with_value(|h| h.is_some()) {
                return;
            }
            let callback =
                Closure::<dyn FnMut(js_sys::Array)>::new(move |entries: js_sys::Array| {
                    if let Some(entry) = entries.get(0).dyn_ref::<web_sys::ResizeObserverEntry>() {
                        let rect = entry.content_rect();
                        size.set((rect.width().max(1.0), rect.height().max(1.0)));
                    }
                });
            if let Ok(observer) = web_sys::ResizeObserver::new(callback.as_ref().unchecked_ref()) {
                observer.observe(&element);
                handle.set_value(Some((observer, callback)));
            }
        }
    });
    on_cleanup(move || {
        handle.update_value(|handle| {
            if let Some((observer, _)) = handle.take() {
                observer.disconnect();
            }
        });
    });
    size
}

#[component]
pub fn Sparkline(
    #[prop(into)] values: Signal<Vec<f64>>,
    #[prop(optional, into)] label: Signal<String>,
) -> impl IntoView {
    view! {
        <svg viewBox="0 0 160 40" role="img" aria-label=move || crate::primitives::ui_t(&label.get()) class="w-full h-10" preserveAspectRatio="none">
            <path d=move || build_sparkline_path(&values.get(), 160.0, 38.0) fill="none" stroke="currentColor" stroke-width="2" vector-effect="non-scaling-stroke"/>
        </svg>
    }
}

/// True-time single or paired sparkline with shared scaling, gap breaks,
/// magnitude references, endpoints, and nearest-timestamp hover.
#[component]
pub fn TimeSparkline(
    #[prop(into)] points: Signal<Vec<Point>>,
    #[prop(optional, into)] secondary: Signal<Vec<Point>>,
    #[prop(optional, into)] label: Signal<String>,
    #[prop(optional, into)] primary_label: Signal<String>,
    #[prop(optional, into)] secondary_label: Signal<String>,
    #[prop(optional, into)] stroke: Signal<String>,
    #[prop(optional, into)] fill: Signal<String>,
    #[prop(optional, into)] secondary_stroke: Signal<String>,
    #[prop(optional, into)] secondary_fill: Signal<String>,
    #[prop(optional, into)] value_format: Signal<ChartValueFormat>,
    #[prop(optional, into)] time_format: Signal<ChartTimeFormat>,
    #[prop(optional, into)] gap_threshold_x: Signal<Option<f64>>,
    #[prop(optional, into)] x_domain: Signal<Option<[f64; 2]>>,
    #[prop(default = 76.0)] height: f64,
    #[prop(default = true)] show_area: bool,
    #[prop(default = false)] show_references: bool,
    #[prop(default = false)] show_endpoints: bool,
    #[prop(default = false)] mini: bool,
) -> impl IntoView {
    let container = NodeRef::<leptos::html::Div>::new();
    let size = use_element_size(container, (280.0, height));
    let hover_x = RwSignal::new(None::<f64>);
    let plot_width = move || size.get().0.max(40.0);
    let plot_height = height.max(24.0);

    let domain = Memo::new(move |_| {
        points.with(|p| secondary.with(|s| effective_x_domain(p, s, x_domain.get())))
    });
    let scale = Memo::new(move |_| {
        let max_y = points.with(|p| {
            secondary.with(|s| {
                p.iter()
                    .chain(s.iter())
                    .filter(|pt| pt.x.is_finite() && pt.y.is_finite())
                    .map(|pt| pt.y)
                    .fold(0.0, f64::max)
            })
        });
        compute_value_scale(max_y, value_format.get())
    });
    let hovered = Memo::new(move |_| {
        let target = hover_x.get()?;
        let x_dom = domain.get()?;
        points
            .with(|p| secondary.with(|s| resolve_hover_snapshot(p, s, target, x_dom, plot_width())))
    });

    view! {
        <div class="w-full min-w-0 max-w-full select-none">
            <div class="flex gap-2 items-stretch min-w-0">
                <div
                    node_ref=container
                    class="relative flex-1 min-w-0"
                    on:mouseleave=move |_| hover_x.set(None)
                >
                    <svg
                        role="img"
                        aria-label=move || crate::primitives::ui_t(&label.get())
                        viewBox=move || format!("0 0 {:.1} {:.1}", plot_width(), plot_height)
                        height=plot_height
                        class="w-full block overflow-visible"
                        on:mousemove=move |event| {
                            if mini {
                                return;
                            }
                            if let (Some(node), Some(x_dom)) = (container.get(), domain.get()) {
                                let cursor_x = event.client_x() as f64 - node.get_bounding_client_rect().left();
                                hover_x.set(Some(target_x_for_cursor(cursor_x, plot_width(), x_dom)));
                            }
                        }
                    >
                        {move || {
                            let Some(x_dom) = domain.get() else {
                                return ().into_any();
                            };
                            let y_dom = scale.get().domain;
                            let w = plot_width();
                            let h = plot_height;
                            let gap = gap_threshold_x.get();
                            let p_stroke = {
                                let s = stroke.get();
                                if s.is_empty() { "var(--af-chart-stroke)".to_string() } else { s }
                            };
                            let p_fill = {
                                let f = fill.get();
                                if f.is_empty() { "var(--af-chart-area-fill)".to_string() } else { f }
                            };
                            let s_stroke = {
                                let s = secondary_stroke.get();
                                if s.is_empty() { "#6366f1".to_string() } else { s }
                            };
                            let s_fill = {
                                let f = secondary_fill.get();
                                if f.is_empty() { "rgba(99, 102, 241, 0.16)".to_string() } else { f }
                            };
                            let p_line = points.with(|pts| build_line_path_in_domain(pts, x_dom, y_dom, w, h, gap));
                            let p_area = if show_area {
                                points.with(|pts| build_area_path_in_domain(pts, x_dom, y_dom, w, h, gap))
                            } else {
                                String::new()
                            };
                            let s_line = secondary.with(|pts| build_line_path_in_domain(pts, x_dom, y_dom, w, h, gap));
                            let s_area = if show_area {
                                secondary.with(|pts| build_area_path_in_domain(pts, x_dom, y_dom, w, h, gap))
                            } else {
                                String::new()
                            };
                            let p_dots = points.with(|pts| visible_dots(pts, false, gap));
                            let s_dots = secondary.with(|pts| visible_dots(pts, false, gap));
                            let p_stroke_dot = p_stroke.clone();
                            let s_stroke_dot = s_stroke.clone();
                            view! {
                                <g>
                                    {(!s_area.is_empty()).then(|| view! { <path d=s_area fill=s_fill stroke="none"/> })}
                                    {(!p_area.is_empty()).then(|| view! { <path d=p_area fill=p_fill stroke="none"/> })}
                                    {(!s_line.is_empty()).then(|| view! {
                                        <path d=s_line fill="none" stroke=s_stroke stroke-width="2" vector-effect="non-scaling-stroke"/>
                                    })}
                                    {(!p_line.is_empty()).then(|| view! {
                                        <path d=p_line fill="none" stroke=p_stroke stroke-width="2" vector-effect="non-scaling-stroke"/>
                                    })}
                                    {s_dots.into_iter().map(|pt| {
                                        let cx = project_x(pt.x, x_dom, w);
                                        let cy = project_y(pt.y, y_dom, h);
                                        let color = s_stroke_dot.clone();
                                        view! { <circle cx=cx cy=cy r="3" fill=color/> }
                                    }).collect_view()}
                                    {p_dots.into_iter().map(|pt| {
                                        let cx = project_x(pt.x, x_dom, w);
                                        let cy = project_y(pt.y, y_dom, h);
                                        let color = p_stroke_dot.clone();
                                        view! { <circle cx=cx cy=cy r="3" fill=color/> }
                                    }).collect_view()}
                                    {hovered.get().map(|snap| {
                                        let cx = snap.crosshair_x;
                                        let p_circle = snap.primary.map(|pt| {
                                            let py = project_y(pt.y, y_dom, h);
                                            let color = p_stroke_dot.clone();
                                            view! { <circle cx=project_x(pt.x, x_dom, w) cy=py r="3.5" fill=color stroke="var(--obs-bg-primary, #0f172a)" stroke-width="1.5"/> }
                                        });
                                        let s_circle = snap.secondary.map(|pt| {
                                            let py = project_y(pt.y, y_dom, h);
                                            let color = s_stroke_dot.clone();
                                            view! { <circle cx=project_x(pt.x, x_dom, w) cy=py r="3.5" fill=color stroke="var(--obs-bg-primary, #0f172a)" stroke-width="1.5"/> }
                                        });
                                        view! {
                                            <g>
                                                <line x1=cx x2=cx y1="0" y2=h stroke="var(--af-chart-hover-stroke)" stroke-dasharray="3 3"/>
                                                {s_circle}
                                                {p_circle}
                                            </g>
                                        }
                                    })}
                                </g>
                            }.into_any()
                        }}
                    </svg>
                    {move || {
                        if mini {
                            return None;
                        }
                        let snap = hovered.get()?;
                        let x_dom = domain.get()?;
                        let locale = current_ui_locale();
                        let fmt = value_format.get();
                        let t_fmt = time_format.get();
                        let span_ms = (x_dom[1] - x_dom[0]).abs();
                        let time_str = format_chart_timestamp(snap.timestamp, t_fmt, span_ms, &locale);
                        let p_name = primary_label.get();
                        let s_name = secondary_label.get();
                        Some(view! {
                            <div role="tooltip" class="absolute top-1 right-1 z-20 rounded-lg af-chart-tooltip border px-2.5 py-1.5 text-xs pointer-events-none space-y-0.5 tabular-nums">
                                <div class="text-slate-400 font-mono">{time_str}</div>
                                {snap.primary.map(|pt| {
                                    let val = format_chart_value(pt.y, fmt, &locale);
                                    let name = if p_name.is_empty() { String::new() } else { format!("{}: ", crate::primitives::ui_t(&p_name)) };
                                    view! { <div class="font-semibold">{format!("{name}{val}")}</div> }
                                })}
                                {snap.secondary.map(|pt| {
                                    let val = format_chart_value(pt.y, fmt, &locale);
                                    let name = if s_name.is_empty() { String::new() } else { format!("{}: ", crate::primitives::ui_t(&s_name)) };
                                    view! { <div class="font-semibold">{format!("{name}{val}")}</div> }
                                })}
                            </div>
                        })
                    }}
                </div>
                {show_references.then(|| {
                    view! {
                        <div class="shrink-0 flex flex-col justify-between items-end text-[11px] font-mono text-slate-400 tabular-nums py-0.5 select-none">
                            <span>{move || {
                                let sc = scale.get();
                                let locale = current_ui_locale();
                                format_chart_axis_tick(sc.domain[1], sc.domain[1], value_format.get(), &locale)
                            }}</span>
                            <span>{move || {
                                let sc = scale.get();
                                let locale = current_ui_locale();
                                format_chart_axis_tick(sc.domain[1] / 2.0, sc.domain[1], value_format.get(), &locale)
                            }}</span>
                            <span>{move || {
                                let sc = scale.get();
                                let locale = current_ui_locale();
                                format_chart_axis_tick(0.0, sc.domain[1], value_format.get(), &locale)
                            }}</span>
                        </div>
                    }
                })}
            </div>
            {show_endpoints.then(|| {
                view! {
                    {move || domain.get().map(|x_dom| {
                        let locale = current_ui_locale();
                        let span_ms = (x_dom[1] - x_dom[0]).abs();
                        let t_fmt = time_format.get();
                        let start = format_short_axis_time(x_dom[0], t_fmt, span_ms, &locale);
                        let end = format_short_axis_time(x_dom[1], t_fmt, span_ms, &locale);
                        view! {
                            <div class="flex justify-between gap-2 text-[11px] font-mono text-slate-400 tabular-nums pt-1">
                                <span>{start}</span>
                                <span>{end}</span>
                            </div>
                        }
                    })}
                }
            })}
        </div>
    }
}

#[component]
pub fn AreaChart(
    #[prop(into)] points: Signal<Vec<Point>>,
    #[prop(optional, into)] label: Signal<String>,
    #[prop(optional, into)] secondary: Signal<Vec<Point>>,
    #[prop(optional, into)] primary_label: Signal<String>,
    #[prop(optional, into)] secondary_label: Signal<String>,
    #[prop(optional, into)] stroke: Signal<String>,
    #[prop(optional, into)] fill: Signal<String>,
    #[prop(optional, into)] secondary_stroke: Signal<String>,
    #[prop(optional, into)] secondary_fill: Signal<String>,
    #[prop(optional, into)] value_format: Signal<ChartValueFormat>,
    #[prop(optional, into)] time_format: Signal<ChartTimeFormat>,
    #[prop(optional, into)] gap_threshold_x: Signal<Option<f64>>,
    #[prop(optional, into)] x_domain: Signal<Option<[f64; 2]>>,
    #[prop(default = false)] show_dots: bool,
    #[prop(default = 240.0)] height: f64,
) -> impl IntoView {
    view! {
        <TelemetryChart
            points
            secondary
            label
            primary_label
            secondary_label
            stroke
            fill
            secondary_stroke
            secondary_fill
            value_format
            time_format
            gap_threshold_x
            x_domain
            show_dots
            height
            area=true
        />
    }
}

#[component]
pub fn LineChart(
    #[prop(into)] points: Signal<Vec<Point>>,
    #[prop(optional, into)] label: Signal<String>,
    #[prop(optional, into)] secondary: Signal<Vec<Point>>,
    #[prop(optional, into)] primary_label: Signal<String>,
    #[prop(optional, into)] secondary_label: Signal<String>,
    #[prop(optional, into)] stroke: Signal<String>,
    #[prop(optional, into)] fill: Signal<String>,
    #[prop(optional, into)] secondary_stroke: Signal<String>,
    #[prop(optional, into)] secondary_fill: Signal<String>,
    #[prop(optional, into)] value_format: Signal<ChartValueFormat>,
    #[prop(optional, into)] time_format: Signal<ChartTimeFormat>,
    #[prop(optional, into)] gap_threshold_x: Signal<Option<f64>>,
    #[prop(optional, into)] x_domain: Signal<Option<[f64; 2]>>,
    #[prop(default = false)] show_dots: bool,
    #[prop(default = 240.0)] height: f64,
) -> impl IntoView {
    view! {
        <TelemetryChart
            points
            secondary
            label
            primary_label
            secondary_label
            stroke
            fill
            secondary_stroke
            secondary_fill
            value_format
            time_format
            gap_threshold_x
            x_domain
            show_dots
            height
            area=false
        />
    }
}

#[component]
fn TelemetryChart(
    points: Signal<Vec<Point>>,
    secondary: Signal<Vec<Point>>,
    #[prop(optional, into)] label: Signal<String>,
    primary_label: Signal<String>,
    secondary_label: Signal<String>,
    stroke: Signal<String>,
    fill: Signal<String>,
    secondary_stroke: Signal<String>,
    secondary_fill: Signal<String>,
    value_format: Signal<ChartValueFormat>,
    time_format: Signal<ChartTimeFormat>,
    gap_threshold_x: Signal<Option<f64>>,
    x_domain: Signal<Option<[f64; 2]>>,
    show_dots: bool,
    height: f64,
    area: bool,
) -> impl IntoView {
    let container = NodeRef::<leptos::html::Div>::new();
    let svg_height = height.max(140.0);
    let plot_height = (svg_height - PLOT_TOP_PAD - PLOT_BOTTOM_PAD).max(60.0);
    let size = use_element_size(container, (800.0, svg_height));
    let hover_x = RwSignal::new(None::<f64>);
    let plot_width = move || (size.get().0 - PLOT_LEFT_PAD - PLOT_RIGHT_PAD).max(40.0);

    let domain = Memo::new(move |_| {
        points.with(|p| secondary.with(|s| effective_x_domain(p, s, x_domain.get())))
    });
    let scale = Memo::new(move |_| {
        let max_y = points.with(|p| {
            secondary.with(|s| {
                p.iter()
                    .chain(s.iter())
                    .filter(|pt| pt.x.is_finite() && pt.y.is_finite())
                    .map(|pt| pt.y)
                    .fold(0.0, f64::max)
            })
        });
        compute_value_scale(max_y, value_format.get())
    });
    let hovered = Memo::new(move |_| {
        let target = hover_x.get()?;
        let x_dom = domain.get()?;
        points
            .with(|p| secondary.with(|s| resolve_hover_snapshot(p, s, target, x_dom, plot_width())))
    });

    view! {
        <div
            node_ref=container
            class="relative min-w-0 max-w-full af-chart"
            on:mouseleave=move |_| hover_x.set(None)
        >
            <svg
                role="img"
                aria-label=move || crate::primitives::ui_t(&label.get())
                viewBox=move || format!("0 0 {:.1} {:.1}", size.get().0, svg_height)
                height=svg_height
                class="w-full block"
                on:mousemove=move |event| {
                    if let (Some(node), Some(x_dom)) = (container.get(), domain.get()) {
                        let cursor_x =
                            event.client_x() as f64 - node.get_bounding_client_rect().left() - PLOT_LEFT_PAD;
                        hover_x.set(Some(target_x_for_cursor(cursor_x, plot_width(), x_dom)));
                    }
                }
            >
                <g transform=format!("translate({PLOT_LEFT_PAD:.0},{PLOT_TOP_PAD:.0})")>
                    {move || {
                        let sc = scale.get();
                        let scale_max = sc.domain[1];
                        let w = plot_width();
                        let fmt = value_format.get();
                        let locale = current_ui_locale();
                        let intervals = sc.ticks.len().saturating_sub(1).max(1) as f64;
                        sc.ticks
                            .into_iter()
                            .enumerate()
                            .map(|(i, tick)| {
                                let y = plot_height - i as f64 * plot_height / intervals;
                                view! {
                                    <g>
                                        <line x1="0" x2=w y1=y y2=y stroke="var(--af-chart-grid)"/>
                                        <text x="-8" y=y + 4.0 text-anchor="end" fill="var(--af-chart-axis-text)" font-size="12">
                                            {format_chart_axis_tick(tick, scale_max, fmt, &locale)}
                                        </text>
                                    </g>
                                }
                            })
                            .collect_view()
                    }}
                    {move || {
                        let Some(x_dom) = domain.get() else {
                            return ().into_any();
                        };
                        let w = plot_width();
                        let span_ms = (x_dom[1] - x_dom[0]).abs();
                        let t_fmt = time_format.get();
                        let locale = current_ui_locale();
                        x_axis_ticks(x_dom, w)
                            .into_iter()
                            .map(|(x, ts, anchor)| {
                                let text = format_short_axis_time(ts, t_fmt, span_ms, &locale);
                                view! {
                                    <text x=x y=plot_height + 20.0 text-anchor=anchor fill="var(--af-chart-axis-text)" font-size="12">
                                        {text}
                                    </text>
                                }
                            })
                            .collect_view()
                            .into_any()
                    }}
                    {move || {
                        let Some(x_dom) = domain.get() else {
                            return view! {
                                <path class="recharts-area-curve af-wasm-area-curve" d="" fill="none" stroke="var(--af-chart-stroke)" stroke-width="2.5" vector-effect="non-scaling-stroke"/>
                            }.into_any();
                        };
                        let y_dom = scale.get().domain;
                        let w = plot_width();
                        let gap = gap_threshold_x.get();
                        let p_stroke = {
                            let s = stroke.get();
                            if s.is_empty() { "var(--af-chart-stroke)".to_string() } else { s }
                        };
                        let p_fill = {
                            let f = fill.get();
                            if f.is_empty() { "var(--af-chart-area-fill)".to_string() } else { f }
                        };
                        let s_stroke = {
                            let s = secondary_stroke.get();
                            if s.is_empty() { "#6366f1".to_string() } else { s }
                        };
                        let s_fill = {
                            let f = secondary_fill.get();
                            if f.is_empty() { "rgba(99, 102, 241, 0.16)".to_string() } else { f }
                        };
                        let p_line = points.with(|pts| build_line_path_in_domain(pts, x_dom, y_dom, w, plot_height, gap));
                        let p_area = if area {
                            points.with(|pts| build_area_path_in_domain(pts, x_dom, y_dom, w, plot_height, gap))
                        } else {
                            String::new()
                        };
                        let s_line = secondary.with(|pts| build_line_path_in_domain(pts, x_dom, y_dom, w, plot_height, gap));
                        let s_area = if area {
                            secondary.with(|pts| build_area_path_in_domain(pts, x_dom, y_dom, w, plot_height, gap))
                        } else {
                            String::new()
                        };
                        let p_dots = points.with(|pts| visible_dots(pts, show_dots, gap));
                        let s_dots = secondary.with(|pts| visible_dots(pts, show_dots, gap));
                        let p_stroke_dot = p_stroke.clone();
                        let s_stroke_dot = s_stroke.clone();
                        view! {
                            <g>
                                {(!s_area.is_empty()).then(|| view! { <path d=s_area fill=s_fill stroke="none"/> })}
                                {(!p_area.is_empty()).then(|| view! { <path d=p_area fill=p_fill stroke="none"/> })}
                                {(!s_line.is_empty()).then(|| view! {
                                    <path class="af-wasm-secondary-curve" d=s_line fill="none" stroke=s_stroke stroke-width="2.2" vector-effect="non-scaling-stroke"/>
                                })}
                                <path class="recharts-area-curve af-wasm-area-curve" d=p_line fill="none" stroke=p_stroke stroke-width="2.5" vector-effect="non-scaling-stroke"/>
                                {s_dots.into_iter().map(|pt| {
                                    let cx = project_x(pt.x, x_dom, w);
                                    let cy = project_y(pt.y, y_dom, plot_height);
                                    let color = s_stroke_dot.clone();
                                    view! { <circle cx=cx cy=cy r="3" fill=color/> }
                                }).collect_view()}
                                {p_dots.into_iter().map(|pt| {
                                    let cx = project_x(pt.x, x_dom, w);
                                    let cy = project_y(pt.y, y_dom, plot_height);
                                    let color = p_stroke_dot.clone();
                                    view! { <circle cx=cx cy=cy r="3" fill=color/> }
                                }).collect_view()}
                                {hovered.get().map(|snap| {
                                    let cx = snap.crosshair_x;
                                    let p_circle = snap.primary.map(|pt| {
                                        let color = p_stroke_dot.clone();
                                        view! { <circle cx=project_x(pt.x, x_dom, w) cy=project_y(pt.y, y_dom, plot_height) r="4.5" fill=color stroke="var(--obs-bg-primary, #0f172a)" stroke-width="1.5"/> }
                                    });
                                    let s_circle = snap.secondary.map(|pt| {
                                        let color = s_stroke_dot.clone();
                                        view! { <circle cx=project_x(pt.x, x_dom, w) cy=project_y(pt.y, y_dom, plot_height) r="4.5" fill=color stroke="var(--obs-bg-primary, #0f172a)" stroke-width="1.5"/> }
                                    });
                                    view! {
                                        <g>
                                            <line x1=cx x2=cx y1="0" y2=plot_height stroke="var(--af-chart-hover-stroke)" stroke-dasharray="4 4"/>
                                            {s_circle}
                                            {p_circle}
                                        </g>
                                    }
                                })}
                            </g>
                        }.into_any()
                    }}
                </g>
            </svg>
            {move || {
                let snap = hovered.get()?;
                let x_dom = domain.get()?;
                let locale = current_ui_locale();
                let fmt = value_format.get();
                let t_fmt = time_format.get();
                let span_ms = (x_dom[1] - x_dom[0]).abs();
                let time_str = format_chart_timestamp(snap.timestamp, t_fmt, span_ms, &locale);
                let p_name = primary_label.get();
                let s_name = secondary_label.get();
                let p_color = {
                    let s = stroke.get();
                    if s.is_empty() { "var(--af-chart-stroke)".to_string() } else { s }
                };
                let s_color = {
                    let s = secondary_stroke.get();
                    if s.is_empty() { "#6366f1".to_string() } else { s }
                };
                Some(view! {
                    <div role="tooltip" class="absolute top-2 right-3 z-20 rounded-lg af-chart-tooltip border px-3 py-2 text-xs pointer-events-none space-y-1 tabular-nums">
                        <div class="text-slate-400 font-mono">{time_str}</div>
                        {snap.primary.map(|pt| {
                            let val = format_chart_value(pt.y, fmt, &locale);
                            let name = if p_name.is_empty() { String::new() } else { format!("{}: ", crate::primitives::ui_t(&p_name)) };
                            view! {
                                <div class="flex items-center gap-1.5 font-semibold">
                                    <svg class="w-2 h-2 shrink-0" viewBox="0 0 8 8" aria-hidden="true"><circle cx="4" cy="4" r="4" fill=p_color/></svg>
                                    <span>{format!("{name}{val}")}</span>
                                </div>
                            }
                        })}
                        {snap.secondary.map(|pt| {
                            let val = format_chart_value(pt.y, fmt, &locale);
                            let name = if s_name.is_empty() { String::new() } else { format!("{}: ", crate::primitives::ui_t(&s_name)) };
                            view! {
                                <div class="flex items-center gap-1.5 font-semibold">
                                    <svg class="w-2 h-2 shrink-0" viewBox="0 0 8 8" aria-hidden="true"><circle cx="4" cy="4" r="4" fill=s_color/></svg>
                                    <span>{format!("{name}{val}")}</span>
                                </div>
                            }
                        })}
                    </div>
                })
            }}
        </div>
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use af_web_core::charts::{build_area_path, build_line_path};

    #[test]
    fn axis_tick_precision_keeps_low_and_high_range_labels_distinct() {
        for (max, expected) in [
            (0.25, ["0", "0.06", "0.12", "0.19", "0.25"]),
            (2.0, ["0", "0.5", "1.0", "1.5", "2.0"]),
            (100.0, ["0", "25", "50", "75", "100"]),
        ] {
            let labels: Vec<_> = (0..=4)
                .map(|step| {
                    format_chart_axis_tick(
                        max * step as f64 / 4.0,
                        max,
                        ChartValueFormat::Number,
                        "en",
                    )
                })
                .collect();
            assert_eq!(labels, expected);
            assert_eq!(
                labels
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len(),
                5
            );
        }
        assert_eq!(
            format_chart_axis_tick(-0.0, 0.25, ChartValueFormat::Number, "en"),
            "0"
        );
    }

    #[test]
    fn chart_svg_geometry_stays_finite_and_inside_the_component_viewbox() {
        assert!(build_sparkline_path(&[], 160.0, 38.0).is_empty());
        for data in [
            vec![5.0],
            vec![2.0, 8.0, 3.0],
            vec![f64::NAN, 4.0, f64::INFINITY],
        ] {
            let path = build_sparkline_path(&data, 160.0, 38.0);
            assert!(!path.is_empty());
            assert!(!path.contains("NaN"));
            assert!(!path.contains("inf"));
            let coords: Vec<_> = path
                .split_whitespace()
                .filter_map(|v| v.parse::<f64>().ok())
                .collect();
            for pair in coords.as_chunks::<2>().0 {
                assert!((0.0..=160.0).contains(&pair[0]));
                assert!((0.0..=38.0).contains(&pair[1]));
            }
        }
        let points = [Point { x: 0.0, y: 0.0 }, Point { x: 1.0, y: 10.0 }];
        assert_eq!(
            build_line_path(&points, 160.0, 38.0),
            "M 0.00 38.00 L 160.00 0.00"
        );
        assert!(build_area_path(&points, 160.0, 38.0).ends_with('Z'));
    }

    #[test]
    fn paired_hover_resolves_true_time_position_across_irregular_bursts() {
        let mut primary = vec![
            Point {
                x: 1_700_000_000_000.0,
                y: 100.0,
            },
            Point {
                x: 1_700_000_060_000.0,
                y: 200.0,
            },
            Point {
                x: 1_700_000_120_000.0,
                y: 300.0,
            },
        ];
        let mut secondary = vec![
            Point {
                x: 1_700_000_000_000.0,
                y: 50.0,
            },
            Point {
                x: 1_700_000_060_000.0,
                y: 80.0,
            },
            Point {
                x: 1_700_000_120_000.0,
                y: 90.0,
            },
        ];
        // Append a 1s live burst at the end.
        for s in 1..=8 {
            let ts = 1_700_000_120_000.0 + s as f64 * 1000.0;
            primary.push(Point {
                x: ts,
                y: 300.0 + s as f64,
            });
            secondary.push(Point {
                x: ts,
                y: 90.0 + s as f64,
            });
        }
        let x_dom = effective_x_domain(&primary, &secondary, None).unwrap();
        let target = target_x_for_cursor(500.0, 1000.0, x_dom); // ~64s into 128s span
        let snap = resolve_hover_snapshot(&primary, &secondary, target, x_dom, 1000.0).unwrap();
        assert_eq!(snap.timestamp, 1_700_000_060_000.0);
        assert_eq!(snap.primary.unwrap().y, 200.0);
        assert_eq!(snap.secondary.unwrap().y, 80.0);
        // Crosshair must sit at 60/128 * 1000 = 468.75 px, not at 5/10 * 1000 = 500 px.
        assert!((snap.crosshair_x - (60_000.0 / 128_000.0 * 1000.0)).abs() < 0.01);
    }

    #[test]
    fn isolated_points_around_gaps_receive_visible_dot_markers() {
        let points = [
            Point { x: 0.0, y: 1.0 },
            Point {
                x: 500_000.0,
                y: 5.0,
            },
            Point {
                x: 1_000_000.0,
                y: 2.0,
            },
        ];
        assert_eq!(visible_dots(&points, false, Some(120_000.0)).len(), 3);
        assert_eq!(visible_dots(&[points[0]], false, None).len(), 1);
    }
}
