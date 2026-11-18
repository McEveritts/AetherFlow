use af_web_core::charts::{
    build_area_path, build_line_path, build_sparkline_path, nice_axis_ticks, Point,
};
use leptos::prelude::*;
use wasm_bindgen::{closure::Closure, JsCast};

fn format_axis_tick(tick: f64, scale_max: f64) -> String {
    if tick == 0.0 {
        "0".into()
    } else if scale_max < 0.5 {
        format!("{tick:.2}")
    } else if scale_max < 5.0 {
        format!("{tick:.1}")
    } else {
        format!("{tick:.0}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn axis_tick_precision_keeps_low_and_high_range_labels_distinct() {
        for (max, expected) in [
            (0.25, ["0", "0.06", "0.12", "0.19", "0.25"]),
            (2.0, ["0", "0.5", "1.0", "1.5", "2.0"]),
            (100.0, ["0", "25", "50", "75", "100"]),
        ] {
            let labels: Vec<_> = (0..=4)
                .map(|step| format_axis_tick(max * step as f64 / 4.0, max))
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
        assert_eq!(format_axis_tick(-0.0, 0.25), "0");
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
    view! {<svg viewBox="0 0 160 40" role="img" aria-label=move || crate::primitives::ui_t(&label.get()) class="w-full h-10" preserveAspectRatio="none"><path d=move||build_sparkline_path(&values.get(),160.0,38.0) fill="none" stroke="currentColor" stroke-width="2" vector-effect="non-scaling-stroke"/></svg>}
}
#[component]
pub fn AreaChart(
    #[prop(into)] points: Signal<Vec<Point>>,
    #[prop(optional, into)] label: Signal<String>,
) -> impl IntoView {
    view! {<TelemetryChart points label area=true/>}
}
#[component]
pub fn LineChart(
    #[prop(into)] points: Signal<Vec<Point>>,
    #[prop(optional, into)] label: Signal<String>,
) -> impl IntoView {
    view! {<TelemetryChart points label area=false/>}
}
#[component]
fn TelemetryChart(
    points: Signal<Vec<Point>>,
    #[prop(optional, into)] label: Signal<String>,
    area: bool,
) -> impl IntoView {
    let container = NodeRef::<leptos::html::Div>::new();
    let size = use_element_size(container, (800.0, 240.0));
    let hover = RwSignal::new(None::<usize>);
    let width = move || (size.get().0 - 64.0).max(40.0);
    let height = 192.0;
    view! {<div node_ref=container class="relative min-w-0 max-w-full h-60 af-chart" on:mouseleave=move|_|hover.set(None)>
        <svg role="img" aria-label=move || crate::primitives::ui_t(&label.get()) viewBox=move||format!("0 0 {} 240",size.get().0) class="w-full h-60" on:mousemove=move|event|{
            if let Some(node)=container.get(){let x=event.client_x()as f64-node.get_bounding_client_rect().left()-56.0;let len=points.with(Vec::len);if len>0{hover.set(Some(((x/width()).clamp(0.0,1.0)*(len-1)as f64).round()as usize));}}
        }>
            <g transform="translate(56,12)">
                {move||{let max=points.with(|p|p.iter().map(|p|p.y).fold(0.0,f64::max));let scale=nice_axis_ticks(max,4,false,1.0);let scale_max=scale.domain[1];scale.ticks.into_iter().enumerate().map(|(i,tick)|view!{<g><line x1="0" x2=width y1={height-i as f64*height/4.0} y2={height-i as f64*height/4.0} stroke="var(--af-chart-grid)"/><text x="-8" y={height-i as f64*height/4.0+4.0} text-anchor="end" fill="var(--af-chart-axis-text)" font-size="12">{format_axis_tick(tick,scale_max)}</text></g>}).collect_view()}}
                {area.then(||view!{<path d=move||build_area_path(&points.get(),width(),height) fill="var(--af-chart-area-fill)" stroke="none"/>})}
                <path class="recharts-area-curve af-wasm-area-curve" d=move||build_line_path(&points.get(),width(),height) fill="none" stroke="var(--af-chart-stroke)" stroke-width="2.5" vector-effect="non-scaling-stroke"/>
                {move||hover.get().map(|index|{let len=points.with(Vec::len);let x=if len>1{index as f64/(len-1)as f64*width()}else{0.0};view!{<line x1=x x2=x y1="0" y2=height stroke="var(--af-chart-hover-stroke)" stroke-dasharray="4 4"/>}})}
            </g>
        </svg>
        {move||hover.get().and_then(|index|points.with(|p|p.get(index).copied())).map(|point|view!{<div role="tooltip" class="absolute top-2 right-3 rounded-lg af-chart-tooltip border px-3 py-2 text-xs pointer-events-none">{format!("{} · {:.2}",point.x as i64,point.y)}</div>})}
    </div>}
}
