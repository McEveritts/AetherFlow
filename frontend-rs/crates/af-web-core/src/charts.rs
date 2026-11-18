use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt::Write;

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Point {
    pub x: f64,
    pub y: f64,
}

#[derive(Clone, Debug)]
pub struct RingBuffer<T> {
    capacity: usize,
    points: VecDeque<T>,
}
impl<T> RingBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            points: VecDeque::with_capacity(capacity),
        }
    }
    pub fn push(&mut self, point: T) {
        if self.capacity == 0 {
            return;
        }
        if self.points.len() == self.capacity {
            self.points.pop_front();
        }
        self.points.push_back(point);
    }
    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.points.iter()
    }
    pub fn len(&self) -> usize {
        self.points.len()
    }
    pub fn is_empty(&self) -> bool {
        self.points.is_empty()
    }
    pub fn clear(&mut self) {
        self.points.clear();
    }
}

/// Largest Triangle Three Buckets, retaining first/last samples and peaks.
pub fn lttb(data: &[Point], threshold: usize) -> Vec<Point> {
    let data: Vec<Point> = data
        .iter()
        .copied()
        .filter(|p| p.x.is_finite() && p.y.is_finite())
        .collect();
    let n = data.len();
    if threshold == 0 {
        return vec![];
    }
    if threshold >= n {
        return data;
    }
    if threshold == 1 {
        return vec![data[0]];
    }
    if threshold == 2 {
        return vec![data[0], data[n - 1]];
    }
    let every = (n - 2) as f64 / (threshold - 2) as f64;
    let mut out = Vec::with_capacity(threshold);
    out.push(data[0]);
    let mut a = 0;
    for i in 0..threshold - 2 {
        let avg_start = (((i + 1) as f64 * every).floor() as usize + 1).min(n - 1);
        let avg_end = (((i + 2) as f64 * every).floor() as usize + 1)
            .min(n)
            .max(avg_start + 1);
        let count = (avg_end - avg_start) as f64;
        let avg = data[avg_start..avg_end]
            .iter()
            .fold(Point::default(), |sum, p| Point {
                x: sum.x + p.x / count,
                y: sum.y + p.y / count,
            });
        let start = (i as f64 * every).floor() as usize + 1;
        let end = (((i + 1) as f64 * every).floor() as usize + 1)
            .min(n - 1)
            .max(start + 1);
        let mut best = start;
        let mut max_area = -1.0;
        for j in start..end {
            let area = ((data[a].x - avg.x) * (data[j].y - data[a].y)
                - (data[a].x - data[j].x) * (avg.y - data[a].y))
                .abs();
            if area > max_area {
                max_area = area;
                best = j;
            }
        }
        out.push(data[best]);
        a = best;
    }
    out.push(data[n - 1]);
    out
}

#[derive(Clone, Debug, PartialEq)]
pub struct LinearScale {
    pub domain: [f64; 2],
    pub ticks: Vec<f64>,
}
pub fn nice_axis_ticks(
    data_max: f64,
    intervals: usize,
    integer_only: bool,
    min_ceiling: f64,
) -> LinearScale {
    let intervals = if intervals == 0 {
        4
    } else {
        intervals.min(100)
    };
    let ceiling = if data_max.is_finite() {
        data_max.max(0.0)
    } else {
        0.0
    }
    .max(if min_ceiling.is_finite() {
        min_ceiling.max(0.0)
    } else if integer_only {
        4.0
    } else {
        1.0
    });
    if ceiling == 0.0 {
        return LinearScale {
            domain: [0.0, intervals as f64],
            ticks: (0..=intervals).map(|v| v as f64).collect(),
        };
    }
    let raw_step = ceiling / intervals as f64;
    let power = 10f64.powf(raw_step.log10().floor());
    let fraction = raw_step / power;
    let factors: &[f64] = if integer_only {
        &[1.0, 2.0, 5.0, 10.0]
    } else {
        &[1.0, 2.0, 2.5, 5.0, 10.0]
    };
    let nice = factors
        .iter()
        .find(|v| fraction <= **v)
        .copied()
        .unwrap_or(10.0);
    let step = (nice * power).max(if integer_only { 1.0 } else { 0.0001 });
    let ticks = (0..=intervals)
        .map(|n| (n as f64 * step * 1_000_000.0).round() / 1_000_000.0)
        .collect();
    LinearScale {
        domain: [0.0, step * intervals as f64],
        ticks,
    }
}

pub fn scale_points(points: &[Point], width: f64, height: f64) -> Vec<Point> {
    let points: Vec<_> = points
        .iter()
        .filter(|p| p.x.is_finite() && p.y.is_finite())
        .collect();
    if points.is_empty()
        || !width.is_finite()
        || !height.is_finite()
        || width <= 0.0
        || height <= 0.0
    {
        return vec![];
    }
    let xmin = points.iter().map(|p| p.x).fold(f64::INFINITY, f64::min);
    let xmax = points.iter().map(|p| p.x).fold(f64::NEG_INFINITY, f64::max);
    let ymin = points.iter().map(|p| p.y).fold(0.0, f64::min);
    let ymax = nice_axis_ticks(
        points.iter().map(|p| p.y).fold(0.0, f64::max),
        4,
        false,
        1.0,
    )
    .domain[1];
    points
        .iter()
        .map(|p| Point {
            x: if xmax == xmin {
                width / 2.0
            } else {
                (p.x - xmin) / (xmax - xmin) * width
            },
            y: height - (p.y - ymin) / (ymax - ymin) * height,
        })
        .collect()
}
pub fn build_line_path(points: &[Point], width: f64, height: f64) -> String {
    let mut path = String::new();
    for (i, p) in scale_points(points, width, height).iter().enumerate() {
        let _ = write!(
            path,
            "{} {:.2} {:.2} ",
            if i == 0 { "M" } else { "L" },
            p.x,
            p.y
        );
    }
    path.trim_end().to_string()
}
pub fn build_area_path(points: &[Point], width: f64, height: f64) -> String {
    let path = build_line_path(points, width, height);
    let scaled = scale_points(points, width, height);
    match (scaled.first(), scaled.last()) {
        (Some(first), Some(last)) => format!(
            "{path} L {:.2} {height:.2} L {:.2} {height:.2} Z",
            last.x, first.x
        ),
        _ => String::new(),
    }
}
pub fn build_sparkline_path(values: &[f64], width: f64, height: f64) -> String {
    build_line_path(
        &values
            .iter()
            .enumerate()
            .map(|(i, v)| Point { x: i as f64, y: *v })
            .collect::<Vec<_>>(),
        width,
        height,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ring_eviction_and_zero_capacity() {
        let mut ring = RingBuffer::new(2);
        for i in 0..4 {
            ring.push(i);
        }
        assert_eq!(ring.iter().copied().collect::<Vec<_>>(), vec![2, 3]);
        ring.clear();
        assert!(ring.is_empty());
        let mut empty = RingBuffer::new(0);
        empty.push(1);
        assert_eq!(empty.len(), 0);
    }
    #[test]
    fn lttb_preserves_endpoints_and_spike() {
        let points: Vec<_> = (0..100)
            .map(|x| Point {
                x: x as f64,
                y: if x == 51 { 100.0 } else { 0.0 },
            })
            .collect();
        let reduced = lttb(&points, 10);
        assert_eq!(reduced.len(), 10);
        assert_eq!(reduced[0], points[0]);
        assert_eq!(reduced[9], points[99]);
        assert!(reduced.iter().any(|p| p.y == 100.0));
    }
    #[test]
    fn lttb_handles_small_budgets_and_nonfinite_points() {
        let points = [
            Point { x: 0.0, y: 1.0 },
            Point {
                x: 1.0,
                y: f64::NAN,
            },
            Point { x: 2.0, y: 2.0 },
        ];
        assert!(lttb(&points, 0).is_empty());
        assert_eq!(lttb(&points, 1).len(), 1);
        assert_eq!(lttb(&points, 2).len(), 2);
        assert_eq!(lttb(&[], 10), vec![]);
    }
    #[test]
    fn paths_are_finite_and_area_closes() {
        let points = [Point { x: 1.0, y: 4.0 }, Point { x: 2.0, y: 8.0 }];
        assert!(build_area_path(&points, 200.0, 100.0).ends_with('Z'));
        assert!(build_line_path(&points, 200.0, 100.0).starts_with("M"));
        assert!(!build_sparkline_path(&[f64::NAN, 2.0], 20.0, 10.0).contains("NaN"));
        assert!(build_line_path(&[], 2.0, 2.0).is_empty());
    }
    #[test]
    fn nice_scale_matches_streaming_chart_steps() {
        assert_eq!(
            nice_axis_ticks(9.0, 4, false, 1.0).ticks,
            vec![0.0, 2.5, 5.0, 7.5, 10.0]
        );
        assert_eq!(
            nice_axis_ticks(1.0, 4, true, 4.0).ticks,
            vec![0.0, 1.0, 2.0, 3.0, 4.0]
        );
        assert_eq!(nice_axis_ticks(f64::NAN, 4, false, 0.0).domain, [0.0, 4.0]);
        assert!(nice_axis_ticks(1234.0, 4, false, 1.0).domain[1] >= 1234.0);
    }
}
