use std::collections::BTreeSet;

pub enum ReservationTarget<'a> {
    Package(&'a str),
    Service(&'a str),
    System,
}

pub fn port_resource(port: i32) -> Option<String> {
    if (1..=65535).contains(&port) {
        Some(format!("port:{port}"))
    } else {
        None
    }
}

pub fn package_resources(package: &str, units: &[String]) -> BTreeSet<String> {
    std::iter::once(package)
        .chain(units.iter().map(String::as_str))
        .map(|unit| unit.trim().to_ascii_lowercase())
        .map(|unit| unit.trim_end_matches(".service").to_owned())
        .filter(|unit| !unit.is_empty())
        .collect()
}

pub fn is_timer_unit(unit: &str) -> bool {
    unit.trim().to_ascii_lowercase().ends_with(".timer")
}

pub fn is_socket_unit(unit: &str) -> bool {
    unit.trim().to_ascii_lowercase().ends_with(".socket")
}

pub fn is_activation_unit(unit: &str) -> bool {
    is_timer_unit(unit) || is_socket_unit(unit)
}

/// Companion units added in newer AetherFlow releases that may legitimately be
/// `LoadState=not-found` on pre-socket LibreSpeed or pre-companion noVNC hosts.
pub fn is_legacy_optional_companion_unit(unit: &str) -> bool {
    let lower = unit.trim().to_ascii_lowercase();
    lower == "librespeed.socket" || lower.trim_end_matches(".service") == "novnc-session"
}

/// Shared stop / quiesce priority tier (lower values stop FIRST).
///
/// 0: socket and timer activation units (`*.socket`, `*.timer`) stop before app
///    workers so incoming requests or timer ticks cannot reactivate a partially
///    replaced or removed service.
/// 1: frontend proxies that require companion services (`novnc`).
/// 2: standard application daemons and intermediate session units (`novnc-session`).
/// 3: underlying display/backend servers (`novnc-xvnc`).
pub fn unit_stop_order_key(unit: &str) -> u8 {
    let lower = unit.trim().to_ascii_lowercase();
    if lower.ends_with(".timer") || lower.ends_with(".socket") {
        0
    } else {
        match lower.trim_end_matches(".service") {
            "novnc" => 1,
            "novnc-session" => 2,
            "novnc-xvnc" => 3,
            _ => 2,
        }
    }
}

/// Shared start / restore / restart priority tier (lower values start FIRST).
///
/// 0: socket units (`*.socket`) and base display servers (`novnc-xvnc`) start
///    before workers that depend on them (`Requires=` / `BindsTo=`).
/// 1: intermediate companion units (`novnc-session`).
/// 2: standard application daemons and frontend proxies (`librespeed`, `novnc`).
/// 3: scheduled timer units (`*.timer`) start after daemons are running.
pub fn unit_start_order_key(unit: &str) -> u8 {
    let lower = unit.trim().to_ascii_lowercase();
    if lower.ends_with(".socket") {
        0
    } else if lower.ends_with(".timer") {
        3
    } else {
        match lower.trim_end_matches(".service") {
            "novnc-xvnc" => 0,
            "novnc-session" => 1,
            "novnc" => 2,
            _ => 2,
        }
    }
}

pub fn sort_units_for_stop(units: &mut [String]) {
    units.sort_by_key(|unit| unit_stop_order_key(unit));
}

pub fn sort_units_for_start(units: &mut [String]) {
    units.sort_by_key(|unit| unit_start_order_key(unit));
}

/// Orders a stop-ordered unit list for restoration/startup: reverses generic
/// ordering first, then applies dependency-aware start tiers so sockets and
/// base servers start before workers while timers start last.
pub fn ordered_units_for_start(stopped_order: &[String]) -> Vec<String> {
    let mut ordered: Vec<String> = stopped_order.iter().rev().cloned().collect();
    sort_units_for_start(&mut ordered);
    ordered
}
