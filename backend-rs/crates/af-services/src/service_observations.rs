use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar};

pub(super) const OBSERVATION_BUDGET: Duration = Duration::from_secs(3);
const SNAPSHOT_TTL: Duration = Duration::from_secs(3);
const MAX_PROBES: usize = 4;

#[derive(Clone, PartialEq, Eq)]
struct Plan {
    policies: Vec<ServiceComponentPolicy>,
    include_pm2: bool,
    metadata: Vec<String>,
}

#[derive(Clone, Default)]
pub(super) struct Observations {
    units: HashMap<String, (String, String)>,
    pm2: Option<HashMap<String, (String, String)>>,
    metadata: HashMap<String, mutators::AppRuntimeMeta>,
    metadata_epoch: u64,
}

impl Observations {
    pub(super) fn systemd(&self, policy: &ServiceComponentPolicy) -> (String, String) {
        self.units
            .get(&policy.unit)
            .cloned()
            .unwrap_or_else(unknown)
    }

    pub(super) fn pm2(&self, service: &str) -> (String, String) {
        self.pm2
            .as_ref()
            .map(|map| pm2_service_info_from_observations(map, service))
            .unwrap_or_else(unknown)
    }

    pub(super) fn runtime_meta(&self, app_name: &str) -> mutators::AppRuntimeMeta {
        if self.metadata_epoch != mutators::app_runtime_meta_epoch() {
            return mutators::AppRuntimeMeta::default();
        }
        self.metadata
            .get(&mutators::normalize_app_key_name(app_name))
            .cloned()
            .unwrap_or_else(|| mutators::cached_app_runtime_meta(app_name))
    }
}

fn unknown() -> (String, String) {
    ("unknown".into(), "-".into())
}

#[derive(Default)]
struct State {
    generation: u64,
    in_flight: bool,
    cached: Option<(Plan, Arc<Observations>, Instant)>,
    partial: Option<(Plan, Arc<Mutex<Observations>>)>,
}

static STATE: Lazy<(Mutex<State>, Condvar)> =
    Lazy::new(|| (Mutex::new(State::default()), Condvar::new()));

pub(super) fn invalidate() {
    let mut state = STATE.0.lock().unwrap_or_else(|error| error.into_inner());
    state.generation = state.generation.wrapping_add(1);
    state.cached = None;
    state.partial = None;
}

struct Flight;

impl Drop for Flight {
    fn drop(&mut self) {
        let mut state = STATE.0.lock().unwrap_or_else(|error| error.into_inner());
        state.in_flight = false;
        state.partial = None;
        STATE.1.notify_all();
    }
}

pub(super) fn collect(
    mut policies: Vec<ServiceComponentPolicy>,
    include_pm2: bool,
    metadata: Vec<String>,
    deadline: Instant,
) -> Arc<Observations> {
    let mut seen = std::collections::HashSet::new();
    policies.retain(|policy| seen.insert(policy.unit.clone()));
    let mut metadata: Vec<_> = metadata
        .into_iter()
        .map(|app_name| mutators::normalize_app_key_name(&app_name))
        .collect();
    metadata.sort();
    metadata.dedup();
    let plan = Plan {
        policies,
        include_pm2,
        metadata,
    };
    let mut state = STATE.0.lock().unwrap_or_else(|error| error.into_inner());
    loop {
        if let Some((cached_plan, observations, expires)) = &state.cached {
            if cached_plan == &plan && Instant::now() < *expires {
                return observations.clone();
            }
        }
        if !state.in_flight {
            break;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            if let Some((partial_plan, observations)) = &state.partial {
                if partial_plan == &plan {
                    return Arc::new(
                        observations
                            .lock()
                            .unwrap_or_else(|error| error.into_inner())
                            .clone(),
                    );
                }
            }
            return Arc::new(Observations::default());
        }
        state = STATE
            .1
            .wait_timeout(state, remaining)
            .unwrap_or_else(|error| error.into_inner())
            .0;
    }
    if Instant::now() >= deadline {
        return Arc::new(Observations::default());
    }
    state.in_flight = true;
    let generation = state.generation;
    let partial = Arc::new(Mutex::new(Observations {
        metadata_epoch: mutators::app_runtime_meta_epoch(),
        ..Observations::default()
    }));
    state.partial = Some((plan.clone(), partial.clone()));
    drop(state);
    let _flight = Flight;
    observe(
        &plan,
        deadline.min(Instant::now() + OBSERVATION_BUDGET),
        &partial,
    );
    let observations = Arc::new(
        partial
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone(),
    );
    let mut state = STATE.0.lock().unwrap_or_else(|error| error.into_inner());
    if state.generation == generation {
        state.cached = Some((plan, observations.clone(), Instant::now() + SNAPSHOT_TTL));
    }
    observations
}

fn observe(plan: &Plan, deadline: Instant, observations: &Mutex<Observations>) {
    let next = AtomicUsize::new(0);
    let status_count = plan.policies.len() + usize::from(plan.include_pm2);
    let count = status_count + plan.metadata.len();
    std::thread::scope(|scope| {
        for _ in 0..MAX_PROBES.min(count) {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= count {
                    break;
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    break;
                }
                let timeout = remaining.min(Duration::from_secs(2));
                if index >= status_count {
                    let app_name = &plan.metadata[index - status_count];
                    let value = mutators::get_app_runtime_meta_until(app_name, deadline);
                    observations
                        .lock()
                        .unwrap()
                        .metadata
                        .insert(app_name.clone(), value);
                } else if plan.include_pm2 && index == 0 {
                    let value = get_pm2_services_with_timeout(timeout).ok();
                    observations.lock().unwrap().pm2 = value;
                } else if let Some(policy) =
                    plan.policies.get(index - usize::from(plan.include_pm2))
                {
                    let value = query_systemd_unit_with_timeout(
                        &policy.unit,
                        policy.role,
                        policy.configured,
                        timeout,
                    );
                    observations
                        .lock()
                        .unwrap()
                        .units
                        .insert(policy.unit.clone(), value);
                }
            });
        }
    });
}
