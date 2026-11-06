//! Reconcile process-local caches with terminal receipts written by another
//! lifecycle entrypoint. Inventory reads only invalidate memory; metadata
//! refresh runs separately from admission and dead-owner recovery.
use crate::{PackageJobOutcome, PackageJobSnapshot};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

#[derive(Default)]
struct Observation {
    seen: HashMap<String, PackageJobOutcome>,
    pending: HashMap<String, PackageJobOutcome>,
}

impl Observation {
    fn observe(&mut self, jobs: &PackageJobSnapshot) -> Vec<String> {
        let mut changed = Vec::new();
        for (package, outcome) in &jobs.outcomes {
            if self.seen.get(package) != Some(outcome) {
                self.seen.insert(package.clone(), outcome.clone());
                self.pending.insert(package.clone(), outcome.clone());
                changed.push(package.clone());
            }
        }
        changed
    }

    fn take_pending(&mut self, jobs: &PackageJobSnapshot) -> Vec<String> {
        std::mem::take(&mut self.pending)
            .into_iter()
            // An active replacement must finish before metadata is refreshed.
            .filter(|(package, outcome)| {
                !jobs.active.contains_key(package)
                    && jobs.outcomes.get(package) == Some(outcome)
                    && outcome.action != "remove"
            })
            .map(|(package, _)| package)
            .collect()
    }
}

static OBSERVATION: Lazy<Mutex<Observation>> = Lazy::new(|| Mutex::new(Observation::default()));

pub(crate) fn observe(jobs: &PackageJobSnapshot) {
    let changed = match OBSERVATION.lock() {
        Ok(mut state) => state.observe(jobs),
        Err(_) => return,
    };
    if changed.is_empty() {
        return;
    }
    af_db::invalidate_ingress_cache();
    crate::clear_service_status_cache();
    crate::mutators::clear_app_runtime_meta_cache();
    if let Ok(mut updates) = crate::workers::PACKAGE_UPDATE_CACHE.lock() {
        for package in changed {
            updates.remove(&package);
        }
    }
}

/// Kept separate from stale-owner reconciliation: upstream update checks must
/// never delay recovery of abandoned lifecycle reservations.
pub fn start_worker() {
    tokio::spawn(async {
        let mut ticker = tokio::time::interval(Duration::from_secs(15));
        loop {
            ticker.tick().await;
            let pending = tokio::task::spawn_blocking(|| -> anyhow::Result<Vec<String>> {
                let jobs = crate::package_job_snapshot()?;
                observe(&jobs);
                let mut state = OBSERVATION
                    .lock()
                    .map_err(|_| anyhow::anyhow!("lifecycle cache observer unavailable"))?;
                Ok(state.take_pending(&jobs))
            })
            .await;
            let packages = match pending {
                Ok(Ok(packages)) => packages,
                Ok(Err(error)) => {
                    tracing::warn!(%error, "lifecycle cache observation failed");
                    continue;
                }
                Err(error) => {
                    tracing::warn!(%error, "lifecycle cache observation task failed");
                    continue;
                }
            };
            // Sequential refreshes keep the remote query budget bounded. The
            // independent recovery worker continues while these await IO.
            for package in packages {
                let _ = crate::workers::refresh_package_update_by_id(&package).await;
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PackageJobInfo;

    fn terminal(id: &str, action: &str) -> PackageJobOutcome {
        PackageJobOutcome {
            job_id: id.into(),
            package_id: "fixture".into(),
            action: action.into(),
            status: "completed".into(),
            message: String::new(),
            started_at: "start".into(),
            finished_at: "finish".into(),
        }
    }

    #[test]
    fn external_terminal_refresh_is_once_and_replacement_aware() {
        let mut observer = Observation::default();
        let mut snapshot = PackageJobSnapshot::default();
        snapshot
            .outcomes
            .insert("fixture".into(), terminal("cli-1", "update"));
        assert_eq!(observer.observe(&snapshot), ["fixture"]);
        assert!(observer.observe(&snapshot).is_empty());
        assert_eq!(observer.take_pending(&snapshot), ["fixture"]);
        assert!(observer.take_pending(&snapshot).is_empty());
        snapshot
            .outcomes
            .insert("fixture".into(), terminal("cli-2", "remove"));
        assert_eq!(observer.observe(&snapshot), ["fixture"]);
        assert!(observer.take_pending(&snapshot).is_empty());
        snapshot
            .outcomes
            .insert("fixture".into(), terminal("cli-3", "install"));
        observer.observe(&snapshot);
        snapshot.active.insert(
            "fixture".into(),
            PackageJobInfo {
                package_id: "fixture".into(),
                job_id: "cli-4".into(),
                action: "update".into(),
                status: "updating".into(),
                started_at: "later".into(),
                progress: 5,
                last_line: String::new(),
            },
        );
        assert!(observer.take_pending(&snapshot).is_empty());
        snapshot.active.clear();
        snapshot
            .outcomes
            .insert("fixture".into(), terminal("cli-4", "update"));
        assert_eq!(observer.observe(&snapshot), ["fixture"]);
        assert_eq!(observer.take_pending(&snapshot), ["fixture"]);
    }
}
