//! Release an operation's busy flag on completion, cancellation, or disposal.
use leptos::prelude::*;

pub(super) struct BusyGuard {
    busy: Option<RwSignal<bool>>,
    generation: Option<(RwSignal<u64>, u64)>,
}

impl BusyGuard {
    pub(super) fn new(busy: RwSignal<bool>) -> Self {
        Self {
            busy: Some(busy),
            generation: None,
        }
    }

    pub(super) fn for_generation(
        busy: RwSignal<bool>,
        generation: RwSignal<u64>,
        ticket: u64,
    ) -> Self {
        Self {
            busy: Some(busy),
            generation: Some((generation, ticket)),
        }
    }

    pub(super) fn release(&mut self) {
        if let Some(busy) = self.busy.take() {
            if self
                .generation
                .is_none_or(|(generation, ticket)| generation.try_get_untracked() == Some(ticket))
            {
                let _ = busy.try_update(|busy| *busy = false);
            }
        }
    }
}

impl Drop for BusyGuard {
    fn drop(&mut self) {
        self.release();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_editor_load_and_save_release_busy_without_touching_new_requests() {
        let owner = Owner::new();
        owner.with(|| {
            let generation = RwSignal::new(1);
            for busy in [RwSignal::new(true), RwSignal::new(true)] {
                drop(BusyGuard::for_generation(busy, generation, 1));
                assert!(!busy.get_untracked());
                busy.set(true);
                let stale = BusyGuard::for_generation(busy, generation, 1);
                generation.set(2);
                drop(stale);
                assert!(
                    busy.get_untracked(),
                    "old completion unlocked a new operation"
                );
                generation.set(1);
            }
        });
    }

    #[test]
    fn explicit_completion_and_disposal_are_safe() {
        let owner = Owner::new();
        let mut guard = owner.with(|| {
            let busy = RwSignal::new(true);
            let mut guard = BusyGuard::new(busy);
            guard.release();
            busy.set(true);
            drop(guard);
            assert!(
                busy.get_untracked(),
                "completion released a later operation twice"
            );
            BusyGuard::new(busy)
        });
        owner.cleanup();
        guard.release();
    }
}
