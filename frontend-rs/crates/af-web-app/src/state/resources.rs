use super::session::app;
use af_web_core::api::{ApiClient, ApiError};
use futures::{
    channel::oneshot,
    future::{AbortHandle, AbortRegistration, Abortable},
};
use leptos::prelude::*;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::collections::BTreeMap;
use wasm_bindgen_futures::spawn_local;

/// Drop each old request future before its replacement can start transport.
struct ResourceRead {
    abort: AbortHandle,
    finished: oneshot::Receiver<()>,
}

#[derive(Default)]
pub(crate) struct ResourceReads(Option<ResourceRead>);

pub(crate) fn owned_resource_reads() -> StoredValue<ResourceReads, LocalStorage> {
    let reads = StoredValue::new_local(ResourceReads::default());
    on_cleanup(move || {
        let _ = reads.try_with_value(ResourceReads::cancel);
    });
    reads
}

pub(crate) struct ResourceReadJob {
    previous: Option<oneshot::Receiver<()>>,
    registration: AbortRegistration,
    finished: oneshot::Sender<()>,
}

impl ResourceReads {
    pub(crate) fn cancel(&self) {
        if let Some(read) = &self.0 {
            read.abort.abort();
        }
    }

    pub(crate) fn next(&mut self) -> ResourceReadJob {
        let previous = self.0.take().map(|read| {
            read.abort.abort();
            read.finished
        });
        let (abort, registration) = AbortHandle::new_pair();
        let (finished, receiver) = oneshot::channel();
        self.0 = Some(ResourceRead {
            abort,
            finished: receiver,
        });
        ResourceReadJob {
            previous,
            registration,
            finished,
        }
    }
}

pub(crate) async fn run_resource_read<F: std::future::Future>(
    job: ResourceReadJob,
    work: F,
) -> Option<F::Output> {
    // Keep this barrier even if the new generation is already canceled: its
    // replacement must still wait for every older request guard to drop.
    if let Some(previous) = job.previous {
        let _ = previous.await;
    }
    let result = Abortable::new(work, job.registration).await.ok();
    // The aborted future and its ApiClient transport guard have dropped before
    // completing the barrier, so a replacement cannot overlap obsolete work.
    drop(job.finished);
    result
}

/// Standard resource boundary for tab builders: cancellation-generation guard,
/// visible loading/error state and explicit revalidation without stale writes.
pub struct ApiResource<T: 'static = Value> {
    pub data: RwSignal<T>,
    pub loading: RwSignal<bool>,
    pub error: RwSignal<Option<ApiError>>,
    pub revision: RwSignal<u64>,
}
impl<T: 'static> Copy for ApiResource<T> {}
impl<T: 'static> Clone for ApiResource<T> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<T: 'static> ApiResource<T> {
    pub fn refresh(self) {
        self.revision.update(|v| *v += 1);
    }
    /// Publish an acknowledged mutation and synchronously invalidate older
    /// reads, including responses queued before the next reactive effect runs.
    pub fn commit(self, data: T)
    where
        T: Send + Sync,
    {
        self.refresh();
        self.data.set(data);
        self.error.set(None);
        self.loading.set(false);
    }
}
pub fn use_api(path: impl Into<Signal<String>>) -> ApiResource {
    use_api_typed::<Value>(path.into())
}

pub fn use_api_when(
    enabled: impl Into<Signal<bool>>,
    path: impl Into<Signal<String>>,
) -> ApiResource {
    use_api_typed_when::<Value>(enabled.into(), path.into())
}

/// Typed requests share the same loading, revalidation and stale-write guards
/// as JSON resources. Invalid responses keep the last good value and surface an
/// error, rather than passing a malformed domain object to a tab.
pub type TypedApiResource<T> = ApiResource<T>;

pub fn use_typed_api<T: DeserializeOwned + Default + Clone + Send + Sync + 'static>(
    path: impl Into<Signal<String>>,
) -> TypedApiResource<T> {
    use_api_typed(path.into())
}

pub fn use_api_typed<T: DeserializeOwned + Default + Clone + Send + Sync + 'static>(
    path: Signal<String>,
) -> ApiResource<T> {
    use_api_typed_when(Signal::stored(true), path)
}

pub fn use_api_typed_when<T: DeserializeOwned + Default + Clone + Send + Sync + 'static>(
    enabled: Signal<bool>,
    path: Signal<String>,
) -> ApiResource<T> {
    let context = app();
    let resource = ApiResource {
        data: RwSignal::new(T::default()),
        loading: RwSignal::new(enabled.get_untracked()),
        error: RwSignal::new(None),
        revision: RwSignal::new(0),
    };
    let generation = RwSignal::new(0u64);
    let reads = owned_resource_reads();
    let last_epoch = StoredValue::new(context.session_epoch.get_untracked());
    let last_server_epoch = StoredValue::new(context.server_epoch.get_untracked());
    let server_cache = StoredValue::new_local(BTreeMap::<(Option<String>, String), T>::new());
    Effect::new(move |_| {
        let epoch = context.session_epoch.get();
        let server_epoch = context.server_epoch.get();
        let active_server = context.active_server_id.get_untracked();
        let allowed = enabled.get();
        let path = path.get();
        if last_epoch.get_value() != epoch {
            let _ = server_cache.try_update_value(BTreeMap::clear);
            resource.data.set(T::default());
            resource.error.set(None);
            last_epoch.set_value(epoch);
            last_server_epoch.set_value(server_epoch);
        } else if last_server_epoch.get_value() != server_epoch {
            // Remote peers always revalidate fresh server data instead of
            // flashing potentially stale or revoked cached payloads on revisit.
            let cached = if allowed && active_server.is_none() {
                server_cache
                    .try_with_value(|cache| {
                        cache.get(&(active_server.clone(), path.clone())).cloned()
                    })
                    .flatten()
                    .unwrap_or_default()
            } else {
                T::default()
            };
            resource.data.set(cached);
            resource.error.set(None);
            last_server_epoch.set_value(server_epoch);
        }
        let requested_revision = resource.revision.get();
        generation.update(|g| *g += 1);
        let ticket = generation.get_untracked();
        if !allowed || path.trim().is_empty() {
            reads.with_value(ResourceReads::cancel);
            let _ = server_cache.try_update_value(|cache| {
                cache.remove(&(active_server.clone(), path.clone()));
            });
            resource.data.set(T::default());
            resource.error.set(None);
            resource.loading.set(false);
            return;
        }
        resource.loading.set(true);
        let Some(job) = reads.try_update_value(ResourceReads::next) else {
            return;
        };
        let cache_key = (active_server, path.clone());
        spawn_local(async move {
            let work = async move {
                if generation.try_get_untracked() != Some(ticket)
                    || resource.revision.try_get_untracked() != Some(requested_revision)
                    || context.session_epoch.try_get_untracked() != Some(epoch)
                    || context.server_epoch.try_get_untracked() != Some(server_epoch)
                    || enabled.try_get_untracked() != Some(true)
                {
                    return None;
                }
                Some(ApiClient.get_typed::<T>(&path).await)
            };
            let Some(Some(result)) = run_resource_read(job, work).await else {
                return;
            };
            if generation.try_get_untracked() != Some(ticket)
                || resource.revision.try_get_untracked() != Some(requested_revision)
                || enabled.try_get_untracked() != Some(true)
            {
                return;
            }
            if context.session_epoch.try_get_untracked() == Some(epoch)
                && context.server_epoch.try_get_untracked() == Some(server_epoch)
            {
                match result {
                    Ok(data) => {
                        let _ = server_cache.try_update_value(|cache| {
                            cache.insert(cache_key, data.clone());
                        });
                        resource.data.set(data);
                        resource.error.set(None);
                    }
                    Err(error) => {
                        if !matches!(error.code.as_deref(), Some("SERVER_CHANGED" | "ABORTED")) {
                            resource.error.set(Some(error));
                        }
                    }
                }
                resource.loading.set(false);
            }
        });
    });
    resource
}
pub fn json_rows(value: &Value) -> Vec<Value> {
    value
        .as_array()
        .cloned()
        .or_else(|| {
            [
                "items",
                "entries",
                "services",
                "data",
                "results",
                "notifications",
                "actions",
                "nodes",
                "users",
                "quotas",
            ]
            .iter()
            .find_map(|key| value[*key].as_array().cloned())
        })
        .unwrap_or_default()
}
