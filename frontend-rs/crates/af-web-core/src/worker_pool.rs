//! Lazy shared worker router. Failed slots retry with bounded backoff; transport
//! errors and timeouts fall back to the same Rust algorithms.
#[cfg(any(target_arch = "wasm32", test))]
const MAX_RETRIES: u32 = 3;
#[cfg(any(target_arch = "wasm32", test))]
#[derive(Clone, Copy, Debug, Default)]
struct SlotRetry {
    failures: u32,
    next_retry_ms: f64,
}
#[cfg(any(target_arch = "wasm32", test))]
impl SlotRetry {
    fn can_retry(self, now: f64) -> bool {
        self.failures <= MAX_RETRIES && now >= self.next_retry_ms
    }
    fn fail_at(&mut self, now: f64) {
        self.failures = self.failures.saturating_add(1).min(MAX_RETRIES + 1);
        self.next_retry_ms = now + 1_000.0 * (1u32 << self.failures) as f64;
    }
    pub fn succeeded(&mut self) {
        self.failures = 0;
    }
    fn fail_once(&mut self, failed: &std::cell::Cell<bool>, now: f64) -> bool {
        if failed.replace(true) {
            return false;
        }
        self.fail_at(now);
        true
    }
}
#[cfg(any(target_arch = "wasm32", test))]
struct PendingEntry<T, R> {
    worker_slot: usize,
    request: R,
    sender: T,
}
#[cfg(any(target_arch = "wasm32", test))]
fn drain_slot<T, R>(
    pending: &mut std::collections::BTreeMap<u64, PendingEntry<T, R>>,
    idx: usize,
) -> Vec<PendingEntry<T, R>> {
    let ids: Vec<_> = pending
        .iter()
        .filter_map(|(id, job)| (job.worker_slot == idx).then_some(*id))
        .collect();
    ids.into_iter()
        .filter_map(|id| pending.remove(&id))
        .collect()
}
#[cfg(target_arch = "wasm32")]
mod browser {
    use super::{drain_slot, PendingEntry, SlotRetry};
    use crate::worker::{execute_worker_request, WorkerEnvelope, WorkerRequest, WorkerResponse};
    use futures::{
        channel::oneshot,
        future::{select, Either, LocalBoxFuture, Shared},
        FutureExt,
    };
    use std::{
        cell::{Cell, RefCell},
        collections::BTreeMap,
        rc::Rc,
    };
    use wasm_bindgen::{closure::Closure, JsCast, JsValue};
    use wasm_bindgen_futures::{spawn_local, JsFuture};

    enum PendingRequest {
        Request(WorkerRequest),
        // Keep the immutable source for fallback without copying transferable
        // Blob bytes into WASM unless the worker actually fails.
        Blob(web_sys::Blob),
    }
    type Pending = BTreeMap<u64, PendingEntry<oneshot::Sender<WorkerResponse>, PendingRequest>>;
    #[derive(Clone)]
    struct SlotHandle {
        idx: usize,
        worker: web_sys::Worker,
        ready: Shared<LocalBoxFuture<'static, bool>>,
        failed: Rc<Cell<bool>>,
    }
    struct Slot {
        handle: SlotHandle,
        _message: Closure<dyn FnMut(web_sys::MessageEvent)>,
        _error: Closure<dyn FnMut(web_sys::Event)>,
        _message_error: Closure<dyn FnMut(web_sys::Event)>,
    }
    impl Drop for Slot {
        fn drop(&mut self) {
            self.handle.worker.set_onmessage(None);
            self.handle.worker.set_onerror(None);
            self.handle.worker.set_onmessageerror(None);
            self.handle.worker.terminate();
        }
    }
    struct Inner {
        slots: RefCell<Vec<Option<Slot>>>,
        retries: Vec<Rc<Cell<SlotRetry>>>,
        pending: Rc<RefCell<Pending>>,
        next: Cell<u64>,
        cursor: Cell<usize>,
    }
    impl Drop for Inner {
        fn drop(&mut self) {
            for slot in self.slots.get_mut().iter().flatten() {
                slot.handle.worker.terminate();
            }
            self.pending.borrow_mut().clear();
        }
    }
    #[derive(Clone)]
    pub struct WorkerPool {
        inner: Rc<Inner>,
    }
    impl Default for WorkerPool {
        fn default() -> Self {
            Self::shared()
        }
    }
    fn transfer_message(
        id: u64,
        kind: &str,
        field: &str,
        payload: &JsValue,
        transfer: js_sys::Array,
    ) -> Result<(JsValue, Option<js_sys::Array>), JsValue> {
        let value = js_sys::Object::new();
        js_sys::Reflect::set(&value, &"id".into(), &JsValue::from_f64(id as f64))?;
        js_sys::Reflect::set(&value, &"type".into(), &kind.into())?;
        js_sys::Reflect::set(&value, &field.into(), payload)?;
        Ok((value.into(), Some(transfer)))
    }
    async fn blob_buffer(blob: &web_sys::Blob) -> Result<js_sys::ArrayBuffer, String> {
        JsFuture::from(blob.array_buffer())
            .await
            .map_err(|_| "Unable to read Blob ArrayBuffer".to_string())?
            .dyn_into::<js_sys::ArrayBuffer>()
            .map_err(|_| "Invalid Blob ArrayBuffer".into())
    }
    impl WorkerPool {
        pub fn shared() -> Self {
            thread_local! {
                static SHARED: RefCell<Option<WorkerPool>> = const { RefCell::new(None) };
            }
            SHARED.with(|slot| {
                slot.borrow_mut()
                    .get_or_insert_with(|| {
                        let concurrency = web_sys::window()
                            .map(|w| w.navigator().hardware_concurrency() as usize)
                            .unwrap_or(2)
                            .clamp(1, 4);
                        Self::new(concurrency)
                    })
                    .clone()
            })
        }
        /// Construction never starts workers, including on public login routes.
        pub fn new(size: usize) -> Self {
            let size = size.clamp(1, 4);
            Self {
                inner: Rc::new(Inner {
                    slots: RefCell::new((0..size).map(|_| None).collect()),
                    retries: (0..size)
                        .map(|_| Rc::new(Cell::new(SlotRetry::default())))
                        .collect(),
                    pending: Rc::new(RefCell::new(Pending::new())),
                    next: Cell::new(1),
                    cursor: Cell::new(0),
                }),
            }
        }
        fn spawn_slot(&self, idx: usize, url: &str) -> Option<Slot> {
            let options = web_sys::WorkerOptions::new();
            options.set_type(web_sys::WorkerType::Module);
            let worker = match web_sys::Worker::new_with_options(url, &options) {
                Ok(worker) => worker,
                Err(_) => {
                    let mut retry = self.inner.retries[idx].get();
                    retry.fail_at(js_sys::Date::now());
                    self.inner.retries[idx].set(retry);
                    self.schedule_retry(idx, None);
                    return None;
                }
            };
            let failed = Rc::new(Cell::new(false));
            let (ready_sender, ready_receiver) = oneshot::channel::<bool>();
            let ready_sender = Rc::new(RefCell::new(Some(ready_sender)));
            let ready = async move {
                matches!(
                    select(
                        ready_receiver,
                        Box::pin(gloo_timers::future::TimeoutFuture::new(5000))
                    )
                    .await,
                    Either::Left((Ok(true), _))
                )
            }
            .boxed_local()
            .shared();
            let handle = SlotHandle {
                idx,
                worker: worker.clone(),
                ready,
                failed: failed.clone(),
            };
            let startup = ready_sender.clone();
            let jobs = self.inner.pending.clone();
            let inner = Rc::downgrade(&self.inner);
            let message_handle = handle.clone();
            let message = Closure::new(move |event: web_sys::MessageEvent| {
                let Some(inner) = inner.upgrade() else {
                    return;
                };
                let pool = WorkerPool { inner };
                if message_handle.failed.get() || !pool.is_current(&message_handle) {
                    return;
                }
                if event.data().as_string().as_deref() == Some("af-worker-ready") {
                    let mut retry = pool.inner.retries[idx].get();
                    retry.succeeded();
                    pool.inner.retries[idx].set(retry);
                    if let Some(sender) = startup.borrow_mut().take() {
                        let _ = sender.send(true);
                    }
                    return;
                }
                if let Ok(response) =
                    serde_wasm_bindgen::from_value::<WorkerEnvelope<WorkerResponse>>(event.data())
                {
                    let mut retry = pool.inner.retries[idx].get();
                    retry.succeeded();
                    pool.inner.retries[idx].set(retry);
                    let mut jobs = jobs.borrow_mut();
                    if jobs
                        .get(&response.id)
                        .is_some_and(|job| job.worker_slot == idx)
                    {
                        if let Some(job) = jobs.remove(&response.id) {
                            let _ = job.sender.send(response.message);
                        }
                    }
                }
            });
            let fault_handler = || {
                let inner = Rc::downgrade(&self.inner);
                let handle = handle.clone();
                let startup = ready_sender.clone();
                Closure::new(move |_: web_sys::Event| {
                    if let Some(sender) = startup.borrow_mut().take() {
                        let _ = sender.send(false);
                    }
                    if let Some(inner) = inner.upgrade() {
                        WorkerPool { inner }.fail_slot(&handle);
                    }
                })
            };
            let error = fault_handler();
            let message_error = fault_handler();
            worker.set_onmessage(Some(message.as_ref().unchecked_ref()));
            worker.set_onerror(Some(error.as_ref().unchecked_ref()));
            worker.set_onmessageerror(Some(message_error.as_ref().unchecked_ref()));
            Some(Slot {
                handle,
                _message: message,
                _error: error,
                _message_error: message_error,
            })
        }
        fn prepare_slots(&self) {
            let url = web_sys::window()
                .and_then(|w| w.document())
                .and_then(|d| {
                    d.query_selector("meta[name='af-worker-url']")
                        .ok()
                        .flatten()
                })
                .and_then(|m| m.get_attribute("content"));
            for idx in 0..self.inner.retries.len() {
                let failed = self.inner.slots.borrow()[idx]
                    .as_ref()
                    .filter(|slot| slot.handle.failed.get())
                    .map(|slot| slot.handle.clone());
                if let Some(handle) = failed {
                    self.fail_slot(&handle);
                    self.inner.slots.borrow_mut()[idx].take();
                }
                if self.inner.slots.borrow()[idx].is_none()
                    && self.inner.retries[idx].get().can_retry(js_sys::Date::now())
                {
                    if let Some(url) = &url {
                        let slot = self.spawn_slot(idx, url);
                        self.inner.slots.borrow_mut()[idx] = slot;
                    }
                }
            }
        }
        fn select_slot(&self) -> Option<SlotHandle> {
            let slots = self.inner.slots.borrow();
            (0..slots.len()).find_map(|offset| {
                let idx = (self.inner.cursor.get() + offset) % slots.len();
                let slot = slots[idx].as_ref()?;
                if slot.handle.failed.get() {
                    return None;
                }
                self.inner.cursor.set((idx + 1) % slots.len());
                Some(slot.handle.clone())
            })
        }
        pub fn is_in_process(&self) -> bool {
            self.inner
                .slots
                .borrow()
                .iter()
                .all(|slot| slot.as_ref().is_none_or(|slot| slot.handle.failed.get()))
        }
        fn is_current(&self, handle: &SlotHandle) -> bool {
            // A late timeout from an earlier incarnation must never kill a respawn.
            self.inner.slots.borrow()[handle.idx]
                .as_ref()
                .is_some_and(|slot| Rc::ptr_eq(&slot.handle.failed, &handle.failed))
        }
        fn schedule_retry(&self, idx: usize, incarnation: Option<Rc<Cell<bool>>>) {
            let retry = self.inner.retries[idx].get();
            if retry.failures > super::MAX_RETRIES {
                return;
            }
            let delay = (retry.next_retry_ms - js_sys::Date::now()).max(0.0).ceil() as u32;
            let inner = Rc::downgrade(&self.inner);
            spawn_local(async move {
                gloo_timers::future::TimeoutFuture::new(delay).await;
                let Some(inner) = inner.upgrade() else {
                    return;
                };
                let pool = WorkerPool { inner };
                let matches = match (&pool.inner.slots.borrow()[idx], incarnation) {
                    (Some(slot), Some(failed)) => Rc::ptr_eq(&slot.handle.failed, &failed),
                    (None, _) => true,
                    _ => false,
                };
                if matches {
                    pool.prepare_slots();
                }
            });
        }
        fn fail_slot(&self, handle: &SlotHandle) {
            if !self.is_current(handle) {
                return;
            }
            let mut retry = self.inner.retries[handle.idx].get();
            let newly_failed = retry.fail_once(&handle.failed, js_sys::Date::now());
            self.inner.retries[handle.idx].set(retry);
            handle.worker.terminate();
            let jobs = drain_slot(&mut self.inner.pending.borrow_mut(), handle.idx);
            for job in jobs {
                match job.request {
                    PendingRequest::Request(request) => {
                        let _ = job.sender.send(execute_worker_request(request));
                    }
                    PendingRequest::Blob(blob) => spawn_local(async move {
                        let response = match blob_buffer(&blob).await {
                            Ok(buffer) => execute_worker_request(WorkerRequest::Sha256Chunk {
                                bytes: js_sys::Uint8Array::new(&buffer).to_vec(),
                            }),
                            Err(message) => WorkerResponse::Error { message },
                        };
                        let _ = job.sender.send(response);
                    }),
                }
            }
            if newly_failed {
                // Keep the executing event Closure alive until the next task;
                // prepare_slots removes it before respawning this incarnation.
                self.schedule_retry(handle.idx, Some(handle.failed.clone()));
            }
        }
        async fn call_slot(
            &self,
            handle: SlotHandle,
            request: PendingRequest,
            message: impl FnOnce(u64) -> Result<(JsValue, Option<js_sys::Array>), JsValue>,
        ) -> Option<WorkerResponse> {
            if !handle.ready.clone().await || handle.failed.get() {
                self.fail_slot(&handle);
                return None;
            }
            let id = self.inner.next.get();
            self.inner.next.set(id.wrapping_add(1));
            let (sender, receiver) = oneshot::channel();
            self.inner.pending.borrow_mut().insert(
                id,
                PendingEntry {
                    worker_slot: handle.idx,
                    request,
                    sender,
                },
            );
            let posted = message(id).and_then(|(value, transfer)| match transfer {
                Some(transfer) => handle.worker.post_message_with_transfer(&value, &transfer),
                None => handle.worker.post_message(&value),
            });
            if posted.is_ok() {
                let timeout = gloo_timers::future::TimeoutFuture::new(15_000);
                if let Either::Left((Ok(response), _)) = select(receiver, Box::pin(timeout)).await {
                    return Some(response);
                }
            }
            self.inner.pending.borrow_mut().remove(&id);
            self.fail_slot(&handle);
            None
        }
        pub async fn execute(&self, request: WorkerRequest) -> WorkerResponse {
            self.prepare_slots();
            for _ in 0..self.inner.retries.len() {
                let Some(handle) = self.select_slot() else {
                    break;
                };
                let response =
                    self.call_slot(handle, PendingRequest::Request(request.clone()), |id| {
                        match &request {
                            WorkerRequest::Sha256Chunk { bytes } => {
                                let buffer = js_sys::Uint8Array::from(bytes.as_slice()).buffer();
                                let transfer = js_sys::Array::new();
                                transfer.push(&buffer);
                                transfer_message(
                                    id,
                                    "Sha256ChunkTransfer",
                                    "buffer",
                                    &buffer,
                                    transfer,
                                )
                            }
                            WorkerRequest::Sha256Batch { chunks } => {
                                let buffers = js_sys::Array::new();
                                let transfer = js_sys::Array::new();
                                for chunk in chunks {
                                    let buffer =
                                        js_sys::Uint8Array::from(chunk.as_slice()).buffer();
                                    buffers.push(&buffer);
                                    transfer.push(&buffer);
                                }
                                transfer_message(
                                    id,
                                    "Sha256BatchTransfer",
                                    "buffers",
                                    &buffers,
                                    transfer,
                                )
                            }
                            _ => serde_wasm_bindgen::to_value(&WorkerEnvelope {
                                id,
                                message: &request,
                            })
                            .map(|value| (value, None))
                            .map_err(|error| JsValue::from_str(&error.to_string())),
                        }
                    })
                    .await;
                if let Some(response) = response {
                    return response;
                }
            }
            execute_worker_request(request)
        }
        pub async fn sha256_chunk(&self, bytes: &[u8]) -> Result<String, String> {
            match self
                .execute(WorkerRequest::Sha256Chunk {
                    bytes: bytes.to_vec(),
                })
                .await
            {
                WorkerResponse::Hash { hex } => Ok(hex),
                WorkerResponse::Error { message } => Err(message),
                _ => Err("Unexpected hash worker response".into()),
            }
        }
        /// Blob bytes stay in JS memory until transferred to the worker. Only the
        /// final in-process fallback copies the bytes into WASM linear memory.
        pub async fn sha256_blob(&self, blob: &web_sys::Blob) -> Result<String, String> {
            self.prepare_slots();
            let mut buffer = blob_buffer(blob).await?;
            for _ in 0..self.inner.retries.len() {
                let Some(handle) = self.select_slot() else {
                    break;
                };
                let response = self
                    .call_slot(handle.clone(), PendingRequest::Blob(blob.clone()), |id| {
                        let transfer = js_sys::Array::new();
                        transfer.push(&buffer);
                        transfer_message(id, "Sha256ChunkTransfer", "buffer", &buffer, transfer)
                    })
                    .await;
                if let Some(WorkerResponse::Hash { hex }) = response {
                    return Ok(hex);
                }
                self.fail_slot(&handle);
                // A posted buffer is detached even if its worker later crashes,
                // including a zero-byte buffer. Re-read the immutable Blob before
                // retrying or hashing locally; byte_length cannot detect that case.
                buffer = blob_buffer(blob).await?;
            }
            let bytes = js_sys::Uint8Array::new(&buffer).to_vec();
            Ok(crate::worker::sha256_hex(&bytes))
        }
    }
}
#[cfg(target_arch = "wasm32")]
pub use browser::*;
#[cfg(not(target_arch = "wasm32"))]
#[derive(Clone, Copy, Default)]
pub struct WorkerPool;
#[cfg(not(target_arch = "wasm32"))]
impl WorkerPool {
    pub fn shared() -> Self {
        Self
    }
    pub fn new(_size: usize) -> Self {
        Self
    }
    pub fn is_in_process(&self) -> bool {
        true
    }
    pub async fn execute(&self, request: crate::WorkerRequest) -> crate::WorkerResponse {
        crate::worker::execute_worker_request(request)
    }
    pub async fn sha256_chunk(&self, bytes: &[u8]) -> Result<String, String> {
        Ok(crate::worker::sha256_hex(bytes))
    }
    pub async fn sha256_blob(&self, blob: &web_sys::Blob) -> Result<String, String> {
        let _ = blob;
        Err("Browser Blob unavailable on host".into())
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    #[test]
    fn healthy_responses_reset_consecutive_worker_failures() {
        let mut retry = SlotRetry::default();
        let mut now = 0.0;
        for _ in 0..20 {
            for failure in 1..=MAX_RETRIES {
                retry.fail_at(now);
                assert_eq!(retry.failures, failure);
                now = retry.next_retry_ms;
                assert!(retry.can_retry(now));
            }
            retry.succeeded();
            assert_eq!(retry.failures, 0);
            assert!(retry.can_retry(now));
        }
        for _ in 0..=MAX_RETRIES {
            retry.fail_at(now);
            now = retry.next_retry_ms;
        }
        assert_eq!(retry.failures, MAX_RETRIES + 1);
        assert!(!retry.can_retry(f64::MAX));
    }
    #[test]
    fn dead_slots_respawn_only_after_exponential_backoff_and_stop_after_four_failures() {
        let mut retry = SlotRetry::default();
        assert!(
            retry.can_retry(0.0),
            "new slots start lazily without a delay"
        );
        let mut now = 500.0;
        for failure in 1..=4 {
            retry.fail_at(now);
            assert_eq!(retry.failures, failure);
            assert_eq!(
                retry.next_retry_ms,
                now + 1_000.0 * 2u32.pow(failure) as f64
            );
            assert!(!retry.can_retry(retry.next_retry_ms - 1.0));
            assert_eq!(retry.can_retry(retry.next_retry_ms), failure < 4);
            now = retry.next_retry_ms;
        }
        assert!(
            !retry.can_retry(f64::MAX),
            "exhausted slots stay in fallback"
        );
        retry.fail_at(now);
        assert_eq!(retry.failures, 4);
    }
    #[test]
    fn a_failed_slot_drains_only_its_own_pending_jobs() {
        let mut pending = std::collections::BTreeMap::from([
            (
                1,
                PendingEntry {
                    worker_slot: 0,
                    request: (),
                    sender: "failed first",
                },
            ),
            (
                2,
                PendingEntry {
                    worker_slot: 1,
                    request: (),
                    sender: "healthy",
                },
            ),
            (
                3,
                PendingEntry {
                    worker_slot: 0,
                    request: (),
                    sender: "failed second",
                },
            ),
            (
                4,
                PendingEntry {
                    worker_slot: 2,
                    request: (),
                    sender: "also healthy",
                },
            ),
        ]);
        let drained = drain_slot(&mut pending, 0);
        assert_eq!(
            drained
                .into_iter()
                .map(|job| job.sender)
                .collect::<Vec<_>>(),
            vec!["failed first", "failed second"]
        );
        assert_eq!(pending.keys().copied().collect::<Vec<_>>(), vec![2, 4]);
        assert_eq!(pending[&2].sender, "healthy");
        assert_eq!(pending[&4].sender, "also healthy");
    }
    #[test]
    fn drained_requests_resolve_immediately_using_the_native_fallback() {
        let (sender, mut receiver) = futures::channel::oneshot::channel();
        let mut pending = std::collections::BTreeMap::from([(
            7,
            PendingEntry {
                worker_slot: 1,
                request: crate::WorkerRequest::Sha256Chunk {
                    bytes: b"abc".to_vec(),
                },
                sender,
            },
        )]);
        for job in drain_slot(&mut pending, 1) {
            job.sender
                .send(crate::worker::execute_worker_request(job.request))
                .unwrap();
        }
        assert!(pending.is_empty());
        assert_eq!(
            receiver.try_recv().unwrap(),
            Some(crate::WorkerResponse::Hash {
                hex: crate::worker::sha256_hex(b"abc")
            })
        );
    }
    #[test]
    fn error_messageerror_and_late_timeouts_count_as_one_slot_failure() {
        let failed = std::cell::Cell::new(false);
        let mut retry = SlotRetry::default();
        assert!(retry.fail_once(&failed, 100.0));
        assert!(!retry.fail_once(&failed, 200.0));
        assert!(!retry.fail_once(&failed, 300.0));
        assert_eq!(retry.failures, 1);
        assert_eq!(retry.next_retry_ms, 2_100.0);
        let respawned = std::cell::Cell::new(false);
        assert!(retry.fail_once(&respawned, 2_100.0));
        assert_eq!(retry.failures, 2);
        assert_eq!(retry.next_retry_ms, 6_100.0);
    }
    #[test]
    fn native_pool_executes_the_identical_fallback_protocol() {
        let pool = WorkerPool::new(2);
        assert!(pool.is_in_process());
        let mut request = std::pin::pin!(pool.execute(crate::WorkerRequest::Sha256Chunk {
            bytes: b"abc".to_vec()
        }));
        let mut context = Context::from_waker(Waker::noop());
        assert!(
            matches!(request.as_mut().poll(&mut context), Poll::Ready(crate::WorkerResponse::Hash { hex }) if hex == crate::worker::sha256_hex(b"abc"))
        );
    }
    #[test]
    fn binary_hash_helper_matches_the_native_protocol() {
        let pool = WorkerPool::shared();
        let bytes = [0, 255, 1, 128];
        let mut hash = std::pin::pin!(pool.sha256_chunk(&bytes));
        let mut context = Context::from_waker(Waker::noop());
        assert_eq!(
            hash.as_mut().poll(&mut context),
            Poll::Ready(Ok(crate::worker::sha256_hex(&bytes)))
        );
    }
}
