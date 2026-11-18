//! Shared algorithms and wire contracts. Browser bindings are target-gated so the
//! exact worker, request-policy, chart and draft logic runs in native unit tests.
#[cfg(feature = "ui")]
pub use af_models as models;
#[cfg(feature = "ui")]
pub mod api;
#[cfg(feature = "ui")]
pub mod charts;
#[cfg(feature = "ui")]
pub mod draft;
#[cfg(feature = "ui")]
pub mod i18n;
pub mod markdown;
#[cfg(feature = "ui")]
pub mod navigation;
#[cfg(feature = "ui")]
pub mod topology;
pub mod worker;
#[cfg(feature = "ui")]
pub mod worker_pool;
#[cfg(feature = "ui")]
pub mod ws;

#[cfg(feature = "ui")]
pub use draft::FormDraft;
pub use worker::{WorkerRequest, WorkerResponse};
