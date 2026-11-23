mod ai_providers;
mod bandwidth;
mod cluster;
mod flowai;
mod mediaflow;
mod metadata;
mod scan_cursor;
mod telemetry;

#[cfg(test)]
mod audit_tests;
#[cfg(test)]
mod bandwidth_tests;
#[cfg(test)]
mod flowai_tests;
#[cfg(test)]
mod media_cluster_tests;

pub(crate) use ai_providers::{
    call_configured_ai, clean_json_fence, is_forbidden_model_alias, is_self_target_ai_endpoint,
    is_valid_local_model_id,
};
pub use ai_providers::{resolve_provider_settings, ChatMessage, ProposedAction, ProviderSettings};
pub use bandwidth::{bandwidth_analyze, bandwidth_apply};
pub use cluster::{
    dispatch_worker_command, enroll_worker, get_cluster_nodes, get_worker_metrics,
    list_worker_commands, remove_worker,
};
pub use flowai::{ai_chat, ai_support, test_ai_connection};
pub use mediaflow::{
    approve_mediaflow_item, decline_mediaflow_item, get_mediaflow_queue, trigger_mediaflow_scan,
};
pub use metadata::{metadata_results, metadata_scan, metadata_status};
pub use telemetry::{
    analyze_predictions, bookmark_log, get_auth_metrics_history, get_bookmarks, get_log_sources,
    get_metrics_history, get_predictions, get_system_metrics_context, get_system_topology,
    query_metrics_history_rows, resolve_metrics_history_window_and_limit,
    METRICS_HISTORY_QUERY_SQL, METRICS_PREDICTIONS_HISTORY_SQL,
};
pub(crate) use telemetry::{filter_log_entries, infer_log_level, AUDIT_LOG_FALLBACK_SQL};
