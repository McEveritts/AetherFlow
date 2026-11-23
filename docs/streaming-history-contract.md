# Streaming History Contract v1

## Scope & Type Ownership

This document specifies the v1 canonical streaming history contract implemented across:

- **Backend API, Collector & Query/Export Handlers**: `backend-rs/crates/af-api/src/streaming_ext/` (`monitor.rs`, `dashboard.rs`, `handlers.rs`, `summary_sync.rs`, `jellyfin.rs`, `plex.rs`, `emby.rs`), `routes/streaming.rs`, `streaming_history.rs`, `streaming_patterns.rs`, `streaming_import.rs`, `streaming_portability.rs` + `streaming_portability/` (export/restore storage and SQL-only cap queries), `streaming_metadata.rs`, and `streaming_emby/`.
- **Shared DTOs, Validation & HTTP Client Layer**: `backend-rs/crates/af-services/src/streaming.rs` (`DEMO_STREAMING_MODE`, URL/IP validation, DNS `StreamingResolver`, and `streaming_http_client_builder()`).
- **Database Migrations, Read Pool & Backup Pruning**: `backend-rs/crates/af-db/src/streaming.rs` (Migrations 20/24 and `prune_old_streaming_backups`) and `backend-rs/crates/af-db/src/pool.rs` (`DB_READ_POOL`).
- **WASM Frontend Consumer**: `frontend-rs/crates/af-web-app/src/tabs/streaming/{types,history}.rs` (declaring matching camelCase DTOs independent of `af-models` without altering the legacy live-dashboard contract).

## Query, Export, Patterns & Drilldown Endpoints

Authenticated streaming explorer endpoints operate independently of the five-second live dashboard poll:

- **History & Export**: `GET /api/v1/auth/streaming/history`, `GET /api/v1/auth/streaming/history/export`
- **Patterns**: `GET /api/v1/auth/streaming/patterns`, `GET /api/v1/auth/streaming/patterns/activity`, `GET /api/v1/auth/streaming/patterns/concurrency`
- **Drilldowns**: `GET /api/v1/auth/streaming/drilldown`, `GET /api/v1/auth/streaming/drilldown/users`, `GET /api/v1/auth/streaming/drilldown/clients`, `GET /api/v1/auth/streaming/drilldown/items`, `GET /api/v1/auth/streaming/drilldown/libraries`, `GET /api/v1/auth/streaming/drilldown/genres`
- **Dashboard & Artwork**: `GET /api/v1/auth/streaming/dashboard`, `GET /api/v1/auth/streaming/artwork/:itemId`

### Pagination, Windows & Filtering

- Default page size is `50`, maximum `200`; sort accepts `startedDesc` or `startedAsc` with undated rows last in either order and row `id` as tie-breaker. Unknown enum/sort/query fields, overlong search/cursors, and invalid timezones/dates return HTTP `400` rather than being ignored.
- `window` defaults to `all`, supporting rolling windows (`7d`, `30d`, `90d`, `365d`), local calendar windows (`today`, `month`, `year`), or `custom` with offset-bearing RFC3339 `from` and `until`. Bounds are half-open `[from, until)` in UTC. Calendar windows use the IANA `timezone` parameter (default `UTC`) with DST boundaries resolved in local time. Dated windows exclude undated rows; `all` retains them. SQL timestamps are interpreted as UTC.
- Search is literal and ASCII-case-insensitive (Unicode matched literally); wildcards do not broaden queries, and IP addresses, device IDs, and session keys are never searchable.

### Provenance & Access Scope

- Existing legacy rows default to `legacy_unverified` and are never inferred as observed sessions from session-key shape. Active collectors write `observed_session` or `item_summary`; event imports write `imported_event` with stable upstream IDs. Only included observed/imported events count toward confirmed plays, watch time, and estimated transfer. Summaries and legacy rows remain separately inspectable, missing values remain `null`, and estimated bytes are not network measurements.
- Administrators can inspect all providers and excluded raw records. Non-admin users see only provider users explicitly linked in `streaming_user_links` (no link means empty results), with counts, facets, and exports sharing that predicate and omitting IP addresses and device IDs.

### Snapshot Isolation, Concurrency & Migrations

- Snapshots freeze the maximum inserted ID and rolling/calendar reference instant. Signed viewer/query-bound cursor tokens expire after 15 minutes; inserts above the watermark are excluded.
- Migration 24 introduces a distinct historical read epoch: structural evidence edits/deletes, inclusion-threshold crossings, policy changes, and identity/label changes invalidate in-flight reads with HTTP `409`. Routine live watch/byte/activity advances do not invalidate reads.
- Page responses return `scope.snapshotToken` for full-query export at the same snapshot (export omits `cursor` and passes `snapshot`). History reads execute against the dedicated read-only WAL pool (`DB_READ_POOL`, `max_size(8)` in `af-db/src/pool.rs`); timeout, cancellation, or structural mutation fails the response rather than returning a truncated successful CSV. `availableRecords` is the authorized policy-visible archive size before optional filters; `matchingRecords` is the complete filtered cohort.
- Migration 20 is additive and transactional, preserves all legacy rows, and captures an integrity-checked SQLite backup in a private directory before migrating a file-backed database (in-memory tests need no disk backup).

---

## Collection and Identity

- The 15-second collector records point samples separately from interval estimates. The first observation of a playback accrues zero seconds/bytes because its prior interval is unknown; reconnect gaps, unobserved intervals over 60 seconds, and nonpositive intervals add no watch time or estimated transfer. Distinct provider/server/session/play-session/item generations preserve repeat plays.
- Item-summary sync uses a provider-instance-scoped key, never promotes a legacy row, and upgrades timestamp certainty only when upstream provides a parseable `LastPlayedDate`. Legacy dashboard statistics remain explicitly mixed/unverified.
- Before recording observations, collectors verify upstream server identity (`/System/Info/Public` for Jellyfin/Emby or `/identity` `machineIdentifier` for Plex), bind an unset server identity, and reject unexpected replacement identities (ASCII case-insensitive comparison preserving stored casing). Jellyfin active session `ServerId` must also match. Write transactions recheck the enabled provider URL and identity.
- Provider support stages: Jellyfin and Plex (`supportStage: "active"`) support active collection; Emby configuration, telemetry, and backend session commands (`POST /api/v1/admin/streaming/sessions/:sessionId/command` for `pause`, `resume`, `stop`, `message` in `streaming_emby/operations.rs`) are wired on the backend, while the WASM UI currently enables session controls for Jellyfin only and Emby item-summary sync returns HTTP `501`.

### Provider Item Metadata

- Library and genre enrichment is asynchronous and restricted to matching verified observed-session evidence (imports, summaries, and legacy rows are not rewritten). Library labels require collection-root/ancestor evidence; missing/deleted upstream metadata preserves existing labels. Failed folder/ancestor lookups are not cached as empty successes, and cached item failures retain their error type/status.
- Background metadata refresh runs for **Jellyfin and Emby** (Plex is skipped) via a single-flight `AtomicBool` guard with a detached `tokio::spawn` task (no explicit cancellation token), bounded to at most 32 distinct items, 6 seconds per request, 2 MiB per response, and a 30-second total network budget. Successful item/root metadata caches for 10 minutes; item failures for 2 minutes. HTTP calls hold no SQLite connection, and background persistence updates only observations seen within 10 minutes without churning snapshot revisions when labels are unchanged.
- Identity probing stays fresh (never using the 10-minute metadata cache). Local/native HTTP URLs are supported, though remote non-loopback cleartext HTTP exposes credentials—use HTTPS or an encrypted tunnel for remote servers. Blocked targets are rejected by `af_services::validate_server_url`, and HTTP redirects are disabled by `af_services::streaming_http_client_builder()` / `METADATA_HTTP_CLIENT`.

---

## Administrative Import and Reconciliation

Administrative endpoints live under `/api/v1/admin/streaming/`:

- `GET /imports/status`, `POST /imports/events`, `POST /imports/upstream-probe`
- `GET/PUT /policies`, `GET/PUT/DELETE /user-links`
- `POST /reconciliation/preview`, `POST /reconciliation/apply`
- `PUT /servers/:provider`, `POST /servers/test`, `POST /servers/:provider/sync`, `POST /sessions/:sessionId/command`, `POST /demo`

Event import accepts up to 500 events per batch, supporting structured canonical JSON batches as well as native Plex and Tautulli JSON/CSV event imports. Upstream `sourceEventId` values are namespaced by provider, server, and `source` before persistence while echoing original IDs in responses. `expectedCheckpoint` is omitted/null for the initial batch and must match the last committed checkpoint when advancing; retrying the current checkpoint allows only already-persisted event IDs, earlier delayed batches cannot rewind a newer checkpoint, and mixed retry/new batches roll back atomically. Cross-source overlaps are marked conservatively ambiguous even with a zero reconnect window.

Reconciliation previews are read-only, and every heuristic classification is a **suspected, unverified proposal** requiring operator verification before approval. Approval binds actor, exact row fingerprints, revision, and archive row count (including insert-only drift) and captures a verified on-disk backup before executing an immediate write transaction with revalidation.

---

## Portability and Operational Limits

Admin portability endpoints (`GET /api/v1/admin/streaming/portability/export`, `POST .../preview`, `POST .../restore`) use a whitelisted v1 JSON format capped at 8 MiB (10 MiB JSON request envelope) and 100,000 total portable records, omitting provider credentials, IPs, and device identifiers/names:

- **Bounded Sample Selection (`build_archive_with_budget`)**: When routine session or bandwidth samples exceed the 100,000-record archive budget after retaining all history, labels, and tracking policies, earlier samples are trimmed and the manifest records an integrity-bound `omittedSamples` object (`sessionSamples`, `bandwidthSamples`) surfaced in headers, UI notices, and restore previews; full archives omit `omittedSamples` completely.
- **SQL-Only Above-Cap Replace (`query_target_counts_and_digest_sql`)**: Replace previews and restores compute target counts and digests in SQL so archives can replace targets that exceed the 100,000-record in-memory cap.
- **Merge Deduplication**: Merge resolves history by stable session/event identity, remaps occupied instance-local row IDs and parent links, preserves target tracking policy, and deduplicates bandwidth samples by natural key `(timestamp, provider)` (reporting collisions rather than silently overwriting unrelated rows).
- **Verified Backup Retention (`prune_old_streaming_backups`)**: Merge/replace restore and reconciliation require exact-preview approval and a verified on-disk SQLite backup; automated retention pruning keeps the newest 2 verified backups (`af-db/src/streaming.rs`).
- **CSV & Session Bounds**: Browser CSV downloads are capped at 128 MiB; server CSV export runs in independent 1,000-row batches with a 30-second deadline. Preview tokens and cursor signing keys are process-local (restarts invalidate outstanding approvals/cursors; multi-process deployments require sticky routing or shared signing state).

---

## Observation and Connection Boundaries

- Routine dashboard reads share a 15-second verified telemetry cache rather than issuing per-viewer provider probes. A saved nonempty provider identity cannot be rebound by a dashboard read or connection test; failed reads report unavailable rather than idle.
- Artwork requests require an authorized provider/current-server/item scope before sending credentials and return `private, no-store` responses. Connector DNS validation inspects resolved addresses, blocks unspecified/link-local/metadata/multicast targets, disables proxies and redirects, and permits loopback and private LAN servers.
- Live collectors run independently per provider; Jellyfin item-summary sync batches are single-flight, checkpointed, and bounded to 8 pages and a 45-second whole-batch deadline. Canonical activity expires after 60 seconds without evidence; disabling a provider clears active flags without inventing an end timestamp while preserving saved credentials and historical server identities.
- Exact-second pattern samples represent partial per-provider observations rather than complete simultaneous all-provider totals. `StructuredPolicyEditor` preserves unsaved policy drafts across background server refreshes (`apply_server_refresh`), disables its inputs while a save is pending (`busy`), and clears local edits on save completion (`mark_saved`; concurrent edits during pending saves are not supported).
