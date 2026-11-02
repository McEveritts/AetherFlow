# Streaming: Jellystat parity implementation plan

Plan date: November 1, 2026. Implementation status updated November 2, 2026. The subsequent implementation request authorizes local development and testing; this document does not authorize production deployment or historical-data cleanup.

Basis: [Streaming audit](streaming-jellystat-audit.md). Target the active Rust V4 API and React Streaming page. Preserve native systemd deployment, Apache ingress, and unrelated McBrowser changes. Do not introduce Docker, an architecture migration, or a rollback of existing work.

## Implementation Status — November 2, 2026

| Phase | Implemented locally | Acceptance still required |
| --- | --- | --- |
| 1 | Reproducible scoped/integrated gate, compatible Node runtime, Rust-to-React fixtures; previous integration blockers repaired | Real Jellyfin clients, browser interaction, and separate release authorization |
| 2 | Transactional v20 migration with verified backup, provenance/certainty fields, server identity, explicit user links, policies and canonical query contract | Operational migration on an authorized copy of the deployment database |
| 3 | Server-side full archive search, null-last keyset pagination, matching counts, snapshot-bound CSV, connected explorer | Live-browser acceptance; active evidence updates deliberately invalidate snapshots rather than returning inconsistent pages |
| 4 | Bounded event batches with stable source IDs/checkpoints, conservative overlap handling, policies, links, preview/approval reconciliation | Direct provider event fetching is unavailable; operators must provide validated event exports with stable IDs. No historical reconciliation has run |
| 5 | Timezone-aware activity, DST disclosures, bounded timelines and sampled concurrency with explicit gaps/retention | Real collector coverage verification; observations cannot reconstruct gaps or pre-retention activity |
| 6 | Connected user/client/item/library/genre drill-downs using canonical filters, stable identities and overlapping denominators | Real library-membership data and live-browser acceptance |
| 7 | Versioned bounded JSON export/preview/restore; capability-aware Emby adapter with mock tests and coming-soon status | Real Emby instance/client verification and full provider activation; no deployment database restore has run |

This matrix records code availability, not completed live acceptance. See [validation evidence](streaming-validation.md) and [canonical contract](streaming-history-contract.md) for test commands and limits. Portability and reconciliation approvals are actor/data bound and expire; process restart invalidates outstanding approvals. A successful test does not grant permission to apply either operation to production.

## Original Starting Point

The first repair pass is already implemented locally. Do not schedule these fixes as new feature development:

- Honest historical metadata and missing timestamps; upstream sync errors no longer masquerade as success.
- Seek/resume-safe interval accounting, stable observed session starts, singleton monitoring, and stale-session cleanup.
- Correct all-time selection, full historical chart coverage, consistent filtered cohorts, Unknown categories, and actual bandwidth/watch-hour chart series.
- Capability-gated session controls, stale/retry feedback, and a loaded-history workbench with dates, filters, pagination, and formula-safe CSV.

At the original planning baseline, integrated application validation and live-client acceptance were outstanding, and the explorer searched at most 500 loaded records. The new canonical explorer is server-side; the old dashboard preview remains bounded and explicitly labeled as mixed legacy statistics. Previously fabricated or inflated stored rows have not been reconciled.

Phase 1 execution tooling and the uncompleted live acceptance matrix are documented in [Streaming repair validation](streaming-validation.md). This does not change the scope or release gates below.

### Recorded validation baseline

These are results from the completed repair pass, not fresh checks of the evolving worktree:

- 11 scoped Rust tests and 22 frontend/Rust-to-React contract tests passed; TypeScript passed.
- Scoped lint had no errors and one existing image-optimization warning.
- The integrated `af-api` build was blocked by concurrent McBrowser compilation errors.
- The full frontend suite had four unrelated public-share failures; the normal test entrypoint also had a missing `ts-node` prerequisite.
- No live Jellyfin-client/browser acceptance or production deployment was performed.

## Delivery order

| Phase | Priority | Outcome | Dependencies |
| --- | --- | --- | --- |
| 1 | Release gate | Existing repairs are integration- and live-verified | McBrowser owners resolve shared build/test blockers |
| 2 | P1 foundation | Canonical history, provenance, and query contracts | Audit baseline; may proceed while phase 1 awaits integration |
| 3 | P1 | Full-history exploration and explicit-scope export | Phase 2 contracts and indexes |
| 4 | P1 foundation | Faithful event import, tracking policies, and safe reconciliation | Phase 2 model; phase 3 query/export for inspection |
| 5 | P1 | Timezone-aware viewing patterns and defensible concurrency | Phase 2 model; phase 4 provenance/deduplication rules |
| 6 | P1/P2 | User/client and library/item/genre drill-downs | Phase 3 queries; phase 4 fidelity; stable library relationships |
| 7 | P2 | Streaming backup/restore and Emby support | Stable model; Emby additionally uses phase 1 acceptance matrix |

## Phase 1 — Close the existing repair release gate

### Work

1. Recheck the shared integration state. Coordinate McBrowser compile/share-test repairs with their owners; do not modify or discard that work under a Streaming task.
2. Make scoped streaming tests and serialized Rust-to-React fixtures reproducible from checked-in test tooling. Remove dependence on temporary harness/config paths without replacing the real modules with simplified mocks.
3. Establish a compatible Node runtime and working standard test entrypoint using repository conventions; then run scoped tests, integrated Rust tests/build, TypeScript, lint, frontend build, and the full frontend suite.
4. Exercise a real Jellyfin server and actual clients: direct play, direct stream, transcode, pause/resume, forward/backward seek, reconnect, simultaneous sessions, provider disable, server outage/recovery, and supported/unsupported playback commands.
5. Verify admin versus non-admin redaction, stale-state messaging, chart units, keyboard/mobile usability, and Unknown/Unrecorded/Estimated labels.

### Acceptance gate

- Integrated builds pass and unrelated failures are resolved by their owners; isolated harness results alone are insufficient for release.
- Seeking/resuming never creates a position-sized accounting jump; paused intervals do not accrue watch time or estimated transfer.
- Dashboard polls do not double-count monitor observations, and stale sessions disappear appropriately.
- Real-client evidence is recorded with server/client versions and test outcomes. Deployment remains a separate authorization, not an automatic consequence of this plan.

## Phase 2 — Define canonical history and query contracts

### Backend and data model

- Define distinct provenance for observed sessions, real imported playback events, Jellyfin last-played item summaries, and legacy/unverified records. Preserve source identity, provider identity, nullable metadata, and timestamp certainty.
- Give real events stable identities and specify session lifecycle/reconnect semantics. Persist stable user, item, and library relationships without assuming titles are unique or metadata never changes.
- Agree on one normalized query contract for windows, IANA timezone, provider/user/library/item, media type, delivery method including Unknown, provenance, search, ordering, and pagination. Only advertise filters supported by persisted data.
- Keep existing dashboard responses backward-compatible. Define denominators and play/watch-time semantics once for lists, counts, charts, exports, and drill-downs.
- Proposed default: count confirmed playback events as plays; expose item summaries separately rather than adding them to observed/imported session counts. Undated records remain visible in all-time exploration, with an explicit count explaining their absence from dated charts.
- Specify UTC storage, rolling versus calendar windows, daylight-saving behavior, null-date ordering, case normalization, permission/redaction rules, and export consistency under concurrent collection.
- Use additive, versioned schema/index changes. Take and verify a consistent database backup before applying migrations to a real database; never silently rewrite old history.

### Acceptance gate

- Checked-in Rust/TypeScript contracts and serialized fixtures cover Unknown values, undated records, mixed provenance, multiple users/providers, boundary days, and role-based redaction.
- List, count, chart, and export queries use the same validated filter semantics. Sampling limitations are part of the response contract, not hidden UI assumptions.
- Migration tests preserve an existing database and can be rerun safely. Query plans and a representative large-history fixture establish a recorded performance baseline.

## Phase 3 — Replace loaded-only history with a full-history explorer

### Backend

- Add a dedicated server-side history query rather than growing the dashboard payload. Use parameterized search/filters and allowlisted sort fields; validate cursor/filter combinations.
- Implement stable ordering with a unique tie-breaker and explicit null-date handling. Proposed page sizes: 50 by default, maximum 200. Return authorized total and matching counts, paging metadata, and query scope.
- Specify snapshot/watermark behavior so collection during paging/export cannot silently duplicate or omit records. Index actual filter/sort paths and test them on histories larger than 500 rows.
- Export the explicit query scope with bounded-memory batches, cancellation/time limits, CSV escaping/formula protection, and the same permissions/redaction as the explorer. Clearly distinguish a full-query export from a loaded-page export.

### Frontend

- Replace local-only filtering/paging with server queries, debounced search, loading/error/empty states, and stale-request cancellation.
- Preserve filter/sort/page state in navigation. Show matching versus available records and export scope; reset invalid cursors when filters change.
- Retain useful live-dashboard behavior without refetching the archive on every live poll.

### Acceptance gate

- A matching record beyond the old 500-row boundary is searchable, reachable by paging, and included in full-query export.
- Duplicate timestamps, missing dates, active collection, changed filters, and late responses do not corrupt navigation or totals.
- Injection/sort/cursor tampering, oversized requests, CSV formulas, cancellation, and non-admin export redaction have regression coverage.
- A representative 100,000-record fixture demonstrates indexed paging and bounded-memory export; record timings and agree on a host-specific latency budget before release.

## Phase 4 — Add faithful imports, collection policies, and legacy reconciliation

### Import and collection

- Detect optional Playback Reporting/plugin availability and supported event fields; leave ordinary Jellyfin item summaries explicitly labeled when real events are unavailable. Do not treat activity logs as equivalent without proving their event detail.
- Add resumable import checkpoints, source event IDs, transactional batches, retries, and sync progress/errors. Repeated or interrupted imports must be idempotent.
- Deduplicate confirmed overlaps between imported events and observed sessions. Preserve ambiguous overlaps for review instead of guessing identity or counting both as confirmed plays.
- Implement minimum observed watch-duration, user/library exclusions, and reconnect policies. Keep raw evidence separate from analytical inclusion, and disclose whether a policy affects future collection or historical reporting.
- Test paused intervals, late observations, poll gaps, provider restarts, repeated playback of the same item, and concurrent sessions with similar titles/users.

### Legacy reconciliation

- Build a read-only preview identifying suspect synthetic/inflated rows, proposed field changes, counts, and effects on totals. Do not treat matching a historical default as proof that otherwise valid data is fabricated.
- Bind approval to the exact preview/data revision. Require an authenticated admin, a verified consistent backup, and explicit approval before applying a bounded reconciliation.
- Preserve an audit trail and source evidence; change only approved records/fields. Invalidate the preview if affected data changes before execution.
- Do not promise that an ordinary re-sync repairs old records; unchanged item summaries may be skipped.

### Acceptance gate

- Importing the same interval twice or resuming after failure creates no duplicate confirmed plays.
- Imported unknown details stay unknown; snapshots and real sessions never silently share the same metric meaning.
- Exclusion/minimum-duration/reconnect policies produce consistent query and chart cohorts.
- Preview changes nothing. Unauthorized, stale-preview, backup-failure, and partially interrupted reconciliation cases are tested; no production cleanup runs implicitly.

## Phase 5 — Add viewing patterns and historical concurrency

### Work

- Add hour-of-day and weekday activity in the selected timezone, including DST transitions and partial boundary days.
- Collect the per-session evidence needed for filtered concurrency. Define whether each chart uses sampled active sessions or reconstructed observed intervals; do not conflate either with actual network measurement.
- Store/aggregate concurrency, playing bitrate, coverage, and sampling gaps with explicit retention and provenance. Define what can be filtered from per-session evidence versus unfiltered aggregate samples.
- Retain the existing 90-day aggregate-sample limit until an explicit retention/storage change is accepted. Longer-term rollups can start prospectively; already expired samples cannot be recovered by changing retention.
- Render activity and concurrency views with accessible tables/tooltips, units, coverage/gap labels, and query-consistent drill-down links.

### Acceptance gate

- Known overlapping-session fixtures produce exact expected sampled/interval peaks, with defined pause/end/reconnect behavior.
- DST, timezone changes, missing samples, undated item summaries, and periods older than retained evidence are covered.
- Item summaries never create historical concurrency. Unavailable history appears unavailable, not as invented zero activity or fabricated precision.

## Phase 6 — Add connected drill-downs

### User and client: first slice, P1

- Link user leaderboards to per-user history, trends, watch time, media preferences, and client/device/delivery-method breakdowns.
- Reuse the canonical query contract and full-history explorer; retain period, provider, and permission context across navigation.
- Keep missing client/device information in explicit Unknown groups, not invented device categories.

### Library, item, and genre: second slice, P2

- Populate stable library/item relationships before exposing library filters or historical detail. Retain identifiers when upstream items disappear; mark missing metadata rather than deleting viewing evidence.
- Add per-library plays/watch time, item history/detail, genres, and distinct-viewer versus total-play rankings.
- Define multi-library/multi-genre attribution so overlapping classifications are not presented as disjoint totals.

### Acceptance gate

- Every drill-down reconciles with the same filtered explorer and metric definitions; summaries are labeled separately.
- Unique viewers and plays differ correctly in repeat-viewing fixtures. Deleted/renamed items, multiple libraries/genres, and Unknown metadata remain navigable.
- Direct links enforce permissions and do not leak private users, IPs, provider credentials, or excluded records.

## Phase 7 — Add portability and Emby as independent increments

### Streaming backup/restore

- Define a streaming-specific versioned archive with manifest, schema/provenance versions, record counts, and integrity checks. A history CSV is not a backup.
- Exclude provider secrets by default. Require authenticated administrative access and protect archives containing private history.
- Validate size/format/version/checksums and stage a read-only restore preview before any write. Reject unsupported, malformed, oversized, or path-traversing input.
- Specify merge/replacement behavior and conflict handling before implementation. Restore must be explicitly approved, consistent/transactional, and unable to modify unrelated AetherFlow/McBrowser data.
- Test round-trip restoration on a disposable database before enabling production restore.

### Emby

- Add an adapter over shared canonical models, not a second analytics implementation. Confirm actual server/API differences with fixtures and a real Emby instance.
- Implement connection validation, library/user metadata, sessions, history availability, artwork, and capability-aware playback controls with honest unsupported states.
- Run the same accounting, privacy, import, filtering, and live-client acceptance matrix used for Jellyfin.

### Acceptance gate

- Backup round trips preserve counts, IDs, nulls, provenance, and timestamps; bad input leaves the target unchanged.
- Emby capabilities pass contract tests and real-client acceptance before removing its coming-soon state.
- Plex and multi-server support remain separately scoped opportunities, not required Jellystat parity claims.

## Parallel work and integration ownership

These are proposed workstreams for future execution; no agents are launched by creating this plan.

- Backend/API: schema/query contracts, indexed history, shared aggregation, streaming export.
- Import/data: event adapters, deduplication/policies, reconciliation preview, archive format.
- Frontend: archive explorer, scope/provenance messaging, charts, connected drill-downs.
- QA/review: serialized contracts, adversarial/privacy tests, migration/large-history fixtures, live-client evidence.

Use Gemini 4 Argon subagents as requested when execution begins and the model is available. Freeze contracts before parallel implementation. Keep one integration owner for shared schema/types and `streaming_ext.rs`; do not let multiple agents independently rewrite that file or mix in concurrent McBrowser repairs.

## Release milestones and next action

1. Repair milestone: close phase 1; release the already completed correctness fixes only after the integrated/live gate and deployment authorization.
2. Trusted-history milestone: phases 2–4; full archive exploration, faithful provenance/import, and non-destructive reconciliation tooling. Applying legacy cleanup remains separately approved.
3. Analytics milestone: phases 5–6; activity/concurrency and connected drill-downs over trustworthy data.
4. Expansion milestone: phase 7; backup/restore and Emby can ship independently after their respective gates.

Every milestone requires reproducible scoped and integrated tests, backward-compatible contracts or an explicit migration, privacy checks, and updated operator/user documentation. Production releases retain the existing native deployment path; this plan performs no release or data mutation.

Recommended first implementation slice: establish phase 1's reproducible integration gate and phase 2's provenance/query contract, then build phase 3's history endpoint and explorer. Do not add more headline dashboard cards before the historical data/query foundation is trustworthy.
