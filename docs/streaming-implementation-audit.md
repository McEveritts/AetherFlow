# Streaming Implementation Audit — November 2, 2026

This is a local implementation/audit record, not release approval. No production database reconciliation, restore, service restart or deployment has been performed. The phase acceptance matrix remains in [streaming-validation.md](streaming-validation.md).

## Review Sources

- Gemini 4 Argon High reviewed the canonical contracts and logic/concurrency behavior, implemented isolated increments, and supplied collector identity regression tests.
- Gemini 3.8 Flash High supplied the performance/contracts audit and repaired pattern contracts. Later Flash invocations returned no assistant result; those invocations are **not** counted as successful reviews.
- GPT Luna MAX reviewed privacy/admin boundaries, portability, imports and approval transactions. Its final import review identified checkpoint rewinds, cross-feed event-ID collisions, and insert-only reconciliation drift.
- McSurgeon dossiers are retained locally under `dist/streaming-surgery/archive` and `dist/streaming-surgery/final`. Their snapshots precede some repairs and concurrent edits; source anchors and suggested patches must be refreshed before use. No generated autofix was blindly applied.
- Final metadata reviews completed with Gemini 4 Argon High, Gemini 3.8 Flash High and GPT Luna MAX. Their findings were repaired/dispositioned by the parent; `dist/streaming-surgery/metadata-final/` is a refreshed snapshot and parent follow-up, not another independent final-source review.

## Verified Repairs and Dispositions

| Area | Disposition |
| --- | --- |
| Privacy | Non-admin legacy dashboard requests return no unscoped history or provider configuration. Canonical history/counts/export/analytics require explicit provider/server/user links; IP/device IDs are omitted. Administrative import/restore handlers deny non-admins before database/body access |
| Collector identity | Provider/server/session/play-session/item generations distinguish repeated playback; legacy records cannot be silently promoted. Dashboard interval zero never writes. First observations and reconnect gaps accrue no invented watch time or transfer |
| Summary sync | Server-instance-scoped keys prevent replacement servers overwriting earlier summaries. Only source-supplied parsed dates may upgrade summary timestamp certainty. Existing legacy rows remain untouched |
| Search and cursors | Bound literal search, correct SQLite escape syntax, stable indexed dated/undated keysets, signed query/viewer bindings, and distinct cursor versus snapshot token roles are regression-tested |
| Export | Independent 1,000-row batches replace UI-sized batches. Client cancellation, failed streams, invalidated snapshots and browser size limits cannot produce a successful partial download. CSV formula/control prefixes are neutralized |
| Checkpoints | `expectedCheckpoint` compare-and-swap occurs inside the batch transaction. Delayed batches cannot overwrite a newer checkpoint; retries at the current checkpoint remain idempotent |
| Event identity | Provider/server/source namespace separates identical event IDs from distinct feeds; stable source names and source event IDs are required |
| Reconciliation drift | Signed approvals include raw archive row count as well as revision and exact candidate fingerprints. Insert-only drift is rejected without adding insert revision triggers that would break archive watermark semantics |
| Reconciliation certainty | Heuristic classifications are explicitly suspected/unverified proposals requiring source review. Historical unknown server IDs are not guessed from current configuration, and key shape cannot upgrade timestamp certainty to last-played |
| Backup and restore | Failed verification cleans partial private backups. Versioned whitelist validation, exact-preview approval, immediate-transaction revalidation, rollback/audit tests and secret-free round trips are implemented. Rust-generated archive/preview/restore responses are consumed by frontend contract tests |
| UI state | Incomplete custom windows do not remain loading or expose stale exports; HTTP 409 clears invalidated rows. Durable bookmarks omit expiring viewer-bound cursors. New archive text observes a 12px minimum |
| Legacy estimates | The suggestion to expose legacy unverified bytes as trustworthy estimates was rejected. Raw database evidence is retained; canonical confirmed totals must not assert unsupported certainty |

## Static-Scan Triage

### Repaired-Import Review Follow-Up

The subsequent Argon review identified additional concrete edge cases. The implementation now rejects fresh event IDs submitted at an already committed checkpoint, while allowing existing-event retries; checks imported-event overlap even with a zero reconnect window; and requires a non-null verified disk backup before reconciliation. Disposable-database regressions cover these cases.

Portability merge now resolves playback identity by session/event keys rather than instance-local SQLite row IDs. An unrelated occupied ID is remapped deterministically, including its labels and session samples; repeated merges resolve the original stable identity. Target tracking policy remains unchanged in merge mode, and the unreachable policy-insertion branch is removed. Bandwidth sample ID collisions remain explicit skipped conflicts, not silently overwritten or inferred duplicates.

Browser JSON exports use compact serialization and recheck the restore size limit, avoiding whitespace inflation that made valid near-limit exports unrestorable. The download regression asserts the exact compact UTF-8 byte size. Unused historical-server lookup queries and misleading reconciliation certainty copy were removed.

The claim that reconciliation updates never invalidate revisions is rejected: migration 20's `streaming_history_changed` AFTER UPDATE trigger increments the shared revision. Existing file-backed reconciliation replay tests exercise stale approval rejection. Adding a redundant application-level bump would not repair a missing invariant.

The refreshed snapshot initially produced 46 heuristic findings. Four SQL-injection alerts are not evidence of injection: the identified collector statements are constant SQL with bound values; canonical query interpolation contains only allowlisted SQL structure and bound filter values; the frontend alert is a JSX test-ID template, not SQL. A `SELECT *` alert targets an aggregate compatibility CTE rather than an unbounded raw-row response. These are manually rejected with the underlying scope/performance caveat retained.

The readability alerts were actionable: all newly introduced 10px/11px archive text and both newly added legacy-warning labels were raised to 12px. Static detector output is retained rather than relabeled as a clean security certificate. Fresh multi-model findings after this snapshot require separate disposition.

## Metadata and Fixture Follow-Up

Transient media-folder and ancestor failures propagate instead of poisoning ten-minute positive caches. Cached item errors preserve actual status/type. Shared URL validation retains reverse-proxy prefixes and blocked targets; upstream identity comparison tolerates ASCII casing while storage retains the configured identity. Both provider collectors establish/check source identity before recording, and observations recheck URL/identity/enabled state inside their write transaction. New regressions cover cold start, stale/disabled configuration, rollback, retries and recently observed metadata updates.

Metadata scheduling resolves configuration in blocking work, performs bounded network work without holding SQLite connections, and updates only recent matching observed sessions in the background. The explicit helper still supports older matching evidence. Identity probes remain fresh by design. The HTTP mounted fixture runs in its own child process, isolating the process-global DB pool; a separate ignored/manual browser fixture is never mixed into normal tests.

Luna's remote cleartext HTTP concern remains an inherited transport-policy risk: administrators must use HTTPS/encrypted transport for remote providers. Native/LAN HTTP compatibility is not silently removed. Synthetic browser evidence is recorded in [streaming-browser-acceptance.md](streaming-browser-acceptance.md); no browser restore or real provider was exercised.

## Remaining Acceptance and Explicit Limits

- The latest integrated gate (`dist/streaming-validation.95isK2`) passes 77 canonical tests, 17 collector tests, 5 migration tests, 51 connected frontend tests, 226 actual API tests (2 ignored/manual fixtures), all 335 frontend tests, TypeScript, lint and both builds. Earlier API compilation/full-frontend failures are retained as history, not current failures. Existing warnings remain; no tests are suppressed.
- Real Jellyfin and Emby instance/client acceptance has not run; synthetic browser acceptance now covers the real UI/router with disposable data only. Emby must remain coming-soon/experimental until its real-client matrix passes; mock HTTP success is not activation evidence.
- Direct Playback Reporting/stock-provider event fetching is not implemented. Bounded event-export ingestion requires stable source IDs; item summaries and activity logs are not silently treated as playback events.
- Evidence updates can invalidate archive snapshots with HTTP 409. Routine dashboard reads do not mutate evidence, but collector updates are real mutations; their watch/byte changes cannot safely be ignored merely to keep an old cursor usable.
- Concurrency is sampled, not continuous: gaps remain unknown, paused observations can prove sampled zero, and pre-retention periods cannot be reconstructed. Polling cannot distinguish every stop/restart that occurs entirely between observations with unchanged IDs.
- JSON portability is bounded at 8 MiB/10,000 total records. Browser CSV downloads are bounded at 128 MiB and server exports at thirty seconds. No unlimited archival-backup claim is made.
- Approvals/cursor signing are process-local; restart invalidates outstanding previews/cursors. A multi-process deployment needs shared approval/signing state or appropriate routing.
- Migration/restore on an authorized deployment copy, production cleanup and deployment require separate operational authorization. No test grants that authorization.
