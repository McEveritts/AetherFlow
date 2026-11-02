# Streaming: Jellystat parity audit and repair plan

Audit date: November 1, 2026. Scope: the active Rust V4 API and `StreamingTab`, not the legacy Go implementation. This is a source-level assessment with automated regression testing, not a claim of verification against every Jellyfin client or a live production deployment.

## Assessment

AetherFlow already has a useful operational foundation: active sessions, artwork, playback controls and messaging, codec/transcoding details, library totals, daily statistics, and user/title leaderboards. Its main weakness is trustworthy historical analysis and exploration, not a lack of dashboard cards. Repair collection and aggregation semantics before adding analytics that amplify inaccurate data.

Jellystat explicitly lists session logging, statistics for libraries/users, user activity, watch history, automatic library synchronization, backup/restore, and Jellyfin statistics-plugin integration. Its source also implements hour/day activity, client statistics, user/library detail endpoints, and paged/filterable/sortable playback queries. These are the relevant parity targets; do not assume that a feature request in its issue tracker is an implemented feature.

## Confirmed defects at audit start

| Priority | Defect | Consequence | Repair direction |
| --- | --- | --- | --- |
| P1 | Historical synchronization supplies invented device/IP/play-method information and fallback duration/codecs/bitrate. | Unknown historical activity appears to be measured telemetry and contaminates statistics. | Preserve only information actually returned by Jellyfin; use unknown/empty values for missing playback metadata. |
| P1 | Live transfer estimates use media position as elapsed transfer time. | Seeking or resuming late in a movie creates an immediate fictitious transfer total. | Accumulate bounded observed playing intervals, not seek position; retain the initially observed start time. |
| P1 | The all-time selector maps to a ten-year window and the chart silently falls back to thirty days. | Totals, selector, and chart do not describe the same period. | Preserve an explicit all-time sentinel and generate buckets spanning the available history. |
| P1 | Chart descriptions promise peak bandwidth and watch hours, but the corresponding series are not plotted. | The page advertises comparisons it does not actually display. | Render the advertised series with appropriate units/axes. |
| P1 | History is a bounded recent-history payload with no real server pagination. | Search cannot find records outside the loaded subset; users cannot meaningfully browse large histories. | Provide an honest loaded-record workbench now; introduce server-side querying separately. |
| P2 | History omits event timestamps; some session metadata and filter choices are unused. | Users cannot tell when playback occurred or fully inspect already collected information. | Surface dates, explicit unknown values, and supported metadata/filter choices. |
| P2 | Upstream metadata/session requests are repeated during dashboard refresh. | Additional Jellyfin load and latency scale with open dashboards. | Separate live polling from slower metadata refresh; cache carefully without hiding connection errors. |

## Feature gaps and delivery order

The first repair pass below is implemented in the working tree. The capabilities in this roadmap remain outstanding; loaded-record tooling is not being presented as full Jellystat parity.

| Priority | Capability | Jellystat evidence | AetherFlow scope / acceptance criteria |
| --- | --- | --- | --- |
| P1 | Full history explorer | `stats.js`: `getPlaybackActivity`; `api.js`: `getHistory`, `getUserHistory` | Parameterized server-side filters, stable sorting, total/matching counts, bounded page sizes, and export of the explicitly selected scope. Local paging of the most recent 500 rows is not full-history parity. |
| P1 | Viewing patterns and concurrency | `stats.js`: `getViewsByHour`, `getViewsByDays`, `getLibraryItemsPlayMethodStats` | Timezone-aware hour/weekday views and peak concurrent streams from collected history/snapshots; state the sampling interval and retention. Do not infer historical concurrency from Jellyfin's last-played snapshot. |
| P1 | User and client drill-down | `stats.js`: `getGlobalUserStats`, `getAllUserActivity`, `getMostUsedClient` | Per-user history and trends, client/device breakdowns, and navigation from existing leaderboards. Unknown clients remain unknown. |
| P2 | Library/item analytics | `stats.js`: `getLibraryCardStats`, `getGenreLibraryStats`, `getMostPopularByType`, `getMostViewedByType` | Persist stable library relationships, then expose per-library plays/time, item detail, genres, and distinct-viewer versus total-play rankings. Global item counts alone do not meet this target. |
| P2 | Historical fidelity and exclusions | README plugin integration and playback-duration/session-threshold settings; `api.js`: tracked-library/untracked-user endpoints | Optional real-event/plugin import, minimum-duration policy, reconnect handling, and explicit library/user exclusions. Avoid double-counting imported item summaries and observed sessions. |
| P2 | Streaming data portability | README and `backup.js` | Streaming-specific authenticated export/import, schema versioning, restore validation, and integrity checks. A CSV of loaded history is useful but is not a database backup. |
| P2 | Emby integration | README: `IS_EMBY_API` | Emby currently remains a coming-soon provider in AetherFlow. Plex is also coming soon, but is not claimed as a Jellystat parity requirement. |

Multi-server support is listed under Jellystat's required development, not its advertised current feature set. It is a potential product opportunity rather than a proven existing competitor advantage.

## Delivered repair pass

- **Historical data fidelity:** imports retain available source metadata and last-played timestamps without inventing client/device/IP, delivery method, codecs, duration, bitrate, or network bytes. Missing dates remain missing. Upstream item-load and persistence errors propagate rather than reporting a successful empty sync.
- **Live accounting:** only positive monitor intervals accrue estimated watch time and transfer bytes while playing. Seeking/resuming does not charge the earlier media timeline, and zero-interval dashboard observations do not accrue counters or prune old bandwidth samples. Session starts remain the first observed start, not Jellyfin's mutable last-activity timestamp. Monitor startup is single-instance; disabling the provider clears stale active flags.
- **Consistent periods:** all-time remains `windowDays: 0`. Charts span the available dated history, with daily buckets through 3,650 calendar days, monthly buckets through 36,500 days, then yearly buckets. `timeSeriesGranularity` drives chart labels and date ticks. Rolling N-day filters retain both partial boundary days, so a daily series may contain N+1 dates; chart sums no longer silently omit matching boundary-day plays.
- **Consistent cohorts:** Unknown delivery methods are filtered in SQL before the 500-row history limit. All play-method percentages share the total-play denominator, Unknown plays appear in the stacked bars, and a user's last device is selected chronologically from the same filtered cohort rather than from excluded/demo records.
- **Actual chart series:** transfer estimates and peak playing bitrate have separate axes; session-method counts and watch hours are both plotted. Concurrent bandwidth samples contribute to unfiltered historical peaks. Sample retention remains 90 days, so older aggregate peaks are not reconstructable from samples that have already expired.
- **Usable loaded history:** search, play-method/media filters, local pagination with a matching page-size selector, explicit UTC playback timestamps, and CSV export now work on the loaded recent-history subset. The interface discloses the loaded/total bound and never labels that CSV an export of the entire archive. CSV cells neutralize spreadsheet formula prefixes and preserve backend privacy redaction.
- **Honest presentation:** imported zero-byte rows say Unrecorded; live transfer totals and retained legacy sync byte values say Estimated, not Measured. An unknown live delivery method alone is not treated as proof of an import. Redacted WAN addresses no longer render as local, and missing pipeline metadata has an explicit unrecorded label.
- **Reliable controls and failures:** client capabilities gate pause/resume/stop/message actions; optimistic updates recompute all live-summary counters. Poll errors retain prior data with a stale-data/retry warning, unreachable configuration stays visible, and session-not-found/unsupported/upstream command failures have appropriate API error classes. The unused connection-test `/Sessions` probe was removed.

No existing production history was erased or silently reconciled. A routine re-sync is not guaranteed to clean old synthetic rows because unchanged last-played records can be skipped; a previewable, explicitly authorized reconciliation remains separate work.

## Data-truth boundaries

- Jellyfin item/user data exposes last-played/resume information, not a complete recording of every historical playback session. Importing it cannot reconstruct actual client IPs, clients, play methods, or network bytes.
- Bitrate multiplied by observed playing time remains a transfer estimate, not interface traffic accounting. Buffering, variable bitrate, and poll gaps limit accuracy.
- Previously persisted synthetic metadata and inflated totals need an explicit, previewable cleanup/reconciliation policy. Do not silently delete production history or pretend collection fixes retroactively repair it.
- Keep non-admin IP/key redaction and administrative mutation boundaries intact. Export must not reintroduce redacted information.
- Preserve Rust V4, native systemd deployment, and the existing Apache ingress architecture. No rollback or container migration is necessary for this work.

## Verification

Final scoped results on November 1, 2026:

| Check | Result |
| --- | --- |
| Rust streaming tests against the real streaming/auth/WebSocket modules in an isolated temporary Cargo harness | **11 passed**, 0 failed |
| Streaming component and serialized Rust-to-React contract suites | **22 passed**, 0 skipped, across 2 suites |
| Frontend TypeScript, `--noEmit --incremental false` | Passed |
| ESLint on the streaming component, tests, and utility | 0 errors; existing Next.js `<img>` optimization warning remains |
| Scoped `git diff --check` | Passed |
| Entire frontend test suite | 201 passed, **4 failed** in the unrelated McBrowser public-share suite (`frontend/src/app/share/page.test.tsx`); 24 of 25 suites passed |
| Integrated `af-api` Cargo test build | Blocked by concurrent McBrowser changes: unresolved archive handlers, missing `InfoResponse` fields, and non-exhaustive archive-format handling in `mcbrowser/operations.rs` |

The scoped Rust harness at `/tmp/aetherflow-streaming-audit/Cargo.toml` imports the repository's real `auth.rs`, `ws.rs`, and `streaming_ext.rs` with their real workspace library dependencies; it does not replace them with mocks or modify McBrowser. It generates `/tmp/aetherflow-streaming-audit/rust-dashboard.json`, which the frontend contract suite consumes through `AF_STREAMING_CONTRACT_FIXTURE`. The integrated Rust build and unrelated share-test failures are **not** claimed to be repaired or green.

The normal npm test entrypoint remains blocked by absent `ts-node`. Validation used a temporary CJS Jest configuration and cached Node 22.20 (the installed Node 22.12 is incompatible with the installed Undici version). These are tooling prerequisites, not evidence of production behavior.

Coverage includes fabricated import metadata/timestamps, upstream sync failures, paused/resumed/seek accounting with interleaved observation/monitor snapshots, historical bucket spans, concurrent peaks, Unknown cohorts and percentage denominators, last-device cohort isolation, rolling-window boundary preservation, pruning behavior, session-control capabilities, non-admin redaction, CSV formula safety, history paging/search, coarse chart labels, UTC parsing, stale-data visibility, and configuration failures.

No production deployment or live Jellyfin-client/browser acceptance run was performed. Production deployment, destructive history repair, and a new full-history query API are not implied by this initial repair pass. Existing unrelated McBrowser work was left untouched.

## Primary sources

- [Jellystat README](https://github.com/CyferShepard/Jellystat/blob/main/README.md)
- [Jellystat statistics routes](https://github.com/CyferShepard/Jellystat/blob/main/backend/routes/stats.js)
- [Jellystat history, user, and tracking routes](https://github.com/CyferShepard/Jellystat/blob/main/backend/routes/api.js)
- [Jellystat backup/restore routes](https://github.com/CyferShepard/Jellystat/blob/main/backend/routes/backup.js)
- AetherFlow: `frontend/src/components/tabs/StreamingTab.tsx`
- AetherFlow: `backend-rs/crates/af-api/src/streaming_ext.rs`
- AetherFlow contracts/schema: `backend-rs/crates/af-services/src/lib.rs`, `backend-rs/crates/af-db/src/lib.rs`
