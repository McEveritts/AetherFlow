# Streaming repair validation gate

This is the validation gate for the [seven-phase implementation](streaming-jellystat-implementation-plan.md). Passing these commands is not permission to deploy, migrate a real database, reconcile historical rows, or claim live-client acceptance. Local feature tests and external acceptance are recorded separately.

## Reproduce the checks

Use the repository root. Install the Node version in `.nvmrc` with your runtime manager (`nvm install && nvm use` for nvm), then install locked dependencies with `npm ci`. The root/frontend manifests require Node >=22.19.0, matching the installed Undici test dependency; the previously used Node 22.12 does not satisfy that requirement. Rust/Cargo and the normal native workspace build prerequisites are also required. Do not install a separate Node daemon or change system services to run these checks.

```bash
bash scripts/validate-streaming.sh --scoped
bash scripts/validate-streaming.sh --integrated
python3 -m unittest discover -s tests -p test_streaming_validation.py -v
```

Each gate run creates a fresh ignored `dist/streaming-validation.*` directory containing individual logs, `summary.txt`, runtime versions, Git HEAD/worktree status, and Rust-generated `rust-dashboard.json`, `rust-archive.json`, and `rust-portability.json` contracts. These contain synthetic fixture data, not private history exports or deployment database backups. No credentials, provider configuration, or real database are needed by the scoped tests. The script rejects unsupported runtimes and unknown arguments before starting checks, continues independent checks after failures, and exits nonzero if any check fails.

Each check has a GNU `timeout` bound of ten minutes and a ten-second termination grace period. A timeout is a failed gate (exit 124), not a skipped test. Set `AF_STREAMING_CHECK_TIMEOUT=20m` for a slower clean build, or a shorter duration for diagnostics. Git and GNU coreutils are required alongside Node/npm and Cargo. This prevents a stalled test runner from hiding later build/lint failures.

### Scoped mode

1. Run the existing `streaming_ext::tests` through the `af-streaming-tests` Cargo workspace member using the workspace lockfile. It imports the repository's actual streaming, authentication, and WebSocket modules with workspace dependencies, not copied implementations or mocks. This isolates unrelated API compilation blockers, not Streaming behavior.
2. Generate fresh serialized Rust fixtures and run both `StreamingTab.test.tsx` and `StreamingTab.rust-contract.test.tsx` through the standard npm/Jest entrypoint with `AF_STREAMING_CONTRACT_FIXTURE`. Missing fixture generation fails the gate rather than silently skipping contract tests.
3. Run frontend TypeScript without incremental state and lint the Streaming component, utility, and both suites.

`frontend/jest.config.mjs` replaces the TypeScript config with the same Next/Jest setup, so standard `npm --workspace frontend test -- --runInBand` no longer needs an undeclared `ts-node` loader. Direct Jest runs without the fixture environment still skip the serialized contract suite; use the validation script when claiming Rust-to-React contract coverage.

### Integrated mode

After scoped checks, run integrated `af-api` tests serially, the debug API build, the full frontend test suite with the scoped Rust fixture, whole-frontend lint, and the static frontend build. Scoped success cannot override any integrated failure. This is a local build only: it neither installs the binary nor restarts services. Database migrations exercised by the scoped Rust tests use disposable temporary databases.

The script's Python regression tests simulate external command outcomes only to check orchestration: scoped versus integrated selection, missing fixtures, independent failure reporting, persistent logs, timeouts, and invalid arguments. They do not substitute for the real Rust/frontend checks.

## Recorded Local Evidence — November 2, 2026

The integrated run `dist/streaming-validation.VzbClE` passed all eleven checks with Node 22.20.0: 47 canonical streaming tests, 5 migration/backup tests, 41 scoped frontend/contract tests, 164 integrated API tests, and 274 full frontend tests across 33 suites, plus TypeScript, scoped/full lint, API build, and frontend static build. Existing lint warnings and the static-export rewrites warning remain. This checkpoint precedes the final event-import/UI and provider-wiring changes; it is not certification of later edits.

Additional targeted checks after that checkpoint pass five import/reconciliation tests, fourteen collector/dashboard tests (including first-observation/reconnect accounting), and the summary-sync server-isolation/certainty regression. The 100,000-row archive benchmark measured approximately 753 ms for first-page counts, 5.5 ms for a deep keyset page, and 4.0 seconds for a complete 100,000-row CSV on this host. These are local synthetic-fixture measurements, not deployment latency guarantees.

Both dashboard and canonical archive Rust-generated fixtures are used by the scoped gate. Tests for imports, patterns, provenance, migration, backup/restore and connected frontend workflows supplement—not replace—the external matrix below. The November 1 diagnostic timeout is retained only as historical evidence.

## Streaming-Only Publication Gate — November 2, 2026

Before committing streaming separately from concurrent McBrowser/marketplace work, the exact staged source was exported to an isolated directory. Shared Rust manifests, API module/route registration, service models and npm lockfile changes were restricted to streaming dependencies; unrelated implementations and dependencies were excluded. A minimal administrative host-filesystem boundary prevents non-admin enumeration of the newly created streaming backups, without including McBrowser lifecycle/permissions code. The mounted-router test also asserts that boundary.

After a clean offline `npm ci --ignore-scripts`, `bash scripts/validate-streaming.sh --integrated` passes all eleven checks against that isolated snapshot: 17 collector tests, 77 canonical tests, 5 migration tests, 51 scoped frontend tests, 107 actual API tests (one manual fixture ignored), all 112 frontend tests in 21 suites, TypeScript, lint and both builds. Six validator-orchestrator tests also pass. Locked manifests remain unchanged. Local evidence is retained in `dist/streaming-validation.streaming-only-jVZNBu/`; its original snapshot run directory is `streaming-validation.jVZNBu`.

The first snapshot build failed because a symlinked `node_modules` was outside Turbopack's filesystem root. Installing the locked dependencies inside the disposable snapshot resolved that setup issue without changing application source. The earlier combined-worktree counts below include concurrent features and are not the test counts for the streaming-only commit. GitHub publication does not establish live-provider acceptance or authorize production migration/restore.

## Prior Combined-Worktree Repair Gate — November 2, 2026

Command: `bash scripts/validate-streaming.sh --integrated`, Node 22.20.0. Latest evidence: `dist/streaming-validation.95isK2/` and `/tmp/af-streaming-integrated-metadata.log`. All eleven local checks pass, exit zero. This does not satisfy the external/provider or operational authorization gates.

| Check | Result |
| --- | --- |
| Collector/dashboard scoped tests | 17 passed |
| Canonical streaming scoped tests | 77 passed, including 16 metadata, 10 import/reconciliation and 8 portability tests |
| Migration/backup tests | 5 passed |
| Connected streaming frontend and all three Rust fixtures | 51 passed; no skipped contracts |
| Entire frontend suite | 40 suites, 335 tests passed |
| TypeScript and static frontend build | Passed |
| Streaming / whole-frontend ESLint | No errors; 2 / 58 warnings remain |
| Actual `af-api` tests and build | 226 passed, 2 ignored; isolated mounted-router child also passed; build passed |
| Validation-orchestrator Python tests | 6 passed separately |

Earlier `ERktCw` evidence recorded concurrent McBrowser API compilation errors; `lMi78G` later passed API tests/build but failed two unrelated McBrowser frontend tests. The latest run supersedes those local failures: both complete suites now pass. No McBrowser source was changed or tests suppressed by the metadata repair, and the passing integrated binary gate is distinct from the scoped harness. Existing compiler/lint warnings remain; no warning-free claim is made.

New regressions cover same-checkpoint fresh-event rejection and retry rollback, zero-reconnect cross-source ambiguity, missing-disk-backup rejection, cross-instance history-ID remapping with label/sample links, compact JSON download bytes, CSV cancellation on unmount, and oversized CSV stream cancellation without partial download. Incremental McSurgeon evidence is in `dist/streaming-surgery/repaired-contracts/`; its inline follow-up is not a new independent model audit or a live acceptance certificate.

The metadata increment additionally covers verified cold-start source identity, changed/disabled-source refusal, transaction rollback, original negative-cache error preservation, transient folder/ancestor retry recovery, recent-only background enrichment and single-flight cancellation. Its three completed model audits and parent repair dispositions are retained in `dist/streaming-surgery/metadata-final/`. The residual cleartext remote-HTTP credential risk is documented rather than waived.

## Disposable Browser Acceptance — November 2, 2026

[streaming-browser-acceptance.md](streaming-browser-acceptance.md) records actual browser checks against the real router/static UI and a synthetic temporary database: desktop/mobile layout, stable drilldown, compact JSON download/upload/preview without restore, linked/unlinked privacy, and keyboard refresh. The ordinary mounted-router regression uses a child process to isolate its temporary global DB pool. Browser fixture and tab were stopped/closed. No live provider or production data was used.

## Historical Local Evidence — November 1, 2026

Final command: `AF_STREAMING_CHECK_TIMEOUT=60s bash scripts/validate-streaming.sh --integrated`, with Node 22.20.0 on PATH. Results are retained locally in `dist/streaming-validation.13knxb/`; the timeout override is a diagnostic limit, not a claim that the suite cannot complete with the default ten-minute bound.

| Check | Result |
| --- | --- |
| Actual Streaming Rust modules in checked-in scoped harness | 11 passed |
| Streaming component and generated Rust-to-React contracts | 22 passed; no skipped contracts |
| Integrated `af-api` tests | 105 passed |
| Integrated debug API build | Passed |
| Frontend TypeScript | Passed |
| Streaming ESLint | No errors; one existing image-optimization warning |
| Whole-frontend ESLint | No errors; 62 existing warnings |
| Static frontend build | Passed; static-export rewrites warning remains |
| Full frontend suite | Timed out after the explicit 60-second bound; exit 124, no complete suite result |
| Validation-orchestrator Python tests | 6 passed |
| Shell syntax, new Rust harness formatting, scoped whitespace checks | Passed |

The worktree changed concurrently: an initial integrated test compile reported three McBrowser `publish_staging_file_to_browser_fs` argument mismatches; a later final run passed all 105 integrated tests. This task did not edit McBrowser implementation/tests and does not claim those repairs. The full frontend timeout has not been root-caused or waived. Both the full-suite gate and the live acceptance matrix remain open. No deployment or historical-data cleanup was performed.

## Real-Provider Acceptance — Not Yet Run

Record the commit and relevant local changes, UTC test time, Jellyfin server version, client name/version, browser/version, operator role, expected result, observed result, and evidence location for each case. Use disposable accounts/media and redact screenshots/logs; do not store API keys, session tokens, IP addresses, or identifiable private viewing history in this document.

| Case | Required evidence | Status |
| --- | --- | --- |
| Direct play / direct stream / transcode | Correct method, playing bitrate units, supported controls | Not run |
| Pause / resume | Paused intervals add no watch time or estimated transfer | Not run |
| Forward / backward seek | No playback-position-sized accounting jump | Not run |
| Reconnect / simultaneous sessions | Stable starts, singleton monitoring, no dashboard-poll double count | Not run |
| Provider disable / outage / recovery | Stale/retry feedback and expired-session removal | Not run |
| Supported / unsupported playback commands | Actual client response versus honest unsupported state | Not run |
| Admin / non-admin | Response and export redaction; administrative actions denied to non-admin | Synthetic router/browser passed; real-provider check not run |
| Keyboard / mobile | Focus, filters, pagination, controls, chart/table readability | Synthetic keyboard refresh/mobile layout passed; full real-client matrix not run |
| Missing metadata / dates / estimates | Unknown, Unrecorded, Estimated and chart-scope labels remain honest | Not run |

Do not infer any of these results from mocked upstream servers, jsdom, a successful build, or a scoped test harness. Integrated failures belong to their component owners; preserve concurrent McBrowser changes rather than suppressing tests or editing them as a Streaming fix.
