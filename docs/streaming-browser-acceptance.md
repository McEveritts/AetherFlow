# Disposable Streaming Browser Acceptance — November 2, 2026

This is local synthetic acceptance, not a real Jellyfin/Emby client or production-data check. The ignored `streaming_http_tests::disposable_streaming_browser_acceptance_server` fixture mounted the real router and static frontend against a fresh temporary SQLite database. Providers were disabled, no monitor/application workers were started, and HTTP mutation methods were blocked except portability preview. No browser restore was executed. The fixture server and agent-owned browser tab were stopped/closed afterward.

## Observed Results

| Surface | Observed result |
| --- | --- |
| Admin desktop, 1280 × 800 | Two canonical rows; connected activity/identity drilldowns and administrative tooling rendered |
| Stable user drilldown | Alice selection set provider/server/user URL filters and retained only synthetic row 10 |
| Unknown concurrency | No samples reported Unknown/null, with gap and ninety-day retention disclosures |
| JSON download | Compact 2,670-byte archive; SHA-256 `4990daea631f8d674df39588441ec0cf3a08b9dbc0ee9c78c5e64bd1df35c284` |
| File upload and preview | Downloaded JSON selected through the file input; two history rows, one label, one policy; four exact duplicates, zero inserts/conflicts; Apply disabled without approval |
| Admin mobile, 390 × 844 | Document width 390, no viewport overflow; wide tables remained inside local horizontal scrollers |
| Linked viewer | One available/matching record, Alice's synthetic movie; Bob's movie absent; no portability apply UI; history response omitted private IP/device evidence |
| Unlinked viewer | HTTP 200 with empty items and all counts zero; explicit no-linked-history empty state; no portability apply UI; no viewport overflow |
| Keyboard | Tab moved from Reset Filters to Refresh Snapshot; Enter triggered refresh and the scoped empty-state snapshot rendered afterward |

The fixture injects `window.__AF_DISABLE_WS__` into its root HTML only, exercising the existing polling fallback without launching a websocket worker. The browser harness normalized API-fetch user agents differently from top-level navigation; fixture login through a same-origin fetch resolved that test setup mismatch without weakening production session checks. No cookies, approval tokens or provider credentials are retained here.

## Reproduction and Limits

Build the static frontend, then run the ignored fixture with `STATIC_DIR="$PWD/frontend/out" AF_STREAMING_BROWSER_ACCEPTANCE=1 cargo test --manifest-path backend-rs/Cargo.toml --locked -p af-api streaming_http_tests::disposable_streaming_browser_acceptance_server -- --ignored --exact --nocapture --test-threads=1`. Its randomized loopback login URLs are printed per run. Do not reuse an old nonce or point the fixture at an existing database.

The ordinary mounted-router regression runs in a separate child test process: changing `DB_PATH` and initializing the one-connection global pool cannot contaminate the parent runner. That automated regression separately checks authorized disposable restore, backup, stale approval rejection and unrelated-user preservation. Browser preview success is not evidence that a browser restore occurred.

Still required: real Jellyfin/Emby clients, actual provider metadata/authentication contracts, pause/seek/reconnect/transcode controls, authorized deployment-copy migration/restore, and release authorization. No deployment, live cleanup, provider request or production database operation was performed for these checks.
