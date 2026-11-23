# Streaming Validation Gate

This document describes the automated validation gate for the canonical streaming history implementation (see [Streaming History Contract](./streaming-history-contract.md)). Passing these local checks verifies Rust and WASM contract regressions; it does not substitute for live-provider testing against real Jellyfin, Emby, or Plex servers.

## Reproducing the Checks

Run from the repository root with Rust `1.99.1` (`rust-toolchain.toml`), Node.js `24.22.2` (`.nvmrc`; `e2e/` requires Node `>= 22.19.0`), Git, GNU coreutils, and locked dependencies (`npm ci`):

```bash
bash scripts/validate-streaming.sh --scoped
bash scripts/validate-streaming.sh --integrated
python3 -m unittest discover -s tests -p test_streaming_validation.py -v
```

Each run writes logs, `summary.txt`, runtime versions, Git status, and generated synthetic Rust contract snapshots (`rust-dashboard.json`, `rust-archive.json`, `rust-portability.json`) into a fresh git-ignored `dist/streaming-validation.*` directory. No credentials, provider configuration, or real database are required. The script rejects unsupported runtimes and unknown arguments up front, runs independent checks to completion, and exits nonzero if any check fails.

Each check runs under a GNU `timeout` bound of 10 minutes with a 10-second termination grace period (timeouts fail with exit code `124`). Override via `AF_STREAMING_CHECK_TIMEOUT=20m` for slower clean builds.

### Scoped Mode (`--scoped`)

1. Runs streaming integration and contract tests inside `af-api` (`streaming_ext::tests`, `streaming_`) and `af-db` (`streaming::tests`) with `--locked`, emitting the synthetic JSON contract files and verifying `-s "${AF_STREAMING_CONTRACT_FIXTURE}"` is non-empty.
2. Runs `frontend-rs` workspace tests (`cargo test --manifest-path frontend-rs/Cargo.toml --workspace --locked`), `e2e/` TypeScript typecheck (`npm exec --workspace e2e -- tsc --noEmit --incremental false`), and `frontend-rs` Clippy (`-D warnings`; without `--all-targets` in scoped mode).

> [!NOTE]
> `scripts/validate-streaming.sh` verifies that the generated Rust contract fixture file is non-empty, whereas current `frontend-rs` unit tests exercise streaming deserialization using inline `json!()` literals rather than reading `AF_STREAMING_*_FIXTURE` environment variables at runtime.

### Integrated Mode (`--integrated`)

After the scoped checks, `--integrated` runs:

1. Serial `af-api` crate tests (`cargo test --manifest-path backend-rs/Cargo.toml --locked -p af-api -- --test-threads=1`) and a debug `af-api` build.
2. `frontend-rs` workspace tests, `frontend-rs` `--all-targets` Clippy (`-D warnings`), and the `frontend-rs` `wasm32-unknown-unknown` crate compilation check (to stage the full Trunk/WASM bundle into `web/dist/`, run `bash scripts/build_wasm_frontend.sh --stage`).

Database migrations exercised during tests operate exclusively on disposable temporary databases. The companion orchestrator test suite (`tests/test_streaming_validation.py`) validates script argument parsing, timeout handling, missing-fixture failure reporting, and log retention using mocked commands; it does not replace running the Rust and WASM suites directly.

---

## Real-Provider Acceptance Matrix (Pending)

Record commit SHA, UTC test timestamp, server version, client name/version, browser/version, operator role, expected vs. observed result, and redacted evidence paths for each case. Use disposable accounts and media; never commit API keys, session tokens, IP addresses, or private viewing history.

| Case | Required Evidence | Status |
| :--- | :--- | :--- |
| Direct play / direct stream / transcode | Accurate playback method, bitrate units, and supported controls | Not run |
| Pause / resume | Paused intervals accrue no watch time or estimated transfer | Not run |
| Forward / backward seek | No playback-position-sized accounting jump | Not run |
| Reconnect / simultaneous sessions | Stable starts, singleton monitoring, no dashboard-poll double counting | Not run |
| Provider disable / outage / recovery | Stale/retry feedback and expired-session removal | Not run |
| Supported / unsupported playback commands | Live client response vs. unsupported status (including Jellyfin vs. Emby UI/API split) | Not run |
| Admin / non-admin | Response and export redaction; administrative routes denied to non-admins | Synthetic router/browser checked; real-provider pending |
| Keyboard / mobile | Focus order, filters, pagination, controls, chart/table readability | Synthetic layout checked; full real-client pending |
| Missing metadata / dates / estimates | Unknown, unrecorded, estimated, and chart-scope labels remain accurate | Not run |
