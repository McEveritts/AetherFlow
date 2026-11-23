# AetherFlow peer clustering preflight drift

This audit compares the original design’s 79 distinct line citations against `origin/nightly` at `447e04fe`. The original code baseline was `702ae0d2`. The [ten-phase revision](peer-clustering.md) preserves all 52 numbered entries and reorganizes their delivery.

## Before You Start checklist

| Requirement | Status on `447e04fe` |
| --- | --- |
| Branch and reference audit | The local feature branch is based on fetched nightly, 197 commits past `702ae0d2`. The citations are audited below. |
| Debian and Jellyfin apt state | Server A runs Debian 13.7 with Jellyfin `12.4+deb13` and `jellyfin-ffmpeg8` `8.1.3-1-trixie`. Both servers target Jellyfin 12.4 per the operator’s decision. Verify the matching apt state after B is provisioned. |
| Addresses and UDP 51821 | Server B is awaiting provisioning. Confirm its SSH destination, both VLAN addresses and end-to-end UDP reachability after provisioning. |
| Toolchain and artifact delivery | Server A has Rust 1.99.1, the WASM target, Trunk 0.22.1 and wasm-bindgen 0.2.130. Both workspace release builds passed with task-local `mold` for the backend. Artifact delivery to both hosts is unverified. |
| Test media and transcode worker | Server A's Intel VA-API device reported hardware encoding support in `vainfo`. The worker assignment and test media library are unverified. |
| Unmodified nightly tests | Frontend passed 338 tests. Two default backend runs stopped in `af-api` at 668 passed, 1 failed and 2 ignored, with different McBrowser upload cleanup failures. A third default run passed `af-api` and stopped in `af-runner` at 1,389 passed across the workspace, 7 failed and 4 ignored. All 34 focused upload tests passed. The serial CI fixture run passed 1,615 tests with 4 ignored. |

Using the same CI fixture environment, a focused `af-runner` run passed 353 tests and failed 21 in parallel. Running the same tests serially passed all 374 active tests. Each run reported two ignored tests. The prerequisite repair is tracked separately from the ten feature phases.

The local McBrowser prerequisite commit `2c9f7032` isolated the upload-expiry fixtures from the process-global user locks. The next default workspace run passed all 670 active `af-api` tests and stopped in `af-runner`, with 1,390 passed across the workspace, 7 failed and 4 ignored. A separate default `af-services` run passed 219 tests.

The `af-runner` prerequisite `f88aaeb0` isolated package fixture environment, hooks and cancellation state. With both prerequisite commits, the default backend workspace suite passed 1,616 tests with four existing ignores. The local feature branch includes the prerequisite commits beneath the phase commits.

## Local implementation while server B is pending

The operator authorized building the feature on A while B awaits provisioning. Each phase requires a passing local gate before its successor begins. The same phase commits retain their two-server acceptance checks in order after B is ready. Keep those checks pending in phase reports until they are run. The release still requires two-server acceptance, and P9 retains its standalone regression.

## Verification command drift

The Trunk configuration and HTML entry point are in `frontend-rs`. The app crate directory has no `index.html`, and Trunk exits before compiling there. Run `trunk build --release` from `frontend-rs`, as `scripts/build_wasm_frontend.sh` does. The corrected command succeeded on A with an isolated output directory. The built index and both WASM files were verified.

## Ten-phase decisions

| Phase | Decision | Reason |
| --- | --- | --- |
| P7 and P9 | Use Jellyfin 12.4 on both servers and verify matching installed Jellyfin and ffmpeg packages. | The operator selected 12.4, which is installed on server A. |
| P0 | Keep migration numbers 25 and 26. Store the incoming link hash and pending attempt state in `peer_links`. Keep the separate grant hash in `peer_grants` and allow clearing it on revocation. | P3 pairs and checks health before grants exist. Grant revocation in P5 must preserve the link. |
| P0 | Serve the initial empty capability list in the current health handler. File 12 introduces the shared capability function in P3. Preserve the existing audit error reporting. | The peer module starts in P3 and the audit change is already in nightly. |
| P1 and P6 | Use thread-local standard-library state in `af-web-core` and the app’s existing reactive state in P6. Rewrite current telemetry and test the log URL in P1. P6 owns the live-log client. | The core crate has no Leptos dependency and currently opens one telemetry socket. |
| P2–P4 | Land a dormant runner in P2. Add the tunnel listener and pending, pinned-peer hello exchange in P3. Keep legacy runtime and UI through that API gate and retire them with migration 26 in P4. | Pairing and revoke require a real tunnel endpoint. The legacy enrollment patterns are still available while P3 is being integrated. |
| P5–P6 | Verify separate link and grant credentials. P5 tests target-side authorization, and P6 adds the managing proxy, server switching and WebSocket revocation. | The listener must enforce grants before the browser can proxy requests. Link health stays available after grant revocation. |
| P7 | Handle an explicitly removed WireGuard peer on the first health tick. Keep the pair of sentinel failures for transient NFS health detection. | The forced peer-removal gate requires the mount to stop within 30 s. |
| P8–P9 | Add the transcode library and local worker fixtures in P8. Publish the binary inside the server bundle and enable it in P9. Local fallback applies before remote start. A dropped active stream ends the current job and allows a local retry. | The API needs the shared codec and argv types. The installer needs a bundled executable. Jellyfin’s retry handles a remote loss without duplicating a running job. |

## File ownership changes

Several current targets sit in files absent from the original lane list. File 1 includes the schema test in `af-db/src/tests.rs`. File 3 includes `af-api/src/routes/health.rs`. File 8 includes the child modules under `af-services/src/cluster_daemon/`. File 10 includes the legacy handlers and the cluster portions of mixed tests under `af-api/src/intelligence/`. File 11 includes two OIDC child modules. File 22 includes the runner client and unit policy modules. Files 32–34 include the current middleware, auth, backup and WebSocket child modules. Assign each of those files one owner in its phase.

Files 12, 17, 18, 22, 30 and 32 spell out the portions applied in each phase. P7 and P9 also extend earlier API and frontend modules. Their phase briefs identify the sole owner of each changed path.

## P0 integration decisions

- Migration 25 uses `CREATE TABLE IF NOT EXISTS`, following the existing migration conventions. The nine table definitions and the users column match the design. `PeerIdentity` treats row ID 1 as an internal singleton key.
- The coordinator updated the API backup fixture’s max-version assertion in `af-api/src/storage/backup_tests.rs` to 25. The P4 API cleanup lane updates the same fixture when migration 26 becomes the maximum version.

- The P0 reviewer identified unbounded request IDs and gaps in direct CRUD test coverage. The coordinator bounded IDs to 128 ASCII identifier bytes, reused one header value for request and response, and extended the existing tests. Existing short identifier values keep their correlation behavior.

## P1 direct URL audit

The file 7 scan confirmed more direct authenticated browser URLs in `af-web-app/src/tabs/mcbrowser/editor.rs` and `af-web-app/src/tabs/mcbrowser/mod.rs`, including media, previews, thumbnails and downloads. The P1 app lane owns these files for that scope. The Streaming history and portability exports already use `ApiClient::fetch_raw_body_with_signal` and get the core rewrite there. Public anonymous shares preserve their existing destinations.

- Dashboard sign-in, session lookup, refresh, sign-out, CSRF issuance, credential changes, OIDC consent and pairing use the managing server. The authenticated request builder also handles those calls, so P1 explicitly keeps their destinations local during a peer selection. P6 must preserve this session when an upstream peer rejects authorization and hide local password, 2FA and session controls in the remote Settings view.
- The P1 review found that browser URL normalization can change the destination of a malformed path. Reject controls, backslashes, duplicate API separators and browser-normalized dot segments before prefixing or sending a request. The direct URL helper substitutes a same-page fragment for malformed root-relative input. Refresh CSRF exemptions apply only to the local endpoint, matching the server middleware.
- The Profile Security avatar is also a direct browser request and now uses `api_url` after validation.
- The Plugin Sandbox iframe and its message bridge stay local. P5 denies the remote iframe route. P6 closes an open local sandbox on a reactive server switch.
- Backup download initiation already uses `ApiClient`. P1 captures the corresponding native download URL when starting the POST so the GET goes to the same server. P6 must scope the download ticket cookie and use the grant for remote step-up without forwarding the local password.
- P6 must teach the McBrowser tus client to accept the selected peer's upload path in a rewritten `Location` response.
- When P6 enables reactive switching, fence asynchronous telemetry, McBrowser subtitle loading and backup downloads by server selection. Check that remote update readiness polls the selected server's authenticated readiness endpoint.

## P2 runner integration

- File 22 includes the dispatcher in `runner_client.rs`. The socket handler lives in `peer_network.rs`, with an injectable manager for isolated fixtures. The shared dump parser in `network.rs` discards private and preshared keys and preserves the legacy status format.
- The local WireGuard address uses the configured subnet prefix so live `wg syncconf` updates have a connected subnet route. Each peer still gets a single-host `AllowedIPs` entry. The runner checks the kernel subnet route and checks a newly synced peer's effective route before accepting the change. It restores the previous disk and live configurations if the route check fails.
- The runner uses the existing Marketplace apt command path and whole-system lifecycle reservation for `wireguard-tools`, a Debian package under the catalog's `wireguard` entry. It bounds lock waits and command deadlines, waits for process-group cleanup, and creates no Marketplace app receipt.
- Held link and grant credentials use their planned files. Pending issuer credentials live in `pending/<attempt>.token` with root-only permissions. Rollback and strip files live in the root-only `.staging` directory. The runner uses directory-anchored file operations and returns credential values in a redacting type over its Unix socket.
- The runner client exposes distinct busy, already-present peer, missing peer and tunnel-IP conflict outcomes for P3 retries. Status also distinguishes persistent peers from peers present in the live dump so P7 can detect an explicitly removed peer. Status and mutations share exclusion, and credential operations have their own lock.
- The local tests use isolated files, sockets and commands. Verify the actual Debian WireGuard service, routing and package behavior during approved two-server acceptance.

## P3 capability advertisement

File 12 advertises `["links"]` on `/health` once the linking implementation is available. The capability describes protocol support before first pairing. The peer listener itself waits for a configured tunnel identity. The P3 API lane also owns the existing `/health` regression in `af-api/src/routes/tests/security_and_account.rs` for this change. Update its exact capability assertion and keep its protocol, response header and liveness coverage.

## Line citations

A cited location beyond the current file length is marked **Past EOF**. The corrected targets identify the current implementation or, for unchanged citations, the verified original target.

| Cited location | What is there on `447e04fe` | Corrected target |
| --- | --- | --- |
| `backend-rs/crates/af-db/src/lib.rs:L939-948` | Past EOF | `lib.rs:197–206`, legacy `cluster_nodes` table. |
| `backend-rs/crates/af-db/src/lib.rs:L1166` | Past EOF | `lib.rs:445`, legacy index statement in migration 5. File 19 removes it in P4 as part of fresh database compatibility. |
| `backend-rs/crates/af-db/src/lib.rs:L1472` | Past EOF | `lib.rs:751–768` is v23, including at the original anchor. Streaming v24 runs at `lib.rs:712` through `streaming.rs:135,174–211`. Migration 25 can follow the v23 verification in `init_db`, after the v24 call. |
| `backend-rs/crates/af-db/src/lib.rs:L2277-2303` | Past EOF | `audit.rs:25–53`. The existing `record_audit` already logs a writer acquisition or insert failure with `tracing::error!`. |
| `backend-rs/crates/af-db/src/lib.rs:L3198-3200` | Past EOF | `tests.rs:194,212–215`, max-version assertion. Preserve the separate v24 collision tests in `streaming_tests.rs`. |
| `backend-rs/crates/af-api/src/routes.rs:L11-12` | Start of `intelligence` import | `routes.rs:14–15`, legacy cluster symbols in that import. |
| `backend-rs/crates/af-api/src/routes.rs:L150-180` | End of an import block and following imports | `routes.rs:244–274`, `security_headers_middleware` and request ID handling. Router construction is at `400–439`. |
| `backend-rs/crates/af-api/src/routes.rs:L206-274` | Package-update imports at the start, then middleware | `routes.rs:300–368`, including the `SAMEORIGIN` exception at 300 and the default `DENY` at 302. |
| `backend-rs/crates/af-api/src/routes.rs:L338` | Deprecation-header code | `routes.rs:432` registers `/health`. Response fields belong in `routes/health.rs:10`. |
| `backend-rs/crates/af-api/src/routes.rs:L387-389` | Successor-version header construction | `routes.rs:481–483`, WebSocket and ticket routes in the auth router that is nested at 813. |
| `backend-rs/crates/af-api/src/routes.rs:L558-563` | Other authenticated routes | `routes.rs:652–657`, legacy cluster routes. |
| `backend-rs/crates/af-api/src/main.rs:L234-239` | Blank line, then logger initialization | `main.rs:235–240`, tracing subscriber setup. |
| `backend-rs/crates/af-api/src/main.rs:L265-282` | Worker-enable guard, then reconciliation task | `main.rs:266–283`, package-job reconciliation. |
| `backend-rs/crates/af-api/src/main.rs:L314` | Metrics recorder startup | `main.rs:321`, legacy cluster runtime startup. |
| `backend-rs/crates/af-api/src/middlewares.rs:L838-1360` | Past EOF in module facade | `middlewares/subdomain_proxy.rs:29–702`, current proxy split with additional upstream paths. Keep existing portal behavior when extracting common transport. |
| `backend-rs/crates/af-api/src/middlewares.rs:L987-1120` | Past EOF in module facade | `middlewares/subdomain_proxy.rs:178` starts upgrade detection. The live branches include the response handling at 326, 471 and 572. |
| `backend-rs/crates/af-api/src/middlewares.rs:L1600-1665` | Past EOF in module facade | `middlewares/host_validation.rs:101`, `host_validation_middleware`. |
| `backend-rs/crates/af-api/src/auth.rs:L114-116` | Past EOF in module facade | `auth/tokens.rs:110`, `load_active_human_subject`, also the target of the shorthand L114 in file 33. |
| `backend-rs/crates/af-api/src/auth.rs:L1139-1155` | Past EOF in module facade | `auth/middleware.rs:330`, `admin_only_middleware`. |
| `backend-rs/crates/af-api/src/auth.rs:L1179-1232` | Past EOF in module facade | `auth/middleware.rs:373`, `csrf_middleware`. |
| `backend-rs/crates/af-api/src/storage.rs:L1201` | Past EOF in module facade | `storage/backups.rs:632,648`, prepare-download reauthentication. |
| `backend-rs/crates/af-api/src/storage.rs:L1415` | Past EOF in module facade | `storage/backups.rs:857,878`, backup-download reauthentication. |
| `backend-rs/crates/af-api/src/ws.rs:L876` | Past EOF in module facade | `ws/tickets.rs:132`, telemetry ticket revalidation. |
| `backend-rs/crates/af-api/src/ws.rs:L1100` | Past EOF in module facade | `ws/tickets.rs:150`, telemetry upgrade origin check. |
| `backend-rs/crates/af-api/src/ws.rs:L1167` | Past EOF in module facade | `ws/tickets.rs:217`, active session subject recheck. |
| `backend-rs/crates/af-api/src/ws.rs:L1565` | Past EOF in module facade | `ws/logs.rs:314`, log upgrade origin check. |
| `backend-rs/crates/af-api/src/ws.rs:L1591` | Past EOF in module facade | `ws/logs.rs:340`, initial live-log authorization check. Later checks also use `current_ws_authorization`. |
| `backend-rs/crates/af-api/src/plugins.rs:L39-66` | Facade re-exports, then EOF | `plugins/manifest.rs:10–36`, default deny prefixes. |
| `backend-rs/crates/af-api/src/plugins.rs:L287-312` | Past EOF in module facade | `plugins/manifest.rs:42–84`, default deny and administrator-only write policy. |
| `backend-rs/crates/af-api/src/plugins.rs:L418-449` | Past EOF in module facade | `plugins/manifest.rs:183–218`, `route_pattern_matches`. |
| `backend-rs/crates/af-api/src/app_launch.rs:L18` | App session cookie constant | Same target, `APP_SESSION_COOKIE`. |
| `backend-rs/crates/af-api/src/app_launch.rs:L93-149` | Managed TLS vhost and app URL construction | Same target, `managed_tls_vhost` and associated launch validation. |
| `backend-rs/crates/af-api/src/mcbrowser.rs:L199-215` | Closing brace, then user validation | `mcbrowser.rs:200–216`, `validate_mcbrowser_user`. |
| `backend-rs/crates/af-api/src/mcbrowser/uploads.rs:L2568` | Past EOF in module facade | `mcbrowser/uploads/session.rs:244`, upload `Location` when reusing a session. |
| `backend-rs/crates/af-api/src/mcbrowser/uploads.rs:L2927` | Past EOF in module facade | `mcbrowser/uploads/session.rs:602`, upload creation `Location`. |
| `backend-rs/crates/af-api/src/intelligence.rs:L5899` | Past EOF in module facade | `intelligence/cluster.rs:8`, `get_cluster_nodes`. Remove the re-export at `intelligence.rs:24–27` with the legacy module. |
| `backend-rs/crates/af-api/src/intelligence.rs:L6183-6213` | Past EOF in module facade | `intelligence/cluster.rs:315`, `enroll_worker`. |
| `backend-rs/crates/af-api/src/intelligence.rs:L6215-6243` | Past EOF in module facade | `intelligence/cluster.rs:342`, `remove_worker`. The same module has dispatch at 389 and list at 504. |
| `backend-rs/crates/af-api/src/intelligence.rs:L6337` | Past EOF in module facade | `intelligence/cluster.rs:529`, `get_worker_metrics`. |
| `backend-rs/crates/af-api/src/intelligence.rs:L6609-6674` | Past EOF in module facade | `intelligence/media_cluster_tests.rs:290` contains the cited enrollment test. That file also has mixed-purpose tests at 402 and 494 and added legacy command tests at 647. Preserve coverage for non-cluster behavior. |
| `backend-rs/crates/af-api/src/oidc.rs:L380` | Past EOF in module facade | `oidc/keys.rs:374`, legacy constant-time comparison call. |
| `backend-rs/crates/af-api/src/oidc.rs:L1137` | Past EOF in module facade | `oidc/token_endpoint.rs:141`, stored-hash comparison. |
| `backend-rs/crates/af-api/src/oidc.rs:L1160` | Past EOF in module facade | `oidc/token_endpoint.rs:164`, challenge comparison. |
| `backend-rs/crates/af-services/src/cluster_daemon.rs:L716-740` | Past EOF in module root | `cluster_daemon/auth.rs:156–180`, single-use enrollment minting and digest storage. |
| `backend-rs/crates/af-services/src/cluster_daemon.rs:L968-986` | Past EOF in module root | `cluster_daemon/membership.rs:200–218`, atomic single-use enrollment consumption. |
| `backend-rs/crates/af-services/src/lib.rs:L1` | `pub mod cluster_daemon` | Same declaration. The current legacy module also includes a child module tree. |
| `backend-rs/crates/af-runner/src/lib.rs:L3329` | Past EOF in split runner root | `sandbox_ops.rs:13–45`, exempt-systemd-unit policy and WireGuard condition at 35. |
| `backend-rs/crates/af-runner/src/lib.rs:L3670` | Past EOF in split runner root | `sandbox_ops.rs:449`, systemd sandbox drop-in fallback. |
| `backend-rs/crates/af-runner/src/lib.rs:L5166` | Past EOF in split runner root | `network_quota_handlers.rs:3`, `handle_network`. Adjacent route registration is `lib.rs:361`. |
| `backend-rs/crates/af-runner/src/lib.rs:L6940` | Past EOF in split runner root | `runner_client.rs:856`, `dispatch_network_control`, re-exported by `lib.rs:664`. |
| `backend-rs/crates/af-runner/src/network.rs:L452` | Saved WireGuard identity validation | Same target. Use the pattern in the new peer module. |
| `backend-rs/crates/af-runner/src/network.rs:L820` | Live versus saved WireGuard identity status | Same target. |
| `backend-rs/crates/af-runner/src/network.rs:L926` | Pre-mutation WireGuard identity guard | Same target. |
| `backend-rs/crates/af-runner/src/network.rs:L1007` | Recovery failure after WireGuard save | Same target. |
| `backend-rs/crates/af-runner/src/app_metadata.rs:L602-621` | Past EOF in module facade | `app_metadata/extractors_media.rs:270–297`, Jellyfin database and config paths. |
| `backend-rs/crates/af-runner/src/package_executor/declarative_recipes.rs:L1920-1924` | Past EOF in module facade | `package_executor/declarative_recipes/catalog.rs:1192–1201`, separate rclone RC and VFS units. This remains an alternatives reference. |
| `backend-rs/crates/af-models/src/constant_time.rs:L4` | `constant_time_eq` | Same reusable helper. |
| `backend-rs/crates/af-hardware/src/lib.rs:L180-246` | `GpuFlags` and detection code | Same target. |
| `backend-rs/crates/af-hardware/src/lib.rs:L189-246` | `get_gpu_transcode_flags` | Same target for splitting out render-node detection. |
| `frontend-rs/crates/af-web-core/src/api.rs:L165-202` | CSRF prefix checks | Same target. Apply the match to both local and peer-prefixed forms. |
| `frontend-rs/crates/af-web-core/src/api.rs:L806-860` | `ApiClient` builders | Same target. Coordinate their rewriting with file 6 so each request is prefixed once. |
| `frontend-rs/crates/af-web-core/src/ws.rs:L280` | Telemetry ticket request through `ApiClient` | Same target. |
| `frontend-rs/crates/af-web-core/src/ws.rs:L307-311` | Telemetry socket URL format | Same target. The current core has one WebSocket constructor. |
| `frontend-rs/crates/af-web-app/src/tabs/mediaflow.rs:L374` | Component fallback markup | `tabs/mediaflow.rs:416`, direct deploy EventSource URL. |
| `frontend-rs/crates/af-web-app/src/shell.rs:L1172` | Profile avatar safety test | The production avatar source is `shell.rs:761`. Rewrite the validated API URL at that caller. |
| `frontend-rs/crates/af-web-app/src/tabs/fileshare/local_storage.rs:L578` | Fileshare download URL format | Same target. |
| `frontend-rs/crates/af-web-app/src/tabs/mcbrowser/helpers.rs:L488` | Subtitle URL allowlist check | Same target. `safe_subtitle_url` is a validator at 486–495. Keep validation when routing the eventual request. |
| `frontend-rs/crates/af-web-app/src/tabs/streaming/live.rs:L67` | Streaming artwork URL | Same target. |
| `frontend-rs/crates/af-web-app/src/tabs/settings/backups_oidc.rs:L123` | Early `return` | `tabs/settings/backups_oidc.rs:156` builds the download path. The POST already uses `ApiClient::fetch_raw_body`. Route the subsequent native download anchor through `api_url`. |
| `setup/modules/00-core.sh:L117-129` | Later distro-reporting logic | `setup/modules/00-core.sh:95–112`, Debian trixie detection in the os-release and lsb_release paths. |
| `docs/API.md:L116-126` | FlowAI table tail and cluster section header | `docs/API.md:122–142`, all of section 8, including added worker-receipt notes. |
| `docs/configuration.md:L114-115` | Release-related configuration flags | `docs/configuration.md:117–118`, `CLUSTER_MODE` and `CLUSTER_PSK`. |
| `docs/architecture.md:L15` | Cluster component in architecture diagram | Same target. |
| `docs/architecture.md:L33` | Control-plane subsystem description | Same target. |
| `docs/architecture.md:L56` | Background workers and cluster description | Same target. |
| `config/openapi-v1.yaml:L725` | Previous operation's request-body schema | `config/openapi-v1.yaml:729–894`, cluster operations. The cited enrollment description moved to 735. |
| `config/package_automation.json:L20-38` | Jellyfin apt automation entry | Same target. |
| `config/package_automation.json:L24-38` | Jellyfin `dotnet` sandbox and related options | Same target. |
| `config/package_automation.json:L25-34` | Jellyfin `sandbox_rw_paths` | Same target for the optional dispatcher socket path in P4. |
