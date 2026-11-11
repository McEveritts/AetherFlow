## Nightly Patch Notes — November 11, 2026 — Release Test Isolation

* Make the runner's rclone version-extraction regression use an isolated package catalog and mock executable while preserving the production version regex and receipt-certification assertions. The release tests no longer depend on rclone or AetherFlow being installed on the CI host.
* Restore the test's catalog environment before checking its result so an assertion failure does not leak fixture configuration to later tests. Keep production probes and all release security gates unchanged.

## Nightly Patch Notes — November 10, 2026 — SQLite Security, Open Canvas UI & Marketplace Lifecycle

Marketplace lifecycle, installer reliability, update certification, and diagnostic-safety improvements since `2d3715e4` (`v4.0.0-nightly.101.2`). These notes describe source changes; they do not claim successful live installation of every catalog application.

### SQLite Security Follow-up

* Upgrade the bundled SQLite dependency family through `rusqlite` 0.41.1, `r2d2_sqlite` 0.36.0, and `libsqlite3-sys` 0.39.1 to address RUSTSEC-2026-0459 (CVE-2026-119375), a local crafted database/WAL information-disclosure advisory.
* Require bundled SQLite 3.54.0 or newer in a runtime regression test. Preserve checked unsigned-integer SQL conversions through the driver's `fallible_uint` compatibility feature, with coverage for maximum signed values, ordinary offsets, and rejected negative values.
* Keep existing database migrations, WAL reader isolation, and all advisory-policy exceptions unchanged. This follow-up does not add new advisory exemptions, deploy to running hosts, or restart services.

### Release-Core Compatibility

* Replace positional lifecycle completion diagnostics with named fields across the shared release core, privileged runner, and job coordinator. Preserve completion identity, outcome details, timestamp handling, and persisted secret redaction.
* Resolve strict release-core Clippy failures without relaxing lint or security gates, and remove an ineffective runner lint attribute.

### Open Canvas UI Included

* Include the existing open-canvas UI nightly: continuous obsidian surfaces, the unboxed luminous logo, a docked collapsible sidebar, improved keyboard focus, and clearer mobile navigation state.
* Reflow constrained McBrowser and Audit tables into labeled ledgers, improve overlay/dropdown positioning and settings navigation, preserve background uploads, and dismiss transient file dialogs when leaving their tab.
* Restore native Settings submission, preserve draft edits, clarify semantic action colors, simplify duplicate controls, and align Services controls and stopped-service counts.
* Known UI follow-ups remain: a narrow Streaming tooltip can clip by 17 CSS pixels, and File Share copy still confuses its per-file limit with transport chunk size. Visual review used synthetic fixtures rather than live-backend or physical-touch certification.

### Marketplace Updates & Inventory

* Keep authenticated installed-app inventory distinct from the public, redacted catalog. Session expiry and unavailable inventory no longer silently turn installed apps into provisioning candidates.
* Preserve a previously known update while reporting release-check freshness and discovery errors separately. Coalesce noisy package-progress inventory refreshes while refreshing terminal outcomes immediately.
* Track accepted jobs by lifecycle identity, retain terminal outcomes, and reconcile polling, event updates, interrupted requests, and authentication changes without accepting stale completion signals.
* Require an admitted target and matching achieved version before certifying an update. Use explicit candidate receipts, strict commit identities, and complete component manifests rather than treating any successful process exit as proof of the requested update.

### Installer & Recovery Reliability

* Harden Rclone GUI/service compatibility, credential handling, target selection, staged replacement, and rollback of both the primary and VFS services.
* Improve Piped component provenance and transactional recovery, Invidious build diagnostics and scratch preflight, KasmVNC TLS/runtime setup, and FileBot lifecycle handling.
* Align release/version tracking for Calibre-Web, Listenarr, Maintainerr, McVNC, Organizr, pyLoad, Readarr, Seedcross, Tautulli, Uptime Kuma, and the supported Servarr applications.
* Make release discovery more resilient to unavailable upstream metadata and GitHub rate limits; distinguish ordering from exact installed-version identity.
* Route privileged host changes through the runner, strengthen lifecycle admission/finalization and cancellation handling, and retain recovery evidence when restoration cannot complete.
* Clean up partially captured runtime snapshots after capture failure without deleting backups needed for an incomplete rollback. Check scratch capacity before destructive work.

### Diagnostic Safety

* Restrict Marketplace lifecycle diagnostics to human administrators. Dedicated and legacy plugin read scopes retain authorized inventory access without gaining operator-only failure details.
* Apply shared sensitive-key rules to scalar fragments, containers, and persisted diagnostics, including long Unicode-escaped keys and repeatedly wrapped receipts. Preserve genuinely closed quoted command context while masking credential tails.
* Sanitize durable failure receipts and authenticated API/WebSocket diagnostics, including multiline and whitespace-leading quoted values, attached curl credentials, partially masked values, encoded sensitive keys, and malformed or truncated sensitive containers. Remove intermediate diagnostic debug output.
* Keep detailed Python and awk receipt masking consistent. When neither interpreter is available, redact complete diagnostic fields rather than risk leaking sensitive suffixes; the receipt remains valid JSON with its numeric exit code.
* Bound receipt fields without SIGPIPE-induced exits or operating-system argument-size failures, including long installer diagnostics.
* Expand Rust, Python, and frontend regression coverage for target certification, recovery cleanup, diagnostic masking, inventory boundaries, and lifecycle reconciliation.

### Rollout Notes

* Keep the API, runner, shared installer helpers, package scripts, catalog metadata, and frontend on the same release revision.
* A branch push triggers the existing nightly build/publication workflow; it does not itself verify or authorize a live host update or service restart.
* Automated source/fixture checks are recorded, but the final independent Terra Max and Sol Max review requests were blocked by the provider and produced no approval. This publication does not claim independent review completion or live rollout certification.

---

## Nightly Patch Notes — November 10, 2026 — Open Canvas UI

This UI-focused nightly refresh improves the dashboard's open-canvas presentation, responsive layouts, and operator controls. It does not include the separate Marketplace lifecycle, backend, or package-installer changes under development.

### Interface & Navigation

* Extend the continuous obsidian canvas across operational tabs and sign-in, consent, and shared-file screens, using aligned content and subtle separators instead of floating page-card islands.
* Preserve the unboxed luminous AetherFlow logo, docked collapsible sidebar, and cyan, indigo, fuchsia, emerald, and amber status accents.
* Improve sidebar pinning, keyboard-focus expansion, and active-section feedback in the mobile navigation menu.
* Keep the McBrowser workspace mounted when navigating between tabs so returning to it preserves workspace state.
* Dismiss transient McBrowser dialogs when navigating away, releasing their focus trap without interrupting background uploads.

### Responsive Controls & Readability

* Reflow McBrowser workspace selections and Audit Trail records into labeled ledgers when available content width is constrained; wrap long identities and paths while keeping actions within reach.
* Improve viewport-aware dropdown and account-menu positioning, scrollable settings navigation, visible scroll controls, and keyboard access.
* Restore native Enter-key submission through the single Settings save action, keep focused settings tabs visible, and preserve manual rail scrolling during resize.
* Clarify approval/rejection button accents, use dark-glass checkboxes, improve modal focus handling, and reduce redundant quota and settings controls.
* Retain the latest Services Connection-control alignment fix and make stopped-service filter counts consistent with the displayed list.

### Scope & Rollout

* This release changes the frontend and release-note/validation plumbing only. Existing backend code, installer scripts, catalog metadata, and Marketplace lifecycle behavior are not upgraded by this change set.
* Nightly artifacts retain the existing `v4.0.0-nightly.<run>.<attempt>` naming and prerelease status. Publishing an artifact does not update running hosts or authorize a service restart.
* Automated publication now includes these patch notes and checks frontend test-file TypeScript in addition to lint, unit tests, and static-export compilation.

### Known Follow-ups

* A pointer-triggered transferred-data tooltip can clip at the right edge of the 390px Streaming view. The recorded narrow-viewport case clips by 17 CSS pixels.
* File Share still labels its 50MiB per-file limit as “50MB Chunk Streaming” while separately describing 5MiB transport chunks; copy clarification remains pending.
* The independent visual review used synthetic fixtures. It does not certify live backend integrations, real uploads, physical-touch behavior, or every production service.

---

## CHANGELOG v4.0.0 - 11-Crate Rust Control Plane, 77-App Bare-Metal Catalog, Native McBrowser & Self-Update Engine
_Promotes the v4.0.0 Rust control plane architecture and `nightly` / `experimental` advancements to the `master` (`stable`) track (`v3.2.7...v4.0.0`)._

---

### Release Highlights (since `v3.2.7`)
* **Eleven-Crate Single-Binary Rust Control Plane, Runner & Unified Admin CLI (`backend-rs`)**: Replaced the legacy Go runtime with an 11-crate Rust workspace (`af-models`, `af-files`, `af-db`, `af-hardware`, `af-runner`, `af-release`, `af-host`, `af-cli`, `af-services`, `af-api`, `af-streaming-tests`) built on **Axum 0.7** and **Tokio**. Preserves the `aetherflow-api` binary name, `aetherflow-api runner` root UNIX socket daemon (`/run/aetherflow/runner.sock`), embedded Next.js 16 (Obsidian V2) static SPA (`rust-embed`), bundled SQLite WAL persistence (eliminating Redis runtime requirements), and existing JWT/TOTP/AES-256-GCM (`enc:v1:`) credential formats while adding the unified **`af` (`af-cli`)** administrative CLI.
* **Native McBrowser (`af-files`)**: Integrated a capability-scoped tenant file manager directly into the dashboard sidebar and Rust API (`/var/lib/aetherflow/mcbrowser`, mode `0700`) with resumable chunked uploads up to 64 GiB, ETag-guarded UTF-8 editing (up to 10 MiB) with Ace + Markdown/KaTeX preview, 9-format archive creation/extraction, password-protected public shares, and FlowAI natural-language BFS file search.
* **77-Application Bare-Metal Catalog & Lifecycle Hardening**: Expanded AetherMarketplace to **77 native Linux packages** across 7 domains—adding **Palate** (Culinary & Nutrition AI), **Maintainerr**, **McVNC** (Rust GPU Remote Desktop), **KasmVNC**, **XRDP**, **Tailscale**, **Piped** *(Experimental)*, and **Invidious** *(Experimental)*—alongside 15 built-in declarative Rust package recipes in `af-runner`, Dispatcharr v0.33.0 Daphne/editable-wheel fixes, and active-release script path resolution.
* **Isolated Self-Updater (`aetherflow-self-update.service`) & Executable Verification**: Isolated control-plane self-updates into a dedicated `aetherflow-self-update.service` systemd unit with atomic `0600` credential handoffs so restarting `aetherflow-runner` and `aetherflow-api` never kills the updater. Verified running physical binary paths before marking deployments complete and accepted legacy completed deployment journals cleanly.
* **Canonical Streaming History, Insights & Portability**: Added `/api/v1/auth/streaming/history` and `/export` with rolling/calendar windows, server-identity verification (`/System/Info/Public`), asynchronous library/genre enrichment, 8 MiB JSON portability archives, 128 MiB streaming CSV exports, and backup-verified reconciliation gates.
* **Native WireGuard & Tailscale Network Control Center**: Added `/api/v1/admin/network/*` and the **Network** UI tab for persistent `wg0` peer management, one-time in-memory client keypair/QR handoff, and Tailscale login, subnet route advertisement, and exit-node controls.
* **Decoupled Navigation & Frame-0 Telemetry Performance**: Decoupled sidebar navigation layout state from high-frequency WebSocket telemetry updates (`useHistoryStore`, `useMetrics`) to eliminate UI re-render contention.

---

## CHANGELOG v4.0.0-experimental - Rust Control Plane & Release Manager Fixes
_Direct comparison against `v3.2.7` (`v3.2.7...v4.0.0-experimental`)._

---

### Release Highlights (since `v3.2.7`)
* **Nine-Crate Rust Control Plane, Runner & Admin CLI (`backend-rs`)**: Replaced the Go backend with a nine-crate Rust workspace (`af-models`, `af-db`, `af-hardware`, `af-runner`, `af-services`, `af-release`, `af-host`, `af-cli`, `af-api`) built on Axum and Tokio. Preserves the `aetherflow-api` binary name, `aetherflow-api runner` socket daemon (`/run/aetherflow/runner.sock`), unified `af` administrative CLI binary, embedded Next.js frontend, existing SQLite tables, and password/JWT/AES-256-GCM credential formats.
* **Forward-Ported `v3.2.7` Capabilities**: Forward-ported the 73rd bare-metal Marketplace package (**Tailscale** mesh VPN + `af-systemd-sandbox` exemption), Experimental update channel UI (`SettingsTab.tsx`, `GlassSelect.tsx`), GitHub API 5-minute response cache + `X-RateLimit-Reset` / `Retry-After` rate-limit backoff + branch-head commit SHA fallback + `/releases/latest` redirect fallback (`storage.rs`), and archive permission normalization (`prepare_release_permissions` in `deploy/release-manager.sh` and `af-release`).
* **Declarative Rust Package Executor (`af-runner`)**: Expanded native declarative Rust package recipes to 15 applications (`fail2ban`, `quassel`, `threadfin`, `znc`, `xrdp`, `novnc`, `x2go`, `scrutiny`, `prometheus`, `netdata`, `mergerfs`, `rclone`, `clamav`, `mosquitto`, `syncthing`) with `GenerateSelfSignedTlsCert`, `CaptureDpkgVersion`, pre-start systemd sandboxing, and transactional rollback journaling.
* **Host Maintenance, Smart Backup Consolidation & Staged Restore (`af-host` & `af-cli`)**: Wired `af-services` smart SQLite backups to `af-host` (`OnlineBackupApi` + `.manifest.json` + `.sha256`), added verified staged restore extraction (`af backup restore --staging-root`), ported native host maintenance utilities (`af tune`, `af sentinel`, `af clean-logs`, `af showspace`), and expanded Rust-native bare-metal provisioning steps in `af provision` from 6 to 14 steps.
* **Native Rust Plugin Runtime (`af-services::plugins` & `af-api`)**: Implemented `plugin.manifest.json` discovery and validation, deterministic/dynamic loopback port allocation (`21000..=21999`), plugin-scoped JWT minting (`POST /api/v1/admin/plugins/:id/token`), segment-boundary `api_scopes` RBAC middleware, and streaming reverse-proxy endpoints (`/api/v1/auth/plugins/:id/proxy/*path` and `/plugins/:id/*path`).
* **Release Manager Database Resolution & Safe Backups**: Added `resolve_db_path` in `deploy/release-manager.sh` and `af-release` to resolve the live SQLite path from `AF_DB_PATH`, `/etc/aetherflow/aetherflow.env`, or `aetherflow-api.service` before falling back to `/var/lib/aetherflow/aetherflow.sqlite`. Pre-swap snapshots use `sqlite3 --readonly .backup` / `rusqlite::backup::Backup` with `PRAGMA integrity_check` verification, preserve existing installed systemd units, and download and verify real release artifacts during `--dry-run`.
* **Subdomain Gateway Streaming & Session Validation**: Updated the Subdomain Gateway proxy to stream upstream response bodies instead of buffering them in memory, verify JWT revocation and client session bindings on SSO pass-through requests, and bound refresh token lifetimes.
* **SQLite Connection Sharing & Non-Blocking I/O**: Refactored auth, OIDC, audit log, and settings handlers to share active connections or drop pool guards before nested queries, and moved synchronous filesystem, `systemctl`, SQLite backup, and SHA-256 hashing operations onto blocking worker threads.
* **Cluster, Upload, FileShare & Webhook Checks**: Required `X-Cluster-PSK` authentication on `GET /cluster/v1/metrics`, validated cluster heartbeat `node_id` and status fields, enforced cumulative size limits on chunked uploads, added canonical path checks on FileShare deletions, and restricted outbound webhooks against private/loopback addresses and redirects.

---

## CHANGELOG v3.2.6 - Stable Nightly Promotion, Remote Desktops & Streaming Reliability
_Promotes the nightly changes since `v3.2.5` to the stable channel._

### Release Highlights (since `v3.2.5`)
* **Remote Desktop Applications**: Added bare-metal KasmVNC, McVNC, and XRDP packages with install/remove lifecycles, service wiring, icons, and regression coverage.
* **Safe Jellyseerr-to-Seerr Upgrades**: Added staged builds and rollback support for in-place migration to Seerr, with installer regression tests.
* **Streaming Reliability**: Improved Jellyfin remote-control capability enforcement, active encoding termination on stop, WebSocket tunnels, and paginated watch-history synchronization with periodic automatic sync.
* **Service Visibility & MediaFlow Controls**: Added application ports and API keys to service cards and a decline action for pending transcode approvals.
* **Security & Project Metadata**: Parameterized sandbox paths, removed environment-specific literals, and refreshed security policy, project metadata, and license attribution.

---

## CHANGELOG v3.2.5 - App Update Engine, Nightly Release Pipeline, Open-Canvas Telemetry & Ingress Consolidation
_Direct comparison against `v3.2.1` (`v3.2.1...v3.2.5`), consolidating in-place Marketplace/Service updates, Nightly release channel orchestration, Open-Canvas UI & LibreSpeed V2, and runtime hardening._

---

### Release Highlights (since `v3.2.1`)
* **Marketplace & Services App Update Engine**: Added end-to-end in-place package updating (`POST /api/v1/admin/packages/:id/update`, `/packages/:id/check-update`, `/packages/updates/check`), live update badges, confirmation modals, and amber `ProgressRing` status across `ServicesTab.tsx` and `MarketplaceTab.tsx`, plus automatic systemd unit stop/restart orchestration in `installer.go` and hardened `Kavita`, `Navidrome`, and `Qui` installers.
* **Nightly Release Channel & Markdown Release Notes**: Wired the `nightly` branch and pre-release channel into `updater.go`, `deploy/release-manager.sh`, and `.github/workflows/release.yml`, replaced the legacy channel selector with `GlassSelect` (`stable` / `nightly`), and added rich Markdown rendering (`FlowAiMarkdown`) with BOM/encoding sanitization for upstream release notes.
* **Open-Canvas Dashboard, Sparkline Hover-Pause & LibreSpeed Obsidian V2**: Redesigned the Overview dashboard and LibreSpeed speedtest stage to a permanent open-canvas layout with an Obsidian V2 completion card and high-BDP tuning, added hover-pause inspection and `0.XX` decimal capping to `Sparkline.tsx`, and removed legacy REST polling in favor of full-duplex WebSocket telemetry.
* **FlowAI Model & Telemetry Context Upgrade**: Updated AI provider catalogs to support OpenAI **GPT-6 / GPT-6.1** and Anthropic **Claude 5.1 / Claude 5.5**, and injected live system telemetry and markdown formatting into FlowAI responses.
* **Apache2 Subdomain Gateway Consolidation & Concurrency Fixes**: Removed the legacy Caddy compatibility layer to standardize on the Apache2 Subdomain Gateway, resolved Apache worker starvation, SQLite ingress contention, auth refresh races, and AI prediction stalls.
* **Systemd, Storage & PWA Cache Hardening**: Configured `ProtectProc=default` in `aetherflow-api.service` with kernel-thread filtering in Top Processes, deduplicated bind-mounts and ramdisks in storage telemetry, fixed `PathSelector` symlink browsing, and upgraded `sw.js` (`aetherflow-cache-v2`) + `embed.go` with network-first HTML revalidation and Next.js RSC flight payload (`index.txt`) resolution.

---

## CHANGELOG v3.2.1 - 69-App Bare-Metal Catalog, Jellyfin Streaming Telemetry, FlowAI Open Canvas & 57-Point Surgical Audit
_Direct comparison against `v3.2.01` (`v3.2.01...v3.2.1`), consolidating catalog expansion, streaming intelligence, ingress hardening, and McSurgeon audit resolutions._

---

### Release Highlights (since `v3.2.01`)
* **69-Application Bare-Metal Catalog (+14 New Native Packages)**: Expanded AetherMarketplace from 55 to **69 bare-metal applications** with idempotent install/remove lifecycles, systemd service units, automation templates, and brand iconography: **Qui**, **Threadfin**, **Dispatcharr**, **Listenarr**, **SeedCross**, **pyLoad**, **Flood**, **Calibre-Web**, **FileBot**, **Unmanic**, **Quassel**, **X2Go**, **Notifiarr**, and **Organizr**.
* **Jellyfin Streaming Dashboard & Bandwidth Telemetry**: Introduced `StreamingMonitor` (`backend/services/streaming_monitor.go`), REST endpoints (`/api/v1/streaming/*`), SQLite playback history persistence, and the dedicated **Streaming** dashboard tab (`StreamingTab.tsx`) featuring live Direct Play vs. Transcode session cards, play statistics, library analytics, and real-time bandwidth telemetry.
* **LibreSpeed Obsidian V2 Theme & Backend Telemetry Patches**: Bundled the custom Obsidian V2 glassmorphic speedtest frontend (`index-modern.html`, `styling/obsidian.css`, `speedtest_worker.js`, custom SVG assets) and Go backend patches (`stats.go`, `telemetry.go`) directly into the `installpackage-librespeed` provisioning pipeline.
* **FlowAI Open-Canvas Overhaul & Docked Sidebar**: Redesigned `AiChatTab.tsx` into a full-viewport open canvas, stabilized primary navigation into a docked left `<aside>` sidebar, unified default Gemini routing on `gemini-4-argon` with automatic model fallback chains, and resolved FileShare & MediaFlow path handling.
* **Master Credential Synchronization & Bootstrap Modularization**: Synchronized operator credentials across the Web UI Onboarding Wizard, password updates, `/root/.master.info`, and automated blueprint/package provisioning (including PBKDF2 WebUI credentials for `qbittorrent-nox`). Decoupled mandatory torrent client installation from `AetherFlow-Setup` so base nodes bootstrap cleanly.
* **57-Point McSurgeon Surgical Audit Resolution**: Resolved 57 security, concurrency, ingress, DNS, hardware telemetry, and UI findings across backend and frontend components.

### Ingress, Auth & Systemd Hardening
* **Apache2 Subdomain Gateway & Certbot SAN Sync**: Consolidated ingress routing onto Apache2 VirtualHosts and the built-in Go `AppSubdomainProxyMiddleware`, automated Certbot SAN certificate synchronization via `af-certbot-sync`, and hardened `.aether.local` and SSO identity header routing (`ingress_handlers.go`, `blueprint_lifecycle.go`, `deploy_orchestrator.go`).
* **Systemd `AF_NETLINK` Sandboxing**: Added `AF_NETLINK` to `RestrictAddressFamilies` in `aetherflow-api.service` so `net.Interfaces()` LAN origin discovery operates cleanly inside strict systemd sandboxing.
* **Session Hijacking & Silent JWT Refresh Fixes**: Prevented false-positive session hijacking invalidations during browser socket rotation and stabilized background silent JWT refresh.

### Telemetry & UI Polish
* **Live GPU & CPU Telemetry**: Enhanced live GPU discovery and utilization polling (`nvidia-smi` and DRM `sysfs`) alongside real-time CPU frequency and thermal sensors in `hardware.go` and `GpuWidget.tsx`.
* **Dashboard & Settings Refinements**: Polished `SettingsTab.tsx`, `ProfileTab.tsx`, and `DataUsageHistoryWidget.tsx` state synchronization, accessibility semantics, and responsive layout density.

---

## CHANGELOG v3.2.01 - Single-Binary Control Plane, Auto-Subdomain Ingress & Real-Time Telemetry
_Direct comparison against `v3.1.5` (`v3.1.5...v3.2.01`), consolidating all architectural, security, packaging, and UI advancements._

---

### Release Highlights (since `v3.1.5`)
* **Whatbox-Style Server Base Domain & Automatic Subdomain Provisioning**: Added `baseDomain` support across Settings, Onboarding Wizard, and environment seeding (`AETHERFLOW_BASE_DOMAIN`). Installing any web-capable Marketplace app automatically provisions `<app>.<baseDomain>` (e.g., `jellyfin.domain.com`) with external access and TLS enabled via the Apache2 Subdomain Gateway, and updating `baseDomain` retroactively syncs existing installed apps.
* **Frame-0 Real-Time Telemetry & Hardware Metric Smoothing**: WebSocket clients now receive an immediate `METRICS_UPDATE` snapshot on connection (`frame 0`) with pre-seeded system/service state, loopback IP-binding tolerance (`127.0.0.1` / `::1` / `localhost`), non-blocking `cpu.Times` delta calculation in `hardware.go`, cached GPU hardware discovery, and two-point sparkline initialization so charts render immediately without waiting or stuttering.
* **Single-Binary Embedded SPA & Privileged Runner Daemon**: Compiled the Next.js static export (`backend/web/dist`) directly into the `aetherflow-api` Go binary (`CGO_ENABLED=0`) and split privileged root operations into a dedicated UNIX domain socket daemon (`aetherflow-runner.service` on `/run/aetherflow/runner.sock`) with strict regex/enum allowlists.
* **Debian 13 (Trixie) & Ubuntu 24.04 Modernization**: Migrated APT repositories to DEB822 `.sources` format with `0644` `/etc/apt/keyrings` permissions for `sqv`, enforced `umask 0022`, preserved execute bits on hoisted workspace `node_modules/.bin` binaries during permission hardening, migrated `sysctl` BBR tuning to `/etc/sysctl.d/99-aetherflow-bbr.conf`, and hardened `vsftpd` TLS and `qbittorrent-nox` PBKDF2 WebUI provisioning.
* **Obsidian V2 Design System & Operator Suite**: Delivered the Obsidian V2 glassmorphic interface with tri-mode navigation, Command Palette (`Cmd+K`), Smart App Switcher, External Access Card with live domain suggestions, Multi-Node Fleet Orchestration, Audit Log & Inbox approval gates, AI Forecasting, and 4-tier E2E verification (387 automated tests).
* **FlowAI Multi-Provider Architecture & MediaFlow Engine**: Finalized provider-agnostic AI routing (Gemini, Anthropic, OpenAI, Ollama, LM Studio) with encrypted credential storage, plus hardware-agnostic MediaFlow transcoding (AMD VAAPI / Intel QSV) and non-destructive `.mediaflow_trash` retention.

### Ingress, Networking & Reverse Proxy
* **Automatic App Subdomain Lifecycle**: `BlueprintLifecycleManager` now resolves `baseDomain` from SQLite settings or environment variables and writes `<app>.<baseDomain>` into `app_ingress_configs` on installation, immediately syncing Apache2 Subdomain Gateway reverse-proxy routes and Certbot SANs.
* **Retroactive Base Domain Sync**: Updating `baseDomain` via `PUT /api/v1/auth/settings` automatically provisions subdomains for all existing installed/running apps and triggers a live Subdomain Gateway and Certbot SAN sync.
* **Apache SSL WebSocket Rewrite Fix**: Updated `setup/templates/default-ssl.conf.template` to proxy WebSocket upgrade requests across all `/api/(.*)` endpoints (`ws://127.0.0.1:8080/api/$1`), fixing `/api/v1/ws` upgrades behind Apache SSL.
* **CORS & Host Validation Auto-Discovery**: Added automatic LAN interface IP and configured `saved_domain` (`http://` and `https://`) registration in `/etc/aetherflow/aetherflow.env` and `HostValidationMiddleware`.

### Telemetry, WebSockets & Dashboard UI
* **Instant WebSocket Snapshot & Transport Ownership**: `maintainSystemState()` pre-populates cached metrics and services prior to accepting connections, and `HandleWebSocket` pushes an immediate initial frame upon registration. Fixed `WebSocketContext` transport ownership so switching between WebSocket (`Hyperspeed`) and REST polling (`Nexus Poll`) cleanly tears down stale timers.
* **Zero-Blocking CPU & Process Telemetry**: Replaced blocking 200ms `cpu.Percent` intervals with non-blocking `cpu.Times` delta math in `GetSystemMetricsCore()`, added monotonic counter guards for Disk I/O and Network throughput, tracked per-PID CPU time deltas across scan windows, and cached `ghw.GPU()` scans after initial boot discovery.
* **Overview & Services Tab Enhancements**: Added full-card click-to-open navigation and public subdomain badges on active services, dynamic partition selection in the Storage widget, and smooth zero-animation Recharts sparklines for high-frequency metric updates.

---

## CHANGELOG v3.1.7 - FlowAI Architecture & Dashboard Optimization
_Generated April 22, 2026 encompassing all commits from v3.1.6 to v3.1.7._

---

### Release Highlights
* **FlowAI Multi-Provider Architecture**: Finalized provider-agnostic routing, per-provider connection testing, and expanded the settings UI to support dynamic model and credential handling for Anthropic, Gemini, and OpenAI.
* **Hybrid File System Browser**: Integrated a secure, controlled "hybrid" file system browser into the AetherMarketplace UI with server-side path-traversal protection.
* **Dashboard Telemetry Refinements**: Upgraded the `WebSocketContext` to bypass polling intervals for genuine real-time `METRICS_UPDATE` broadcasting. Fixed SQLite date parsing to accurately bucket historical Data Usage metrics.
* **Storage Insights**: Introduced a dynamic partition-filtering dropdown to the Storage widget, allowing targeted drive inspection instead of only aggregate views.
* **Immersive UI Polish**: Refactored the Ghost Spacer Sidebar to align icon dimensions, optimized the `GpuWidget` layout to prevent text clipping, and integrated SVGL for fetching dynamic AetherMarketplace logos.
* **Frontend Build Integrity**: Resolved pre-existing TypeScript/build errors in `StorageWidget`, `AppTopologyMap`, and `MediaFlowTab`. Removed the orphaned `LoginOverlay` component.
  * *Hotfix:* Patched a strict type validation mismatch (`e.target.value as AIProviderID`) in `AiChatTab` that blocked Next.js production builds during deployment.

---

## CHANGELOG v3.1.6 - MediaFlow Engine & AetherMarketplace Stabilization
_Generated April 18, 2026 encompassing all commits from v3.1.5 to v3.1.6._

---

### Release Highlights
* **MediaFlow Hardware-Agnostic Engine**: Implemented dynamic AMD (VAAPI) and Intel (QSV) GPU detection with zero-container transcoding mapping directly to optimal `.mkv` targets.
* **Non-Destructive Retention**: Upgraded MediaFlow to utilize a safe `.mediaflow_trash` lifecycle hook, abolishing legacy destructive file deletions.
* **Atomic Deploy Engine & SSO**: Introduced Native SSO, Atomic Deploy Engine functionality, and optimizations to Next.js UI.
* **Update Channels**: Separated stable releases from beta tags natively within the updater.
* **Marketplace Hardening**: Resolves numerous marketplace and script installation errors, adding proper permission escalations and error bubbling.

### AetherMarketplace & Services
* **Error Bubbling & Execution**: Stripped sandbox blockers, automatically set execute (`+x`) permissions, and surfaced `stderr` so failed installations become visible.
* **Sudo Automation**: Automated sudo permissions for the `aetherflow` service user.
* **Prowlarr & Core App Fixes**: Resolved Prowlarr installation extraction error by pointing directly to the update API.
* **UI State Sync**: Jobs now immediately reflect as "installed" or "uninstalled" on the frontend upon script completion.
* **Visual Polish**: Restored missing icons, fixed progress overlay, corrected status labels, and aligned the Services tab aesthetics with the main AetherMarketplace.
* **Systemd Refinements**: Hardened systemd path logic, enforce strict mounts, and deployed fixes to python remote deployment (`deploy_server.py`) scripts.

### Dashboard & Immersive UI
* **Global Glassmorphism**: Synchronized sidebar aesthetics and resolved visual glitches matching the high-glow indigo variants of the login flow.
* **Density-Aware Widgets**: Completed full scaling logic for Storage, Process, and Network widgets to utilize full-screen real estate in Immersive Mode without overlaps.
* **Mission Control Scale**: Optimized the App Topology Map and Data Usage History for ultra-wide and immersive dashboard views, fixing duplicate node renders.
* **Deployment Previews**: Expanded platform preview documentation to a 2x8 grid with 11 distinct aesthetic screenshots.

---

## CHANGELOG v3.1.5 - Immersive Security & Dashboard Evolution
_Generated April 15, 2026 from recent implementation turns._

---

### Release Highlights
* **Enterprise Security**: Implemented full TOTP 2FA support with recovery codes for all local accounts.
* **Dashboard Evolution**: Upgraded the standard layout into an immersive, hardware-aware mission control center with "Hyperspeed" WebSocket performance.
* **UI Consolidation**: Migrated the Profile page into the Settings suite and aligned sidebar styling for brand consistency.
* **Hardware Intelligence**: Shifted from generic static metric reporting to real-time, detected component stats (e.g., live CPU freq).

### Security & Identity
* **Two-Factor Authentication**: Native support for TOTP (Google Authenticator/Authy) in the Go backend (`totp.go`) and Next.js frontend.
* **Update Channel Separation**: Decoupled Stable and Beta update channels. The Stable channel is now strictly restricted to official `mceveritt` authored releases and ignores pre-releases to secure deployment integrity, whereas the Beta channel uses Git Tags.
* **Recovery Logic**: Integrated a secure recovery code system with hashed storage for account restoration.
* **Hardened Login**: Updated the `LocalLogin` workflow to require multi-stage verification when 2FA is enabled.
* **Security Dashboard**: Added a consolidated Security tab for managing authentication factors and sessions.

### New Features & Improvements
* **WebSocket "Hyperspeed"**: Optimized the metrics broadcast/render pipeline to eliminate stuttering in high-frequency monitoring mode.
* **Real-time CPU Polling**: Upgraded CPU frequency tracking to use kernel-level frequency scaling files (`sysfs`) for true "Live" updates.
* **Profile Migration**: Removed the redundant Profile sidebar link and integrated profile management as a sub-tab within Settings.
* **Network Label Clarity**: Renamed "RX" and "TX" to "Downloaded" and "Uploaded" respectively across the dashboard for better human readability.
* **Topology Map Stabilization**: Resolved node jitter in the App Topology Map by refactoring the D3 force-directed graph with persistent coordinate logic.
* **Immersive Mode**: Introduced a new high-fidelity dashboard density mode that utilizes full screen real-estate.
* **GPU Intelligence**: Implemented detectable GPU metric monitoring for both headless and desktop server environments.
* **Sidebar Alignment**: Synchronized sidebar visual styling with the login page for unified glassmorphism aesthetics.

### UI/UX & Control Plane
* **Quick-Access Settings**: Integrated a settings cog wheel directly in the dashboard header.
* **Adaptive Grid**: Refactored the dashboard grid to re-render based on user density preferences (Compact vs. Immersive).
* **Hardware Detection**: Enhanced `ghw`-based hardware discovery for specialized compute devices.
* **Data History**: Introduced the Data Usage History widget for long-term traffic trend analysis.

---

## CHANGELOG v3.1.0 - Gold Release Candidate
_Generated March 15, 2026 from commits since `v3.0.1`._

---

### Release Summary
* **Version**: Promoted the repository to `v3.1.0` for the Gold release candidate.
* **Scope**: Consolidated the post-`v3.0.1` modernization work across the Go control plane, Linux installer/runtime scripts, and the Next.js dashboard.
* **Focus**: Elevated bare-metal readiness, tightened security defaults, and completed the UI transition away from the legacy PHP surface.

### Features
* **Go Platform Expansion**:
  * Expanded the Go backend with auth, services, marketplace, updater, WebSocket, backup, AI, and clustering capabilities.
  * Added local username/password onboarding, dynamic OAuth redirect handling, safer SQLite backup/export flows, and richer package/service verification.
* **Operational Depth**:
  * Grew the marketplace catalog to 37 managed applications with improved install/remove coverage and Web UI routing.
  * Added installer recovery/resume behavior, smarter updater flows that preserve local changes, and broader Debian/Ubuntu hardening across setup templates and service scripts.
* **Observability & Intelligence**:
  * Introduced hardware identifier discovery, real package/service status checks, and AI model selection improvements for Gemini-powered workflows.

### Security Hardening
* **Legacy PHP Removal**:
  * Removed the remaining legacy PHP codepaths, deleted the PHP dashboard, and completed the transition to the Next.js frontend as the sole supported UI surface.
* **JWT & Session Controls**:
  * Hardened JWT handling by refusing to start without `JWT_SECRET`, tightening session-cookie defaults, and reinforcing auth-sensitive/admin-only routes.
* **Defense in Depth**:
  * Closed critical audit findings across service action allowlists, WebSocket origin validation, upload/path traversal protection, dangerous file-extension blocking, backup path validation, and runtime secret hygiene.

### UI/UX Enhancements
* **Dashboard Maturity**:
  * Added missing security, backup, fileshare, profile, and users tabs, along with stronger marketplace and services workflows.
  * Introduced onboarding, skeleton loaders, toast notifications, and more polished authentication flows across the Next.js application.
* **Polish & Responsiveness**:
  * Delivered a Netdata-style dashboard with sparklines, heatmaps, process visibility, disk I/O, swap telemetry, and dynamic hardware identity widgets.
  * Added circular install progress states, cleaner login copy, and broader frontend lint/build cleanup to stabilize the release candidate.

---

## CHANGELOG v3.0.1 - Initial Stable Release
_Changelog updated February 18, 2026_

---

### Version 3.0.1
* **Version**: Set to `v3.0.1`.
* **System**: Initial Stable Release.

### Security & Core Fixes (v3.0.1 Audit)
* **Frontend/Backend Synchronization**:
  * Transitioned all legacy toggle links from insecure `GET` to secure `POST` requests.
  * Implemented `csrf-interceptor.js` to automatically attach CSRF tokens to forms.
  * Secured Gemini API proxy endpoint with CSRF middleware validation.
* **UI/UX Refinements (Glassmorphism)**:
  * Overhauled `slate_stone.css` with advanced backdrop blur, custom scrollbars, glowing borders, and improved accessibility (contrast).
  * Removed deprecated third-party and donation assets from the login experience.
* **Modernization Scaffolding**:
  * Scaffolded Native Go API (`backend/main.go`) structured to read `/proc` directly.
  * Scaffolded Native Next.js App (`frontend/src/app`) mirroring the Glassmorphism aesthetic for the complete dashboard rewrite.
* **Installer Enhancements**:
  * Corrected bash path detection resulting in execution failures during setup.
  * Standardized binary casing (`AetherFlow`) across package uninstall hooks.

---

## CHANGELOG v3.0.0 - AetherFlow Foundation
_Changelog updated February 18, 2026_

---

### Platform Foundation
* **AetherFlow Bootstrap**: Established the `McEveritts/AetherFlow` monorepo, branding assets, `/usr/local/bin/aetherflow` runtime paths, and `AetherFlow-Setup` bootstrap installer.

### Core System Updates
* **CLI Tooling**: Standardized on the `af` CLI (`af install <package>`, `af remove <package>`, `af upgrade`).
* **Authentication**:
  * **Google Sign-In**: Native Google OAuth 2.0 integration for dashboard login.
  * **Remember Me**: Added 30-day persistent session support.
  * **Middleware**: Added authentication middleware across dashboard routes.
* **Gemini AI Integration**:
  * Integrated OAuth 2.0 Service Account authentication and Gemini AI system assistance.
* **Security**:
  * Added CSRF protection middleware and interceptors.
  * Removed deprecated legacy widgets and third-party tracking assets.
