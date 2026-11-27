# AetherFlow v4.0.0 Post-EGM CI Recovery and Hardening Program

*   **Author**: AetherFlow Maintainers
*   **Status**: Proposed (Post-EGM Review Revision)
*   **Date**: 2026-11-23

---

## Overview

AetherFlow v4.0.0 is a self-hosted media and server control plane comprising a Rust HTTP API server (`af-api` / `aetherflow-api.service`, default port `8080`, SQLite WAL), a Leptos Rust/WASM web frontend (`af-web-app` / `frontend-rs`), a privileged root runner daemon (`af-runner` over `/run/aetherflow/runner.sock`), an admin CLI (`af` / `af-cli`), a backup/restore crate (`af-host`), a release engine (`af-release`), and a confined filesystem crate (`af-files`).

Following the five-round Elephant-Goldfish Model (EGM) documentation audit across all 43 living documentation files (pushed to `origin/nightly` at commit `40797bb5`), all 43 audited documents match live v4.0.0 behavior at that baseline. That reconciliation surfaced two sets of defects blocking a `v4.0.0` release:

1. **Active pipeline failures on `nightly` (Phase 0)**: All three GitHub Actions workflows (`CI`, `Security Gate`, and `Production Release Pipeline`) fail on `40797bb5` due to RustSec advisory `RUSTSEC-2026-0592` (`url` `2.5.8`), Gitleaks allowlist path drift after commit `ade31c08`, and regressions from the `packages/common.sh` modularization and Ubuntu 26.04 `uutils-coreutils` umask handling.
2. **Fourteen verified code, security, operational, and test-hygiene defects (`ESC-01` through `ESC-14`, Tracks A–D)**: Live code permits recursive account deletion across bind mounts, retains an offboarding-resistant Basic Auth credential fallback, exposes gateway-protected apps unauthenticated over `*.aether.local` to RFC 6598 (`100.64.0.0/10`) Tailscale/CGNAT peers, and allows arbitrary IP-literal `Host` headers to bypass `ALLOWED_HOSTS`. Live code also leaves managed plugins sharing the host network namespace with unauthenticated loopback `/metrics`, rejects default backup archives during canonical `/` restores, and aborts release rollbacks on non-compliant log files.

This design defines an immediate standalone CI hotfix (**Phase 0**) followed by **four domain-aligned hardening tracks (Tracks A–D)** across `backend-rs`, `frontend-rs`, `deploy/`, `packages/`, `docs/`, and `tests/`. Each track groups changes that touch shared files and living documentation so every shared file and documentation target is modified once, remains independently buildable and testable, and lands cleanly on `nightly`.

## The Problem

AetherFlow v4.0.0 cannot safely ship to `master` or run on multi-user, LAN, or Tailscale-connected hosts in its current state for five concrete reasons:

*   **Broken release and verification signal (Phase 0)**:
    *   `CI`, `Security Gate`, and `Production Release Pipeline` all fail on `origin/nightly` (`40797bb5`), blocking signed multi-architecture `nightly` tarballs and ARM64 verification runs and hiding new regressions.
    *   `url` `2.5.8` triggers `RUSTSEC-2026-0592` across all three Rust workspaces; `.gitleaks.toml` misses split test fixture paths; `packages/common.sh` initialization, `uutils-coreutils` `install -d -m 0755` under `umask 077`, and hardcoded `/run/systemd/resolve/resolv.conf` in `installpackage-adguardhome` cause 17 failing Python installer tests.
*   **Ingress, authentication, and session boundary defects (Track A — `ESC-09`, `ESC-10`, `ESC-13`, `ESC-14`, `ESC-05`)**:
    *   Subdomain Gateway Basic Auth (`verify_proxy_basic_credentials`) checks four provisioning master-credential stores (`/var/lib/aetherflow/.master.creds`, legacy `/opt/AetherFlow/backend/data/.master.creds`, `/install/.aetherflow.conf`, and `system_config.master_credentials`) before verifying an active admin in `users`, so rotated, demoted, or deleted initial admins retain access and bypass TOTP (`ESC-09`).
    *   Clients on loopback, RFC 1918 LAN, link-local, IPv6 ULA, or RFC 6598 CGNAT (`100.64.0.0/10`, including Tailscale peers) can reach all nine currently gateway-protected apps (`mcvnc`, `scrutiny`, `prometheus`, `flaresolverr`, `jackett`, `threadfin`, `unmanic`, `netdata`, `autoscan`) unauthenticated via `Host: <app>.aether.local`, even when `external_access_enabled = 0` (the SQLite `system_config` toggle controlling public external vhosts) and `*.aether.local` is absent from `ALLOWED_HOSTS` (`ESC-10`).
    *   Arbitrary IPv4/IPv6 literal `Host` headers bypass `ALLOWED_HOSTS` and reflect into `GET /.well-known/openid-configuration` and SPA `Content-Security-Policy` `connect-src` (`security_headers_middleware` wraps outside `host_validation_middleware`); `POST /api/v1/auth/refresh` lacks auth rate limiting; `AF_DISABLE_RATELIMIT` disables limiters in production (`ESC-13`).
    *   Apache `htpasswd` and `rutorrent.htpasswd` fail open on admin offboarding or TOTP enrollment (never auto-revoking existing entries), fail closed only when an initial `htpasswd` cannot be built on an all-TOTP host, and `af provision run` writes an unlogged 24-character random password into `htpasswd` when `.master.creds` uses `enc:v1:` AES-GCM encryption (keyed by `AETHERFLOW_MASTER_CREDS_SECRET`) (`ESC-14`).
    *   Human-session revocation checks `active_sessions` on only four narrow paths (`auth/sessions.rs`, `app_launch.rs`, `routes/marketplace/catalog.rs`, and `routes/health.rs` admin check) instead of uniformly across API, proxy, WebSocket, and OIDC surfaces, and `POST /api/v1/public/auth/refresh` resurrects deleted `active_sessions` rows when `existing_family_opt` is `None` (`ESC-05`).
*   **Filesystem confinement and backup/restore defects (Track B — `ESC-01`, `ESC-08`, `ESC-06` FS/Version)**:
    *   Deleting a user account recursively deletes McBrowser's per-user storage (`/var/lib/aetherflow/mcbrowser/user-<id>`) without checking mount boundaries, while `deploy/systemd/aetherflow-api.service` suggests bind-mounting shared media beneath `user-1/Media` (`ESC-01`).
    *   `af backup create` packs `.master.creds` and `oidc_rsa.pem`, which canonical `/` restore rejects (`UnsafeOverwriteRejected`) and omits from `0600` `.creds` clamping and non-root `/var/lib/aetherflow` parent handling; staging restores without `--root` stop live `aetherflow-api.service`; `restore-preflight` rejects `--allow-overwrite` (`ESC-08`).
    *   Default `GET /api/v1/auth/fs` allowed roots include `env::temp_dir()` (`/tmp`), and five backup/restore defaults hardcode `"v4.0.0"` / `"4.0.0"` (`ESC-06`).
*   **Privileged runner, release rollback, plugin isolation, and package tooling defects (Track C — `ESC-07`, `ESC-11`, `ESC-02`, `ESC-03`, `ESC-12`, `ESC-06` Units/Shell)**:
    *   Managed plugin systemd units share the host network namespace and can bind arbitrary ports, reach external hosts, and scrape unauthenticated loopback `/metrics` (`ESC-07`).
    *   A single non-compliant file under `/var/log/aetherflow` (failing `deploy/log-retention.py` symlink, ownership, or mode checks) causes `aetherflow-log-retention.service` (`required = true`) and `/var/log/aetherflow` directory setup to fail Stage 3 deploy (service restart/cutover) and Stage 4 rollback (automatic restore of prior release), stranding the host in `RollbackFailed`; `af release deploy --local` ignores `HEALTH_ENDPOINT` in `/etc/aetherflow/aetherflow.env` (`ESC-11`).
    *   Self-update drops GitHub auth tokens and `AETHERFLOW_SKIP_PROVENANCE_VERIFY`, prefers the mutable `/opt/AetherFlow/current/bin/af` symlink over the running binary directory, and writes `0644` job receipts across `job_receipts.rs`, `core_restart_worker.sh`, and `deploy/release-manager.sh` (`ESC-02`).
    *   `DeclarativeStep::RunCommand` accepts arbitrary binaries without an allowlist and has only one caller (`build_rclone_recipe` invoking `/bin/sh -c`) (`ESC-03`).
    *   Default Bash Marketplace installers (all `77` packages by default; `68` when `AETHERFLOW_ENABLE_RUST_PACKAGES=1`) receive an unused `DPKG_LOCK_TIMEOUT=120` environment variable instead of passing `-o DPkg::Lock::Timeout=120` to `apt-get` (`ESC-12`).
    *   Staging `.af-backup.*` backups accumulate without pruning, `removepackage-palate` prints a stale retention message after `DELETE_DATA=true`, `docs/installpackage-template.sh` violates Marketplace shell hygiene rules, and systemd unit templates retain a retired `backend/.env` `EnvironmentFile` (`ESC-06`).
*   **FlowAI and test-integrity defects (Track D — `ESC-04`, `ESC-06` E2E/Streaming)**:
    *   FlowAI (AetherFlow's built-in AI assistant) defaults its `anthropic-local` local-server preset to `http://localhost:8080` (colliding with `aetherflow-api`), exposes cloud providers (`openai`, `anthropic`, `gemini`) to standard users without an admin role gate, and allows `provider: "anthropic-local"` to invoke `call_anthropic_api` with the configured paid `ps.anthropic_api_key` (`ESC-04`).
    *   Twenty-five checks across eight Tier 1/2 Python E2E contract files pass via `assert_true(True)` placeholders (22 unconditional across all modes; 3 stubbed only in `--mode contract` while verifying live responses in `--mode live`); `RunnerSocketClient` and `--socket` are dead harness code; `AF_STREAMING_*_FIXTURE` files are unread by `frontend-rs` tests and only partially validated/unset in `scripts/validate-streaming.sh` (`ESC-06`).

## Goals

*   **Phase 0 (Passing CI Baseline — Immediate Hotfix)**: Restore passing status on `CI`, `Security Gate`, and `Production Release Pipeline` on `nightly` by resolving `RUSTSEC-2026-0592` across all three Rust workspaces, syncing `.gitleaks.toml` alternation regexes, and fixing the `packages/common.sh`, `uutils-coreutils` umask, and AdGuard Home resolver regressions.
*   **Track A (Ingress, Auth, and Session Integrity)**: Resolve `ESC-09`, `ESC-10`, `ESC-13`, `ESC-14`, and `ESC-05` with regression tests verifying active-admin Basic Auth, authenticated `*.aether.local` access (including TOTP launch support and Tailscale reachability without unauthenticated bypass), strict IP-literal `Host` validation without CSP reflection, gateway-authenticated `rutorrent` with internal loopback secret protection, and uniform `active_sessions` enforcement without multi-tab family destruction.
*   **Track B (Filesystem, Backup, and Restore Safety)**: Resolve `ESC-01`, `ESC-08`, and `ESC-06` (FS Browser & version identity) so mount-boundary deletion stops before crossing same-FS or cross-FS mounts, default host backups pass canonical `/` restore with `0600` clamping and `aetherflow:aetherflow` ownership, isolated staging restores never stop live `aetherflow-api.service`, `/tmp` is excluded from default FS roots, and backup version metadata reuses `runtime_identity()`.
*   **Track C (Runner, Release, Plugin Isolation, and Package Tooling)**: Resolve `ESC-07`, `ESC-11`, `ESC-02`, `ESC-03`, `ESC-12`, and `ESC-06` (shell/unit hygiene) so managed plugins enforce cgroup v2 `SocketBindDeny`/`IPAddressDeny`, `/metrics` requires authentication, release rollback completes despite log-retention failures, self-update reads tokens from `/etc/aetherflow/aetherflow.env` with `0600` receipts and immutable binary resolution, dead `DeclarativeStep::RunCommand` is removed, and Bash APT installers honor `DPKG_LOCK_TIMEOUT`.
*   **Track D (FlowAI Guardrails and Contract Test Integrity)**: Resolve `ESC-04` and `ESC-06` (E2E & streaming contracts) so FlowAI prevents self-targeting port `8080` and gates paid cloud keys/providers to admins by default, all 25 E2E stubs become deterministic static assertions, dead `RunnerSocketClient`/`--socket` code is removed, and `frontend-rs` deserializes all three backend-emitted streaming fixtures fail-closed.
*   **Continuous Documentation Parity**: Synchronize affected living documentation files inside the same phase or track that changes code behavior so `$egm-drift-report` (the EGM codebase-vs-docs drift audit covering all 43 living documentation files) remains at zero unresolved drift.

## Non-Goals

*   **No `master` cutover or `v4.0.0` release tagging**: Merging `nightly` into `master`, clearing the 45 legacy pre-v4 Dependabot alerts on `master`, running KVM clean-host/lifecycle/privileged guest drills, and running blind independent multi-model certification occur after Phase 0 and Tracks A–D land.
*   **No live host or production deployment**: Scope covers repository code, tests, CI workflows, systemd units, and living documentation only; no live server updates or service restarts are performed.
*   **No new product features or UI redesigns**: Scope is limited to CI recovery and the 14 documented escalations.
*   **No wholesale migration of Bash installers to Rust**: Only `ESC-03` (`RunCommand` / `rclone`), `ESC-12` (`DPkg::Lock::Timeout` in `versions_apt.sh`), `ESC-06` (`docs/installpackage-template.sh`, `removepackage-palate`, and `.af-backup.*` retention), `ESC-14` (`installpackage-rutorrent` / `removepackage-rutorrent`), and Phase 0 `packages/` regressions are in scope.

## Open Questions

None. All architectural decisions—including the four post-review trade-offs resolved during `$egm-resolve` (`ESC-14` single-purpose loopback ruTorrent proxy token, `ESC-05` retaining safe in-memory `ROTATED_TOKEN_GRACE` with uniform `active_sessions` and `/refresh` resurrection fix, `ESC-10` decoupling authenticated Tailscale reachability from unauthenticated LAN opt-in plus scoped `aetherflow_local_app` cookie for TOTP admins, and extracting Phase 0 + four domain tracks)—are recorded in the Technical Plan below and in [Alternatives Considered](#alternatives-considered).

## Critical User Journeys (CUJs)

### CUJ 1: Maintainer pushes a change to `nightly` and receives verified release artifacts

*   **Given**: A commit on `nightly` with updated Cargo lockfiles (`url` patched for `RUSTSEC-2026-0592`), updated `.gitleaks.toml` alternation path regexes, guarded `packages/common.sh` initialization, umask-safe directory creation, and rebased AdGuard Home resolver paths.
*   **When**: GitHub Actions executes `CI`, `Security Gate`, and `Production Release Pipeline`.
*   **Then**: All jobs pass with zero `RUSTSEC-2026-0592` advisories, zero Gitleaks false positives, zero `mkdir /install`, `umask 077`, or AdGuard DNS handoff test failures, and signed `amd64`/`arm64` release tarballs are built and verified.

### CUJ 2: Operator deletes a user account containing a mounted shared directory

*   **Given**: A McBrowser directory `/var/lib/aetherflow/mcbrowser/user-<id>` containing either a cross-filesystem mount or a same-filesystem bind mount (`mount --bind` / `BindPaths=`) on a subdirectory or directly on `user-<id>`.
*   **When**: An admin deletes the user account and `account_cleanup` invokes `af-files` recursive removal.
*   **Then**: Removal stops via `openat2(RESOLVE_NO_XDEV)` (with `st_dev` `ENOSYS` fallback) before crossing any mount boundary, leaves all mounted files untouched, removes remaining same-mount entries, deletes the completed `account_storage_cleanup` retry row (no infinite 15-minute loop), and logs a structured `WARN` plus `admin_audit_log` entry naming the preserved mount paths.

### CUJ 3: Admin offboards a former administrator and rotates credentials

*   **Given**: A host where an initial admin account was provisioned via `POST /api/v1/public/auth/setup` or `af provision`, then later deleted, demoted, password-rotated, or enrolled in TOTP.
*   **When**: The former admin attempts Basic Auth against any gateway-protected subdomain or managed external ruTorrent endpoint.
*   **Then**: Access is denied (`401`/`403`); neither the four provisioning master-credential stores nor stale Apache `htpasswd` entries grant access.

### CUJ 4: Untrusted Tailscale, CGNAT, or IP-spoofing client probes the control plane

*   **Given**: AetherFlow running with `AETHERFLOW_ENV=production`, `AF_DISABLE_RATELIMIT=1`, `external_access_enabled = 0`, and an explicit `ALLOWED_HOSTS` allowlist.
*   **When**: An unauthenticated client from `100.64.0.0/10` sends `Host: mcvnc.aether.local`, an external client sends an unlisted IP-literal `Host` header to `GET /.well-known/openid-configuration` or `/`, or a client bursts `POST /api/v1/auth/refresh`.
*   **Then**: Unauthenticated `*.aether.local` requests are rejected (`401`) even if `AF_ALLOW_UNAUTH_LOCAL_LAN=1` is enabled (while authenticated Tailscale admins can still sign in to `aetherflow.aether.local` and launch protected apps via scoped app cookies); unlisted IP-literal `Host` headers return `400 INVALID_HOST` without reflecting into OIDC discovery or SPA CSP `connect-src`; and `auth_rate_limit_middleware` enforces rate limits despite `AF_DISABLE_RATELIMIT=1`.

### CUJ 5: Operator restores a default host backup

*   **Given**: A default archive created by `af backup create` (containing `.master.creds` and `oidc_rsa.pem`).
*   **When**: The operator runs `af backup restore-preflight --allow-overwrite` and restores to either an isolated staging directory or canonical `/`.
*   **Then**: Staging restore selects `NoopQuiescenceController` without stopping live `aetherflow-api.service` (while still quiescing whenever the target path contains the live `AF_DB_PATH`); canonical `/` restore accepts `.master.creds` and `oidc_rsa.pem` with `0600` mode clamping and `aetherflow:aetherflow` ownership.

### CUJ 6: Release deploy recovers cleanly from a failed cutover on a host with a non-compliant log file

*   **Given**: A host running `af release deploy` (or `af release deploy --local` with `HEALTH_ENDPOINT` configured in `/etc/aetherflow/aetherflow.env`) where one file under `/var/log/aetherflow` violates `deploy/log-retention.py` checks.
*   **When**: `af-release` or `deploy/release-manager.sh` enters Stage 3 service restart or Stage 4 rollback.
*   **Then**: `aetherflow-runner.service` and `aetherflow-api.service` restart first and pass readiness checks against the resolved `HEALTH_ENDPOINT`; `aetherflow-log-retention.service` runs afterward as best-effort, recording a structured warning without aborting into `RollbackFailed`.

### CUJ 7: A managed plugin executes inside `af-runner` isolation

*   **Given**: A third-party plugin started via `af-runner` transient systemd unit on its allocated loopback port on a cgroup v2 host (systemd `>= 249`).
*   **When**: The plugin attempts to bind another port, connect to an external IP, scrape `http://127.0.0.1:8080/metrics`, or call `http://127.0.0.1:8087` (`rutorrent`) directly.
*   **Then**: Systemd `SocketBindDeny`/`SocketBindAllow` and `IPAddressDeny`/`IPAddressAllow=localhost` reject unauthorized binds and non-loopback egress, `/metrics` returns `401` without `METRICS_BEARER_TOKEN` or an active admin session, and local `rutorrent` rejects requests lacking the internal gateway proxy secret header.

## Technical Plan (Architecture)

Phase 0 ships immediately as a standalone CI hotfix PR. Tracks A–D execute in domain-aligned PRs (each track touching its owned shared files and living documentation once).

```text
External HTTPS Client                     Internal LAN / Tailscale Client
  │                                         │
  ▼                                         ▼
Apache2 External Vhost (TLS + ACME)       Apache2 Internal Vhost (*.aether.local)
  │  All 10 protected apps (incl.           │  Auth required by default; Tailscale
  │  rutorrent, ESC-14) with header         │  100.64.0.0/10 allowed when authenticated
  │  x-aetherflow-external-app <app>        │  (never in AF_ALLOW_UNAUTH_LOCAL_LAN=1)
  └───────────────────┬─────────────────────┘
                      ▼
af-api HTTP Middleware Stack
  ├── 1. Host Validation (outermost — ESC-10, ESC-13)
  │      - Reject unlisted IPv4/IPv6 literals with 400 INVALID_HOST (only 127.0.0.0/8, ::1 implicit)
  │      - Attach validated host to Request extension (no blocking SQLite in security_headers_middleware)
  │      - Keep 100.64.0.0/10 eligible for authenticated internal-domain reachability, never unauth LAN
  ├── 2. Security Headers (inner — ESC-13)
  │      - SPA CSP connect-src uses validated Request extension host ('self'-only fallback; omitted on errors)
  ├── 3. Subdomain Gateway (ESC-09, ESC-10, ESC-14)
  │      - Gateway-protected apps require auth on *.aether.local by default (TOTP via aetherflow_local_app)
  │      - Opt-in AF_ALLOW_UNAUTH_LOCAL_LAN=1 for RFC 1918/ULA/link-local only (never 100.64.0.0/10 or 127/8)
  │      - Basic Auth requires active users.role='admin' & totp_enabled=0 (no master-creds fallback)
  │      - Local rutorrent (127.0.0.1:8087): single-purpose proxy secret header + Require local + REMOTE_USER
  ├── 4. Rate Limit & Auth Layer (ESC-05, ESC-07, ESC-13)
  │      - Inline .route_layer(auth_rate_limit_middleware) on POST /api/v1/auth/refresh & /api/auth/refresh
  │      - Ignore AF_DISABLE_RATELIMIT when AETHERFLOW_ENV is production|release (is_production_or_release_env)
  │      - Uniform active_sessions check on all HTTP/proxy/WS/OIDC surfaces; close /refresh resurrection;
  │        retain strict in-memory ROTATED_TOKEN_GRACE gated on live active_sessions leaf_jti
  │      - /metrics requires METRICS_BEARER_TOKEN or active admin session (METRICS_PUBLIC=1 opt-in only)
  └── 5. Application Subsystems
         ├── McBrowser Cleanup -> af-files (ESC-01): openat2(RESOLVE_NO_XDEV) + st_dev ENOSYS fallback
         ├── FS Browser (ESC-06): remove env::temp_dir() from default allowed roots
         ├── FlowAI /ai/chat (ESC-04): cloud keys/providers admin-only by default; anthropic-local on :8081
         └── Privileged UDS IPC (/run/aetherflow/runner.sock) -> af-runner
                ├── Plugins (ESC-07): cgroup v2 preflight + SocketBindDeny/Allow + IPAddressDeny/Allow=localhost
                ├── Package Executor (ESC-03, ESC-12): delete RunCommand, UnmountPaths for rclone, APT lock timeout
                ├── Self-Update & af-release (ESC-02, ESC-11): current_exe bin, unified aetherflow.env loader,
                │   0600 receipts, post-restart non-fatal log-retention (Rust + release-manager.sh parity)
                └── af-host Backup & Restore (ESC-08, ESC-06): allowlist .master.creds & oidc_rsa.pem (0600,
                    aetherflow:aetherflow), contained AF_DB_PATH quiescence check, runtime_identity() version
```

### Phase 0 — CI, Security Gate, and Release Pipeline Recovery (Standalone Hotfix)

Ships first as an independent hotfix PR with zero overlap against `ESC-01`..`ESC-14`:

1. **Dependency Advisory Remediation (`RUSTSEC-2026-0592`)**: Upgrade `url` from `2.5.8` to the patched crates.io release across all three Rust workspaces (`backend-rs`, `frontend-rs`, `plugins/sdk-template-rust/backend`), regenerating all three `Cargo.lock` files and verifying with `cargo deny --locked` and `cargo audit`.
2. **Gitleaks Allowlist Path Sync**: Update `.gitleaks.toml` using alternation regexes that preserve **both** pre-`ade31c08` legacy paths and post-split paths (`middlewares(?:/tests)?\.rs$`, `routes/tests(?:/marketplace_catalog)?\.rs$`, `ws(?:/telemetry_tests)?\.rs$`) so full-history `gitleaks git .` passes without disabling production secret rules, using standard TOML syntax compatible with Python 3.10 `_parse_gitleaks_toml_fallback`.
3. **`packages/` and Installer Test Regressions (`uutils-coreutils`, Source-Time Init, AdGuard Home DNS)**:
   *   Guard top-level `af_ensure_lock_dir "$LOCK_DIR"` and `af_prepare_logfile_path "$LOGFILE"` in `packages/common.sh` when `AF_SKIP_COMMON_INIT=1` (and pass rebased `LOCK_DIR` / `LOGFILE` environment overrides in installer tests so non-root CI runners never invoke `mkdir -p -m 0750 /install`).
   *   Define one umask-safe directory helper `af_mkdir_p_0755()` in `packages/lib/logging_archives.sh` (`( umask 022 && mkdir -p -- "$@" )` plus `chmod 0755`) and replace multi-level `install -d -m 0755` calls in `packages/lib/state_downloads.sh` (`install_binary_atomic`) and `packages/package/install/installpackage-transmission` so intermediate parent directories receive `0755` under `umask 077` on Ubuntu 26.04 `uutils-coreutils`.
   *   Parameterize `/run/systemd/resolve/resolv.conf` and `/etc/resolv.conf` in `packages/package/install/installpackage-adguardhome` via `AF_RESOLVED_RESOLV_CONF` and `AF_RESOLV_CONF_PATH`, and add `'/run/'` to `rebase()` in `tests/test_marketplace_servarr.py` so the `Node Application Installer Regression Tests` job in `.github/workflows/ci.yml` never leaks CI host resolver content.
   *   Fix path rebasing across `tests/test_autoscan_installer.py` (`REBASE_RE`) and `tests/test_marketplace_ports_removers_hardening.py` (trailing-slash `"/install/"` prefix tuple).

### Track A — Ingress, Authentication, and Session Boundaries (`ESC-09`, `ESC-10`, `ESC-13`, `ESC-14`, `ESC-05`)

Groups all HTTP middleware, Apache vhost rendering, and session-auth changes into one cohesive track touching `proxy_helpers.rs`, `subdomain_proxy.rs`, `vhost_render.rs`, `app_launch.rs`, `routes.rs`, and `auth/` once:

1. **`ESC-09` (Eliminate Provisioning Master-Credential Basic Auth Fallback)**:
   *   Remove `load_master_credentials()` fallback authentication from `verify_proxy_basic_credentials` (`af-api/src/middlewares/proxy_helpers.rs`).
   *   Require every Subdomain Gateway Basic Auth attempt to resolve an active `users` row with `role == "admin"`, `totp_enabled == 0`, and a matching bcrypt hash regardless of `/var/lib/aetherflow/.master.creds`, `/opt/AetherFlow/backend/data/.master.creds`, `/install/.aetherflow.conf`, or `system_config.master_credentials`.
2. **`ESC-10` (Authenticated `*.aether.local`, Decoupled Tailscale Reachability, and TOTP Local Launch)**:
   *   Separate *internal-domain reachability* from *unauthenticated LAN bypass*: keep RFC 6598 (`100.64.0.0/10`) permitted for **authenticated** access to `aetherflow.aether.local` and `<app>.aether.local` (`is_private_or_loopback_ip` / Apache `INTERNAL_NETWORKS`), while introducing a dedicated `is_unauth_local_lan_ip` classifier restricted strictly to RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`, `fe80::/10`), and IPv6 ULA (`fc00::/7`) — unconditionally excluding `100.64.0.0/10` (Tailscale/CGNAT) and `127.0.0.0/8` / `::1` (host loopback). Document that enabling `AF_ALLOW_UNAUTH_LOCAL_LAN=1` also permits local Docker bridge ranges within `172.16.0.0/12`.
   *   Require authentication on `*.aether.local` by default for all ten gateway-protected apps (`mcvnc`, `scrutiny`, `prometheus`, `flaresolverr`, `jackett`, `threadfin`, `rutorrent`, `unmanic`, `netdata`, `autoscan`, matching `external_proxy_requires_auth(&app_name)`). Bypass authentication on `*.aether.local` only when `AF_ALLOW_UNAUTH_LOCAL_LAN` is `1` or case-insensitive `true` (default `false`) AND the client IP passes `is_unauth_local_lan_ip`. `*.aether.local` internal-domain routing continues to operate when `external_access_enabled = 0` and without requiring `*.aether.local` in `ALLOWED_HOSTS`, now gated by authentication.
   *   Add a scoped non-`__Host-` signed app-launch cookie (`aetherflow_local_app`, `HttpOnly`, `SameSite=Lax`, bound to `<app>.aether.local` + active admin `jti`, validated against `active_sessions`) minted by `af-api/src/app_launch.rs` so TOTP-enrolled admins can launch protected apps on HTTP `*.aether.local` from `aetherflow.aether.local`.
3. **`ESC-13` (Host Validation, Middleware Ordering, CSP Non-Reflection, and Rate Limiting)**:
   *   Narrow `local_control_plane_host` (`host_resolution.rs`) so only canonical loopback IP literals (`127.0.0.0/8`, `::1`) bypass `ALLOWED_HOSTS`; non-loopback IPv4/IPv6 literals must appear in `ALLOWED_HOSTS`, `PUBLIC_URL`, `OIDC_ISSUER`, or `ALLOWED_CORS_ORIGIN` (rejecting unlisted hosts with `400 INVALID_HOST` and unauthorized internal-domain peers with `403 INTERNAL_DOMAIN`). Update `af-cli/src/provision/steps.rs` so provisioning with non-loopback `BIND_ADDR` seeds the host's LAN/public IP into `ALLOWED_HOSTS`.
   *   Reorder `host_validation_middleware` **outside** `security_headers_middleware` in `routes.rs` and attach the validated host to a `Request` extension inside `host_validation_middleware`. `security_headers_middleware` reads only that extension (zero blocking SQLite calls on Tokio worker threads), emits `ws://{validated_host}` / `wss://{validated_host}` for SPA WebSockets, falls back to `'self'` only when absent, and skips SPA CSP on non-200 error responses. (`oidc/keys.rs` already delegates to `is_trusted_request_host` and needs no edit.)
   *   Attach `auth_rate_limit_middleware` inline via `.route_layer(...)` on `POST /api/v1/auth/refresh` inside `auth_routes` (preserving `tests/test_zero_go_cutover.py`'s sub-router parser) and on legacy `POST /api/auth/refresh`.
   *   In `middlewares/rate_limit.rs`, reuse `auth/middleware.rs::is_production_or_release_env` so `AF_DISABLE_RATELIMIT` is ignored whenever runtime `AETHERFLOW_ENV` is `production` or `release` (case-insensitive; unset defaults to non-production, matching `CSRF_DISABLED`).
4. **`ESC-14` (Unified Gateway Ingress for ruTorrent, Single-Purpose Loopback Secret, and `htpasswd` Safety)**:
   *   Remove `rutorrent` exclusions in `vhost_render.rs` (emitting unquoted lowercase `RequestHeader set x-aetherflow-external-app rutorrent`) and `af-api/src/app_launch.rs` (enabling launch-ticket / TOTP SSO). Scope `/etc/apache2/AetherFlow/htpasswd` in `vhost_render.rs` strictly as a legacy fallback for custom Apache `blocks` or non-loopback `BIND_ADDR`, retiring automatic `htpasswd` generation for standard gateway-proxied external apps.
   *   Protect local `127.0.0.1:${APP_PORT}` (`rutorrent.conf`) with one single-purpose internal proxy secret (reusing the `librespeed-proxy-token.conf` pattern: `/etc/aetherflow/rutorrent-proxy-token.conf` `0640 root:www-data` included by Apache to verify `Require expr "%{HTTP:X-Aetherflow-Rutorrent-Token} == '<token>'"` alongside `Require local`, paired with `/etc/aetherflow/rutorrent-proxy-token` `0640 root:aetherflow` read by `af-api`'s `subdomain_proxy.rs` to inject the header; cleaned up on removal in `removepackage-rutorrent`, `package_purge.rs`, and `runtime_targets.rs`). This prevents local plugins under `ESC-07` from calling rTorrent XML-RPC.
   *   In `installpackage-rutorrent`, map `X-Aetherflow-User` to PHP `$_SERVER['REMOTE_USER']` via Apache `SetEnvIf`, rewrite existing `/etc/apache2/sites-available/rutorrent.conf` on upgrade so upgraded hosts do not enter a `401` loop, keep `rutorrent.htpasswd` Basic Auth only when `AF_APACHE_LISTEN_ALL=1`, and derive the SCGI readiness probe user (`RUT_PROBE_USER`) from `MASTER_USER` / configured ruTorrent profile when `AF_APACHE_LISTEN_ALL=0`.
   *   In `af-cli/src/provision/apache_htpasswd.rs`, remove `generate_crypto_secret(24)` silent writes: when no plaintext password is supplied via `AETHERFLOW_PASSWORD`, `AETHERFLOW_MASTER_CREDS_SECRET`, or unencrypted legacy credentials, preserve an existing valid file (non-empty `user:$2[aby]$...` bcrypt entries) and return `Ok(Some(path))`, or return `Ok(None)` without writing.
5. **`ESC-05` (Uniform `active_sessions` Enforcement, `/refresh` Resurrection Fix, and Safe In-Memory Rotation Grace)**:
   *   Add shared `verify_active_session_on_conn` in `af-api/src/auth/tokens.rs` (re-exported via `auth.rs`), composing existing `load_active_human_subject` + `af_db::has_unexpired_active_session` + `af_db::token_revocation_status_with_conn` (retiring silent `table_exists("active_sessions")` fail-open fallbacks). Define one typed result enum mapping `Suspended` (`403 ACCOUNT_SUSPENDED` on API routes, `401` on forward-auth), `MissingOrRevoked` (`401 SESSION_EXPIRED` / `401 UNAUTHORIZED`), and `DbError` (`503`).
   *   Call `verify_active_session_on_conn` uniformly across `auth_middleware`, `proxy_helpers.rs` (`resolve_optional_authenticated_user`), `auth/sessions.rs` (`verify_proxy_auth`), `routes/health.rs` (`/metrics`), `routes/marketplace/catalog.rs` (optional `/api/v1/public/marketplace` — revoked/missing human session falls back to unauthenticated catalog view), `app_launch.rs` (`__Host-aetherflow_app` & `aetherflow_local_app`), `ws/tickets.rs`, and `oidc/authorize.rs`. Non-human tokens (`METRICS_BEARER_TOKEN`, API keys, OIDC client tokens) remain separate from human `active_sessions`.
   *   Close the `/refresh` resurrection bug in `auth/sessions.rs` (`refresh_session_with_peer`): fail closed with `401` whenever `existing_family_opt.is_none()` so deleted `active_sessions` rows cannot be recreated by a refresh token.
   *   Retain strict-fingerprint in-memory `ROTATED_TOKEN_GRACE` (`10s`) and `ROTATED_SESSION_SUCCESSOR` so concurrent browser tabs (where `af-web-core/src/api.rs` serializes per tab only) never trigger replay-induced session-family deletion, while tightening grace acceptance to verify that `leaf_jti` still holds an unexpired `active_sessions` row (logout, single-session revoke, and admin kill already delete `active_sessions` and evict grace entries immediately).

### Track B — Filesystem Confinement, Host Backup/Restore, and FS Browser (`ESC-01`, `ESC-08`, `ESC-06` FS/Version)

1. **`ESC-01` (Mount-Boundary Guard on Recursive Deletion)**:
   *   Reuse `af-files/src/syscall.rs::openat2_with_resolve` with `RESOLVE_NO_XDEV` inside `af-files/src/mutation.rs` (retaining `fstatat` `st_dev` comparison as `ENOSYS` fallback) anchored to `self.root_fd` / parent directory FD before entering `user-<id>`, blocking both cross-filesystem mounts and same-filesystem bind mounts (`BindPaths=`) on nested subdirectories or directly on `user-<id>`.
   *   Define `RemoveTreeOutcome { removed_bytes: u64, skipped_mount_paths: Vec<PathBuf> }` (root-relative paths) in `af-files/src/types.rs` and re-export from `af-files/src/lib.rs`. Keep `BrowserFs::remove_tree_with_size*` returning `Result<u64, RemovalError>` (applying the same boundary skip internally so McBrowser interactive deletes in `info_delete.rs` also stay confined without breaking callers) and add `remove_tree_with_outcome` / `remove_tree_with_outcome_allowing_symlinks` for `account_cleanup.rs`. Ensure `cleanup_staging_tree` and `remove_orphaned_upload_temps_if_only_children` inherit `RESOLVE_NO_XDEV`.
   *   In `account_cleanup.rs`, when `Ok(RemoveTreeOutcome)` returns non-empty `skipped_mount_paths`, delete the completed `account_storage_cleanup` row (zero schema migration, preventing 15-minute infinite retries) and log a structured `WARN` plus `admin_audit_log` entry naming the preserved mount paths.
   *   In `deploy/systemd/aetherflow-api.service`, replace the commented `BindPaths=` example with an explicit warning against bind-mounting shared storage beneath `/var/lib/aetherflow/mcbrowser/user-*`, and remove the retired `EnvironmentFile=-/opt/AetherFlow/current/backend/.env` fallback in the same edit.
2. **`ESC-08` (Canonical `/` Restore Allowlist and Contained `AF_DB_PATH` Quiescence)**:
   *   In `af-host/src/restore/policy.rs`, add `var/lib/aetherflow/.master.creds` and `var/lib/aetherflow/oidc_rsa.pem` to canonical `/` destinations. In `af-host/src/restore/journal.rs`, extend `is_secret_credential_entry` to match `.creds` so `.master.creds` receives mandatory `0o600` clamping. In `af-host/src/restore/execution.rs`, extend `trusted_ancestor_uid` and `aetherflow:aetherflow` ownership (`trusted_sqlite_uid`/`trusted_sqlite_gid`) beyond `SqliteSnapshot` to canonical `/var/lib/aetherflow/{.master.creds,oidc_rsa.pem}` when running as `root` (skipping `chown` in non-root staging/tests).
   *   In `af-cli/src/cli/parse_backup.rs`, accept `--allow-overwrite` as an alias for `--allow-staging-overwrite` (permitting overwrite of non-empty staging targets) on `af backup restore-preflight`.
   *   In `af-cli/src/commands/backup.rs`, reuse existing `is_system_scoped_backup_path` and `resolve_contained_sqlite_restore_override` in both `RestoreDestructive` and `RecoverInterrupted` so live `aetherflow-api.service` quiescence runs whenever `resolved_target` is canonical `/` (no `--root` isolation) or contains the live `AF_DB_PATH`, while isolated staging restores use `NoopQuiescenceController`.
3. **`ESC-06` (FS Browser Default Roots and Runtime Version Identity)**:
   *   In `af-api/src/routes/fs_browser.rs`, remove `env::temp_dir()` from the default allowed roots when `AF_ALLOWED_FS_ROOTS` is unset (retaining `/mnt`, `/media`, `/srv`, `/data`, `/home`, and non-service `env::current_dir()`).
   *   Reuse `af-release::runtime::runtime_identity()` across all five hardcoded `"v4.0.0"` / `"4.0.0"` sites (`af-cli/src/commands/backup.rs`, `af-cli/src/cli/parse_backup.rs`, `af-host/src/backup.rs`, `af-host/src/restore/policy.rs`, `af-host/src/restore/journal.rs`), respecting `--root`, validating semver via `af_host::parse_semver_triplet`, and falling back to `concat!("v", env!("CARGO_PKG_VERSION"))` for non-semver stamps.

### Track C — Privileged Runner, Release Engine, Plugin Isolation, and Package Tooling (`ESC-07`, `ESC-11`, `ESC-02`, `ESC-03`, `ESC-12`, `ESC-06` Units/Shell)

1. **`ESC-07` (Plugin Cgroup v2 Isolation and Authenticated `/metrics`)**:
   *   In `af-runner/src/plugins/isolation.rs`, append `--property=SocketBindDeny=any`, `--property=SocketBindAllow=ipv4:tcp:{port}`, `--property=IPAddressDeny=any`, and `--property=IPAddressAllow=localhost` to transient plugin units. In `af-runner/src/plugins.rs` (`ensure_systemd_isolation_ready`), probe cgroup v2 (`/sys/fs/cgroup/cgroup.controllers`) and systemd version `>= 249`, failing closed with `PluginRunnerError::IsolationUnavailable` (`503 PLUGIN_ISOLATION_UNAVAILABLE`) when unsupported (preserving `using_custom_systemd_run_override()` in unit tests). Document explicitly that `IPAddressDeny=any` + `IPAddressAllow=localhost` blocks plugin outbound internet egress.
   *   In `af-api/src/routes/health.rs` (`is_metrics_request_authorized`), remove the unauthenticated loopback shortcut so `/metrics` requires `Authorization: Bearer <METRICS_BEARER_TOKEN>` or an active admin session even on `127.0.0.1`/`::1`, keeping live `METRICS_PUBLIC=1` as explicit opt-in only. Drop speculative `installpackage-prometheus` changes (the installer never scraped `aetherflow-api`).
2. **`ESC-11` + `ESC-02` (Unified `aetherflow.env` Loader, Non-Fatal Rollback Log-Retention, Immutable Binary Resolution, and `0600` Receipts)**:
   *   In `af-release/src/health.rs` (`restart_systemd_units`) and `deploy/release-manager.sh` (Stage 3/4 parity), enable and restart `aetherflow-runner.service` and `aetherflow-api.service` before running `/var/log/aetherflow` directory ownership setup, `aetherflow-log-retention.timer` enablement, and `aetherflow-log-retention.service` start. Execute all three log-retention steps best-effort (`required = false`), updating `run_systemctl(..., false)` to emit a structured warning to `append_jsonl_log(&config.log_file, "WARN", ...)` instead of silently returning `Ok(())`.
   *   Unify `/etc/aetherflow/aetherflow.env` (`0600`) loading in `af-release/src/config.rs` with explicit precedence: `process env > explicit --config assignment > /etc/aetherflow/aetherflow.env (unless AETHERFLOW_SKIP_ENV_FILES=1) > default-fallback --config line (is_default_fallback = true) > compiled default`. Resolve `HEALTH_ENDPOINT`, GitHub tokens (`AF_GITHUB_TOKEN` / `GITHUB_TOKEN` / `GH_TOKEN`, stored in a redacted non-`Debug`/non-`Serialize` field passed explicitly to `artifact/provider.rs`), and root-only `AETHERFLOW_SKIP_PROVENANCE_VERIFY` (`artifact.rs`) via this loader—and mirror in `deploy/release-manager.sh`. Never pass secrets via `systemd-run --setenv` or copy them into `<jobs_dir>/<unit>.conf` (eliminating persistent token copies and the `deploy/release-manager.sh` `chmod 0644` staging leak).
   *   Reorder `af-runner/src/lib.rs` (`resolve_af_cli_binary`, `package_script_roots`, `resolve_release_manager_script`, `resolve_sandbox_script_path`) to check `env::current_exe().parent()` before mutable `/opt/AetherFlow/current` (preserving explicit `AETHERFLOW_CLI_BIN` override first).
   *   Clamp `.self-update-jobs/*.json` receipts from `0o644` to `0o600` in `af-runner/src/job_receipts.rs`, `af-runner/src/core_restart_worker.sh` (Python `os.fchmod`), and `deploy/release-manager.sh` (Python `os.fchmod`).
   *   Remove retired `EnvironmentFile=-/opt/AetherFlow/current/backend/.env` from `deploy/systemd/aetherflow-runner.service` (keeping `deploy/release-manager.sh`'s Stage 0 v3→v4 migration intact).
3. **`ESC-03` (Delete Dead `DeclarativeStep::RunCommand` and Migrate `rclone` to `UnmountPaths`)**:
   *   Extend `DeclarativeStep::UnmountPaths` in `package_executor/model.rs` with `{ paths: Vec<String>, only_if_delete_data: bool }`, migrate `build_rclone_recipe` (`catalog.rs`, `paths: vec!["/mnt/remote".into()], only_if_delete_data: true`), update `build_mergerfs_recipe` (`only_if_delete_data: false`), and keep `steps_files_services.rs`'s existing fail-closed non-lazy shell-free unmount sequence (`is_active_mountpoint` → `fusermount -u` → `umount` without `-l` → re-check).
   *   Delete `DeclarativeStep::RunCommand` completely from `model.rs`, `validation.rs`, and `steps_system.rs` (zero callers remain after `rclone` migrates).
4. **`ESC-12` + `ESC-06` (Bash APT Lock Timeout, Backup Pruning, and Shell Template Hygiene)**:
   *   In `packages/lib/versions_apt.sh`, centralize validated digits-only `DPKG_LOCK_TIMEOUT` (default `120` when unset or non-numeric) injection of `-o DPkg::Lock::Timeout=<N>` for **both** the `apt-get()` wrapper and `rollback_apt_packages()`.
   *   In `packages/lib/config_database.sh` (`finish_app_archive_update`, invoked post-activation from `write_lock` in `apache_dns_locks.sh`), prune old `${destination}.af-backup.*` staging directories keeping the newest 2 backups (matching `retain_successful_app_backups`), verifying `.af-archive-owner` and skipping `.af-archive-pending` and symlinks; apply the same retention helper to `replace_app_tree` backups.
   *   In `packages/package/remove/removepackage-palate`, print the backup-retention note only when `DELETE_DATA != true` and print purge confirmation when `DELETE_DATA=true`.
   *   Update `docs/installpackage-template.sh` to use `af-<app_id>.service`, `validate_config_paths` (path-traversal guard), `write_config_file` (atomic mode-clamped config writer), `af_github_curl` (pinned TLS GitHub fetcher), and `127.0.0.1` loopback binding, passing `tests/check_shell_hygiene.py`.

### Track D — FlowAI Guardrails and Contract Test Integrity (`ESC-04`, `ESC-06` E2E/Streaming)

1. **`ESC-04` (FlowAI Port Collision, Self-Target Guard, and Outbound Cloud-Credential Invariant)**:
   *   Unify all four `"http://localhost:8080"` defaults (`flowai.rs` and `ai_providers.rs`) behind one constant `DEFAULT_ANTHROPIC_LOCAL_ENDPOINT = "http://127.0.0.1:8081"`.
   *   Enforce a structural outbound cloud-credential/endpoint invariant inside `run_chat_session`: local providers (`ollama`, `lm-studio`, `anthropic-local` / `localai`) never attach paid cloud API keys (`ps.anthropic_api_key`, etc.) and never default to `https://api.anthropic.com`; any dispatch using a paid cloud API key or cloud endpoint (`openai`, `anthropic`, `gemini`, including `"anthropic"` unless configured to a local endpoint without a cloud key) requires `user.role == "admin"` unless `AF_AI_ALLOW_USER_CLOUD_PROVIDERS` is `1` or case-insensitive `true` (default `false`), otherwise returning `403 AI_PROVIDER_ADMIN_ONLY`.
   *   Enforce a self-target guard returning `400 AI_SELF_TARGET_REJECTED` at three boundaries (`routes/settings.rs` save-time validation, `test_ai_connection`, and outbound local dispatch), rejecting any URL whose host resolves syntactically or via canonical IP parsing to `localhost`, `127.0.0.0/8`, `::1`, `::ffff:127.0.0.0/104`, `0.0.0.0`, `[::]`, or configured `BIND_ADDR` on `aetherflow-api`'s configured `PORT` (default `8080`, handling implicit `80`/`443` scheme ports).
2. **`ESC-06` (E2E Contract Integrity, Dead `--socket` Removal, and Streaming Fixture Parity)**:
   *   Replace all 25 `self.assert_true(True, ...)` placeholders across eight Tier 1/2 Python files with deterministic declarative/AST/source/test-anchor assertions enumerated in Item 26 below, while preserving the 3 existing `--mode live` checks in `test_boundaries_api.py`.
   *   Remove dead `RunnerSocketClient` (`tests/e2e/framework.py`) and unused `--socket` (`tests/e2e/runner.py`, `scripts/run_embedded_e2e.sh`, and `tests/test_v4_release_bootstrap_ci.py`).
   *   Update `scripts/validate-streaming.sh` to check non-emptiness (`-s`) and unset/re-export all three `AF_STREAMING_*_FIXTURE` variables in `--integrated` mode, and wire all three fail-closed into `frontend-rs` streaming tests (`types.rs`, new JSON deserialization test in `history.rs` parsing `{"administrative": HistoryPage, "linked": HistoryPage}`, and `portability.rs`).

### Continuous Documentation Synchronization

Each phase or track updates its mapped living documentation files in the same PR (retiring resolved `ESC-*` hazard notices and documenting new environment variables, flags, and zero-stub contract status) while preserving all automated doc-contract `unittest` anchors (`tests/test_zero_go_cutover.py`, `tests/test_v4_release_bootstrap_ci.py`, `tests/test_listenarr_release_policy.py`, `tests/test_ci.py`).

## Alternatives Considered

### Alternative A: Serial Severity-Ordered 5-Stage Waterfall Locking Phase 0 Behind Full Hardening Spec

*   **Pros**: Fixes all three Critical items (`ESC-01`, `ESC-09`, `ESC-10`) strictly ahead of High/Medium work under one linear phase sequence.
*   **Cons**: Stalls emergency Phase 0 CI recovery behind 14-defect architectural convergence and edits six shared files (`vhost_render.rs`, `proxy_helpers.rs`, `aetherflow-api.service`, `commands/backup.rs`, `routes/health.rs`, `deploy/release-manager.sh`) and 27 living documentation files across multiple redundant passes.
*   **Reason for Rejection**: Rejected by author: keeping one unified design document while shipping Phase 0 immediately as an independent CI hotfix and organizing `ESC-01`..`ESC-14` into four domain tracks eliminates multi-pass file churn and restores CI immediately.

### Alternative B: Always Require Auth or Hard-Block Tailscale `100.64.0.0/10` on All `*.aether.local` Access (`ESC-10`)

*   **Pros**: Removes all CIDR-based authentication exceptions (always-auth) or hard-rejects Tailscale peers at the IP classifier without distinguishing reachability from unauthenticated bypass.
*   **Cons**: Permanently breaks isolated home LAN workflows that opt into passwordless `<app>.aether.local` bookmarks; hard-blocking `100.64.0.0/10` breaks authenticated Tailscale admin access to `aetherflow.aether.local`; and omitting a local launch cookie locks TOTP-enrolled admins out of HTTP `*.aether.local`.
*   **Reason for Rejection**: Rejected by author: decoupling authenticated Tailscale reachability from the opt-in `AF_ALLOW_UNAUTH_LOCAL_LAN=1` LAN bypass (never allowing `100.64.0.0/10` or loopback) and adding the scoped `aetherflow_local_app` cookie for TOTP admins secures default access without breaking legitimate authenticated Tailscale or TOTP workflows.

### Alternative C: Retain External Apache Basic Auth for ruTorrent or Leave `127.0.0.1:8087` Protected Only by `Require local` (`ESC-14`)

*   **Pros**: External Basic Auth avoids one loopback hop; `Require local` without a proxy token avoids adding `/etc/aetherflow/rutorrent-proxy-token.conf`.
*   **Cons**: Static external `htpasswd` cannot enforce TOTP and drifts from SQLite admin offboarding; leaving `127.0.0.1:8087` open to `Require local` without a shared proxy secret exposes rTorrent XML-RPC execution hooks to local plugins sharing the host network namespace under `ESC-07`.
*   **Reason for Rejection**: Rejected by author: routing external `rutorrent` through the Rust Subdomain Gateway with `app_launch.rs` TOTP SSO and gating local `127.0.0.1:8087` behind one single-purpose internal proxy secret (plus `REMOTE_USER` mapping and upgrade migration) unifies authentication across all ten protected apps without regressing loopback rTorrent security.

### Alternative D: `PrivateNetwork=yes` or `127.0.0.0/8` Loopback Subnet Partitioning for Managed Plugins (`ESC-07`)

*   **Pros**: Full network-namespace isolation (`PrivateNetwork=yes`) or per-plugin loopback addresses (`127.0.21.<slot>`) would block plugins from reaching sibling `127.0.0.1:<port>` Marketplace apps.
*   **Cons**: `PrivateNetwork=yes` with UDS breaks the TCP `PLUGIN_BIND_ADDR:PLUGIN_PORT` contract in `plugins/sdk-template-rust/`; moving plugins and `af-api` off `127.0.0.1` breaks `plugins/proxy.rs` (`127.0.0.1` assumption), Apache vhosts, `af-release`, and runbooks.
*   **Reason for Rejection**: Rejected by author: host-network systemd hardening (`SocketBindDeny`/`SocketBindAllow` + `IPAddressDeny=any` + `IPAddressAllow=localhost` + cgroup v2 preflight) combined with authenticated `/metrics` and the `ESC-14` ruTorrent proxy token preserves the TCP plugin SDK contract while documenting the residual loopback port-sharing boundary.

### Alternative E: Zero Rotation Grace (`Delete ROTATED_TOKEN_GRACE`) or `prev_jti` SQLite Schema Migration (`ESC-05`)

*   **Pros**: Deleting `ROTATED_TOKEN_GRACE` removes the 10-second in-memory grace window; adding `prev_jti` columns persists rotation grace in SQLite.
*   **Cons**: Because `frontend-rs/crates/af-web-core/src/api.rs` serializes refresh requests per tab only (`thread_local! REFRESH`), deleting `ROTATED_TOKEN_GRACE` sends concurrent tab refreshes into replay detection (`auth/sessions.rs`), wiping the entire `active_sessions` family and logging out every tab; `prev_jti` columns introduce an irreversible SQLite schema migration and cannot return rotated JWT strings without persisting raw tokens.
*   **Reason for Rejection**: Rejected by author: live `logout()`, `revoke_session()`, and `revoke_all_user_credentials()` already delete `active_sessions` and evict in-memory grace entries immediately. Retaining strict-fingerprint in-memory `ROTATED_TOKEN_GRACE` tightened on live `active_sessions` (`leaf_jti`) while closing the `/refresh` resurrection bug and unifying `active_sessions` checks across all auth surfaces prevents multi-tab lockouts with zero schema migration.

### Alternative F: SQLite Per-User Daily Chat Quotas or Rate-Limit-Only Non-Admin FlowAI Chat (`ESC-04`)

*   **Pros**: Daily SQLite quotas allow capped cloud usage for standard users; rate-limit-only avoids role checks and new database tables.
*   **Cons**: Request-count quotas do not cap per-request token cost and add SQLite write/pruning state; rate-limit-only permits sustained non-admin cloud API charges over time.
*   **Reason for Rejection**: Rejected by author: gating paid cloud keys and endpoints to admins by default (with `AF_AI_ALLOW_USER_CLOUD_PROVIDERS=1` opt-in) while keeping local providers open to all authenticated users restricts third-party cloud access for non-admins with zero schema overhead.

### Alternative G: Mark the 25 Stubbed Contract Checks `SKIP` or Delete Them from Tier 1/2 (`ESC-06`)

*   **Pros**: Removes placeholder passes without authoring static assertions and concentrates verification on `--mode live` or Rust/Playwright suites.
*   **Cons**: Reduces the 387-check `--mode contract` verification surface and drops offline contract coverage tracked in `tests/TEST_INFRA.md` and `tests/TEST_READY.md`.
*   **Reason for Rejection**: Rejected by author: replacing all 25 placeholders with enumerated declarative/AST/test-anchor assertions preserves 387-check offline contract coverage while ensuring each check fails on regression.

---

## Non-Functional Requirements

### Security and Privacy

*   **Residual Risk — `ESC-07` Host-Loopback Port Sharing**: Host-network systemd hardening (`SocketBindDeny`/`SocketBindAllow` + `IPAddressDeny=any` + `IPAddressAllow=localhost`) keeps managed plugins in the host network namespace. Because systemd `IPAddressAllow=localhost` filters by IP address rather than destination TCP port, a malicious plugin cannot bind unauthorized ports, access `/metrics` (authenticated), reach `rutorrent` (gated by the `ESC-14` proxy secret), or connect to external IPs, but can still initiate TCP connections to other loopback-bound Marketplace apps on `127.0.0.1:<port>` (such as McVNC). Per [Security Guide](../security.md), operators must install only reviewed/trusted plugins on hosts running loopback-bound apps; full network isolation requires a future `PrivateNetwork=yes` plugin SDK transport.
*   **Plugin Outbound Egress Constraint (`ESC-07`)**: Enforcing `IPAddressDeny=any` + `IPAddressAllow=localhost` blocks managed plugins from initiating outbound internet or LAN connections; plugin documentation will state this constraint explicitly.
*   **Secret Hygiene**: No GitHub token or credential may appear in `systemd-run --setenv` arguments (readable via `systemctl show`), persistent `<jobs_dir>/<unit>.conf` copies, `0644` receipt files, `ReleaseConfig` `Debug`/`Serialize` output, or unlogged random `htpasswd` writes. All secret files (`aetherflow.env`, `.self-update-jobs/*.json` receipts, `.master.creds`, `oidc_rsa.pem`) remain `0600` (`0640` only where `root:aetherflow` or `root:www-data` group read is required, such as `/etc/aetherflow/rutorrent-proxy-token*`).

### Performance and Latency

*   **Auth Hot Path (`ESC-05`)**: Combining `af_db::has_unexpired_active_session` with `load_active_human_subject` on the 8-connection `DB_READ_POOL` (`query_only = ON`) adds one indexed primary-key lookup per authenticated request (target budget `<1 ms` on local SQLite WAL, zero writer-pool contention).
*   **Security Headers Middleware (`ESC-13`)**: Passing the validated host from `host_validation_middleware` via a `Request` extension adds zero SQLite queries or Tokio worker blocking in `security_headers_middleware`.
*   **External ruTorrent Proxy Hop (`ESC-14`)**: Streaming external `rutorrent` through `af-api`'s reverse proxy (`Body::from_stream`) avoids buffering request/response bodies in RAM (target overhead `<1 ms` on local loopback).

### Rollout and Rollback

*   **Execution Ordering**: Phase 0 merges first as an independent hotfix PR and must pass `CI`, `Security Gate`, and `Production Release Pipeline` on `origin/nightly`. Tracks A, B, C, and D then merge independently (Track A and Track B prioritized first because they resolve all three Critical items `ESC-01`, `ESC-09`, and `ESC-10`).
*   **Operator Compatibility**:
    *   Single-owner home LAN hosts opting into unauthenticated `*.aether.local` can set `AF_ALLOW_UNAUTH_LOCAL_LAN=1` (RFC 1918, IPv6 ULA, and link-local only — never `100.64.0.0/10` or loopback).
    *   Hosts where non-admin users need cloud FlowAI providers can set `AF_AI_ALLOW_USER_CLOUD_PROVIDERS=1`.
    *   External or local Prometheus scrapers configured by operators for `/metrics` must supply `METRICS_BEARER_TOKEN` (or operators may set `METRICS_PUBLIC=1` on isolated hosts).
    *   IP-only hosts upgrading into Track A (`ESC-13`) must ensure their host LAN/public IP is listed in `ALLOWED_HOSTS` (fresh `af provision` runs populate this automatically).
*   **Rollback Strategy**: Each phase and track ships as an isolated PR on `nightly`, revertible via `git revert` with zero irreversible SQLite schema migrations. On live hosts where Apache vhosts (`ESC-10`/`ESC-14`), `rutorrent.conf`, or packaged systemd units (`ESC-06`) were rewritten, rolling back code also requires re-running Apache vhost sync / installer reconciliation and `systemctl daemon-reload` after deploying the reverted release.

---

### Additional Resources

*   [Architecture](../architecture.md), [API Reference](../API.md), and [Configuration](../configuration.md)
*   [Security Guide](../security.md) and [Threat Model](../threat_model.md)
*   [Operational Runbook](../RUNBOOK.md), [Deployment Checklist](../deployment_checklist.md), and [Upgrading](../upgrading.md)
*   [Rust Release Engine](../rust-release-engine.md), [Self-Update](../self-update.md), [Rust Host Management](../rust-host-management.md), [Rust Admin CLI](../rust-admin-cli.md), and [Rust Package Executor](../rust-package-executor.md)
*   [Marketplace](../marketplace.md), [Marketplace Developer Guide](../marketplace-developer-guide.md), [McBrowser](../mcbrowser.md), [FlowAI](../flowai.md), and [Plugins README](../../plugins/README.md)
*   [Testing Guide](../testing.md), [Streaming Validation](../streaming-validation.md), [Test Infrastructure](../../tests/TEST_INFRA.md), and [Static Contract Verification Report](../../tests/TEST_READY.md)

### Future Improvements

*   **Network-namespace plugin transport (`PrivateNetwork=yes`)**: In a future plugin SDK major revision, introduce UDS or per-plugin bridged transport so managed plugins lose TCP reachability to sibling loopback-bound Marketplace apps (`ESC-07` residual risk).
*   **`v4.0.0` stable cutover**: After Phase 0 and Tracks A–D land and pass KVM clean-host/lifecycle/privileged guest drills plus blind independent multi-model certification, promote `nightly` to `master` (clearing the 45 legacy pre-v4 Dependabot alerts) and tag `v4.0.0`.
*   **Additional declarative Rust Marketplace recipes**: Incrementally migrate high-risk Bash installers into the declarative Rust executor once `ESC-03` and `ESC-12` land.

---

## Detailed Implementation Plan

Phase 0 ships first as a standalone CI recovery PR. Tracks A–D then execute as domain-aligned PRs so shared files and living documentation are edited once per domain. No production implementation code is included below; target files, behavioral invariants, error codes, environment variables, and verification gates are specified for every item.

### Target Files to Create/Modify

#### Phase 0 — CI, Security Gate, and Release Pipeline Recovery (Standalone Hotfix PR)

1. **`backend-rs/Cargo.lock`, `frontend-rs/Cargo.lock`, `plugins/sdk-template-rust/backend/Cargo.lock`** (Modify)
   *   **Type / Scope**: Rust Dependency Lockfiles (`RUSTSEC-2026-0592`)
   *   **Proposed Changes**: Run `cargo update -p url` across all three workspaces to upgrade `url` from `2.5.8` to the patched crates.io release resolving `RUSTSEC-2026-0592` (`Url::origin()` nested `blob:` stack overflow). Do not alter unrelated crate versions or `Cargo.toml` manifests unless required by a minimum version constraint.

2. **`.gitleaks.toml`** (Modify)
   *   **Type / Scope**: Security Gate Configuration
   *   **Proposed Changes**: Update existing synthetic test-fixture allowlist `paths` using alternation regexes that preserve **both** pre-`ade31c08` legacy paths and post-split paths so full-history `gitleaks git .` passes, keeping exact `condition = "AND"` secret regexes and standard TOML syntax compatible with `_parse_gitleaks_toml_fallback` in `tests/test_zero_go_cutover.py`:
       *   `generic-api-key` RFC 6455 `Sec-WebSocket-Key` nonce: `backend-rs/crates/af-api/src/middlewares(?:/tests)?\.rs$`.
       *   `generic-api-key` redaction canary: `backend-rs/crates/af-api/src/routes/tests(?:/marketplace_catalog)?\.rs$`.
       *   `curl-auth-header` and `curl-auth-user` redaction canaries: `backend-rs/crates/af-api/src/ws(?:/telemetry_tests)?\.rs$` and `backend-rs/crates/af-api/src/routes/tests(?:/marketplace_catalog)?\.rs$`.

3. **`packages/common.sh`, `packages/lib/logging_archives.sh`, `packages/lib/state_downloads.sh`, `packages/package/install/installpackage-transmission`, `packages/package/install/installpackage-adguardhome`** (Modify)
   *   **Type / Scope**: Shared Shell Installer Runtime (`uutils-coreutils`, Source-Time Init, AdGuard Home Resolver)
   *   **Proposed Changes**:
       *   In `packages/common.sh`, guard top-level `af_ensure_lock_dir "$LOCK_DIR"` and `af_prepare_logfile_path "$LOGFILE"` behind `[[ "${AF_SKIP_COMMON_INIT:-0}" != "1" ]]` so isolated dry-run tests can source `common.sh` without creating `/install` on non-root CI runners.
       *   In `packages/lib/logging_archives.sh`, define helper `af_mkdir_p_0755()` executing `( umask 022 && mkdir -p -- "$@" )` followed by `chmod 0755 -- "$@"`. Replace multi-level `install -d -m 0755` calls in `packages/lib/state_downloads.sh` (`install_binary_atomic`) and `packages/package/install/installpackage-transmission` (`$WEB_DIR` creation) with `af_mkdir_p_0755` so intermediate parent directories receive mode `0755` instead of `0700` under `umask 077` on Ubuntu 26.04 `uutils-coreutils`.
       *   In `packages/package/install/installpackage-adguardhome`, replace hardcoded `/run/systemd/resolve/resolv.conf` and `/etc/resolv.conf` in the DNS handoff block with `${AF_RESOLVED_RESOLV_CONF:-/run/systemd/resolve/resolv.conf}` and `${AF_RESOLV_CONF_PATH:-/etc/resolv.conf}` (matching `packages/lib/apache_dns_locks.sh`'s parameterized `resolv_path`).

4. **`tests/installer_test_helpers.py`, `tests/test_autoscan_installer.py`, `tests/test_marketplace_ports_removers_hardening.py`, `tests/test_sandbox_paths.py`, `tests/test_marketplace_servarr.py`** (Modify)
   *   **Type / Scope**: Python Installer Regression Harnesses
   *   **Proposed Changes**:
       *   Fix path rebasing in `test_autoscan_installer.py` (`REBASE_RE` negative lookbehind skipping bare `/install` in `${LOCK_DIR:-/install}`) and `test_marketplace_ports_removers_hardening.py` (trailing-slash `"/install/"` prefix tuple missing bare `/install`), and pass explicit rebased `LOCK_DIR` and `LOGFILE` environment overrides before sourcing `common.sh` in `test_sandbox_paths.py` and `installer_test_helpers.py`.
       *   In `test_marketplace_servarr.py`, add `'/run/'` to `rebase()` and set `AF_RESOLVED_RESOLV_CONF` / `AF_RESOLV_CONF_PATH` in `test_adguardhome_dns_handoff_and_failed_probe_rollback` so GitHub Actions runner `/run/systemd/resolve/resolv.conf` content never leaks into the fixture.

---

#### Track A — Ingress, Authentication, and Session Boundaries (`ESC-09`, `ESC-10`, `ESC-13`, `ESC-14`, `ESC-05`)

5. **`backend-rs/crates/af-api/src/middlewares/proxy_helpers.rs`, `backend-rs/crates/af-api/src/middlewares/subdomain_proxy.rs`** (Modify)
   *   **Type / Scope**: Subdomain Gateway Auth, Private-IP/LAN Classifiers, and ruTorrent Proxy Secret (`ESC-09`, `ESC-10`, `ESC-14`, `ESC-05`)
   *   **Proposed Changes**:
       *   In `proxy_helpers.rs` (`verify_proxy_basic_credentials`), delete the `af_services::mutators::load_master_credentials()` fallback block so Basic Auth succeeds if and only if an active `users` row exists with `role == "admin"`, `totp_enabled == 0`, and a matching bcrypt hash (`ESC-09`).
       *   In `proxy_helpers.rs`, keep `is_private_or_loopback_ip` allowing authenticated `100.64.0.0/10` reachability on internal `.aether.local` domains, add `is_unauth_local_lan_ip` permitting only RFC 1918 (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`, `fe80::/10`), and IPv6 ULA (`fc00::/7`) (explicitly excluding `100.64.0.0/10`, `127.0.0.0/8`, and `::1`), and add `unauth_local_lan_enabled()` reading `AF_ALLOW_UNAUTH_LOCAL_LAN` (`1` or case-insensitive `true`; default `false`) (`ESC-10`).
       *   In `subdomain_proxy.rs` (`app_subdomain_proxy_middleware`), require authentication by default on `*.aether.local` for all ten gateway-protected apps (`external_proxy_requires_auth(&app_name)`), bypassing authentication only when `is_internal_aether_local && unauth_local_lan_enabled() && is_unauth_local_lan_ip(client_ip)`; accept the scoped `aetherflow_local_app` cookie alongside `__Host-aetherflow_app` on HTTP `*.aether.local` (`ESC-10`).
       *   In `subdomain_proxy.rs`, when forwarding to `rutorrent` on `127.0.0.1:${APP_PORT}`, read `/etc/aetherflow/rutorrent-proxy-token` (`0640 root:aetherflow`) and inject `X-Aetherflow-Rutorrent-Token` (stripping any client-supplied copy first) alongside `X-Aetherflow-User` (`ESC-14`).
       *   Update `resolve_optional_authenticated_user` (`proxy_helpers.rs`) to validate human sessions through `verify_active_session_on_conn` (`ESC-05`).

6. **`backend-rs/crates/af-api/src/middlewares/host_resolution.rs`, `backend-rs/crates/af-api/src/middlewares/host_validation.rs`, `backend-rs/crates/af-api/src/routes.rs`, `backend-rs/crates/af-api/src/middlewares/rate_limit.rs`, `backend-rs/crates/af-cli/src/provision/steps.rs`** (Modify)
   *   **Type / Scope**: Host Validation, Middleware Ordering, CSP Non-Reflection, Rate Limiting, and Provisioning `ALLOWED_HOSTS` (`ESC-13`)
   *   **Proposed Changes**:
       *   In `host_resolution.rs` (`local_control_plane_host`), trust only canonical loopback IP literals (`127.0.0.0/8`, `::1`) implicitly; require non-loopback IPv4/IPv6 literals to appear in `ALLOWED_HOSTS`, `PUBLIC_URL`, `OIDC_ISSUER`, or `ALLOWED_CORS_ORIGIN`.
       *   In `host_validation.rs`, reject unlisted IP-literal `Host` and `X-Forwarded-Host` headers with `400 INVALID_HOST` (keeping `403 INTERNAL_DOMAIN` for unauthorized internal-domain peers) and insert the validated host string into a typed `Request` extension on accepted requests.
       *   In `routes.rs`, layer `host_validation_middleware` **outside** `security_headers_middleware`. Update `security_headers_middleware` to read the validated host from the `Request` extension (zero SQLite queries on Tokio workers), emit `ws://`/`wss://` only for that validated host (falling back to `'self'` only when absent), and skip SPA CSP headers on non-200 error responses.
       *   In `routes.rs`, attach `auth_rate_limit_middleware` inline via `.route_layer(...)` on `/refresh` inside `auth_routes` (preserving `tests/test_zero_go_cutover.py`'s sub-router parser and executing outside `csrf_middleware`) and on legacy `POST /api/auth/refresh`.
       *   In `middlewares/rate_limit.rs`, reuse `auth/middleware.rs::is_production_or_release_env` so `AF_DISABLE_RATELIMIT` is ignored whenever runtime `AETHERFLOW_ENV` is `production` or `release` (case-insensitive; unset defaults to non-production).
       *   In `af-cli/src/provision/steps.rs`, when provisioning with non-loopback `BIND_ADDR`, include the host's configured LAN/public IP in `ALLOWED_HOSTS`.

7. **`backend-rs/crates/af-runner/src/package_executor/apache_ingress/vhost_render.rs`, `backend-rs/crates/af-runner/src/package_executor/tests/blueprint_and_apache.rs`, `backend-rs/crates/af-api/src/app_launch.rs`** (Modify)
   *   **Type / Scope**: Unified Gateway External Ingress for ruTorrent and Local Launch Cookies (`ESC-10`, `ESC-14`, `ESC-05`)
   *   **Proposed Changes**:
       *   In `vhost_render.rs`, keep `INTERNAL_NETWORKS` aligned with `proxy_helpers.rs` authenticated internal-domain reachability (documenting IPv4 link-local `169.254.0.0/16` parity decision explicitly), remove the `rutorrent` exclusion from the Rust Subdomain Gateway path so external `rutorrent` vhosts emit unquoted lowercase `RequestHeader set x-aetherflow-external-app rutorrent`, and scope `/etc/apache2/AetherFlow/htpasswd` strictly as a legacy fallback for custom Apache `blocks` or non-loopback `BIND_ADDR`. Update `blueprint_and_apache.rs` to assert gateway header forwarding for `rutorrent`.
       *   In `af-api/src/app_launch.rs`, remove the `req.app == "rutorrent"` exclusion in `eligible_destination` (`ESC-14`), mint the scoped `aetherflow_local_app` cookie (`HttpOnly`, `SameSite=Lax`, bound to `<app>.aether.local` + active admin `jti`) for HTTP `*.aether.local` launches (`ESC-10`), and validate active admin sessions in `live_admin` via `verify_active_session_on_conn` (`ESC-05`).

8. **`packages/package/install/installpackage-rutorrent`, `packages/package/remove/removepackage-rutorrent`, `backend-rs/crates/af-runner/src/package_purge.rs`, `backend-rs/crates/af-runner/src/package_lifecycle/runtime_targets.rs`, `backend-rs/crates/af-cli/src/provision/apache_htpasswd.rs`, `backend-rs/crates/af-cli/src/provision/tests.rs`** (Modify)
   *   **Type / Scope**: Local ruTorrent Vhost Hardening, Upgrade Migration, and Provisioning `htpasswd` Safety (`ESC-14`)
   *   **Proposed Changes**:
       *   In `installpackage-rutorrent`:
           *   Generate a 32-byte random hex secret if absent, writing `/etc/aetherflow/rutorrent-proxy-token` (`0640 root:aetherflow`, raw token for `af-api`) and `/etc/aetherflow/rutorrent-proxy-token.conf` (`0640 root:www-data`, Apache `Require expr` matching `X-Aetherflow-Rutorrent-Token`).
           *   On default loopback mode (`AF_APACHE_LISTEN_ALL=0`), render `<VirtualHost 127.0.0.1:${APP_PORT}>` with `Require local`, `Include /etc/aetherflow/rutorrent-proxy-token.conf`, and `SetEnvIf X-Aetherflow-User "^([A-Za-z0-9._-]+)$" REMOTE_USER=$1` (no `AuthType Basic` prompt, no `MASTER_PASS` exit when `rutorrent.htpasswd` is unneeded, and SCGI probe using `MASTER_USER` / configured ruTorrent profile).
           *   On `AF_APACHE_LISTEN_ALL=1`, retain `AuthType Basic` + `AuthUserFile /etc/apache2/AetherFlow/rutorrent.htpasswd` + `Require valid-user`.
           *   On upgrade of existing hosts where `/etc/apache2/sites-available/rutorrent.conf` already exists and still contains legacy loopback Basic Auth (`AF_APACHE_LISTEN_ALL=0`), migrate the managed `<Directory /var/www/rutorrent>` block to the proxy-token + `Require local` + `REMOTE_USER` config so upgraded hosts do not enter a `401` loop.
       *   In `removepackage-rutorrent`, `package_purge.rs`, and `runtime_targets.rs`, register `/etc/aetherflow/rutorrent-proxy-token` and `/etc/aetherflow/rutorrent-proxy-token.conf` for purge/rollback cleanup (matching `librespeed-proxy-token.conf`).
       *   In `apache_htpasswd.rs`, remove `generate_crypto_secret(24)` fallback writes; when no plaintext password is provided via `AETHERFLOW_PASSWORD`, `AETHERFLOW_MASTER_CREDS_SECRET`, or unencrypted legacy credentials, preserve an existing valid file (non-empty `user:$2[aby]$...` bcrypt entries) returning `Ok(Some(path))`, or return `Ok(None)` without overwriting. Add unit tests in `provision/tests.rs` verifying encrypted `enc:v1:` `.master.creds` never writes a random password.

9. **`backend-rs/crates/af-api/src/auth.rs`, `backend-rs/crates/af-api/src/auth/tokens.rs`, `backend-rs/crates/af-api/src/auth/revocation.rs`, `backend-rs/crates/af-api/src/auth/sessions.rs`, `backend-rs/crates/af-api/src/auth/middleware.rs`, `backend-rs/crates/af-api/src/routes/marketplace/catalog.rs`, `backend-rs/crates/af-api/src/ws/tickets.rs`, `backend-rs/crates/af-api/src/oidc/authorize.rs`, `backend-rs/crates/af-api/src/routes/health.rs`** (Modify)
   *   **Type / Scope**: Uniform `active_sessions` Validation, `/refresh` Resurrection Fix, and Safe In-Memory Rotation Grace (`ESC-05`)
   *   **Proposed Changes**:
       *   In `auth/tokens.rs` (re-exported from `auth.rs`), add `verify_active_session_on_conn(conn, user_id, jti, ver, now) -> Result<ActiveHumanSubject, SessionValidationError>` composing `load_active_human_subject` + `af_db::has_unexpired_active_session` + `af_db::token_revocation_status_with_conn` (retiring silent `table_exists("active_sessions")` fallbacks). Define `SessionValidationError::{Suspended, MissingOrRevoked, DbError}` mapped deterministically by callers (`403 ACCOUNT_SUSPENDED` on API routes vs `401` on forward-auth; `401 SESSION_EXPIRED`/`UNAUTHORIZED`; `503` on DB error).
       *   Wire `verify_active_session_on_conn` across `auth/middleware.rs`, `auth/sessions.rs` (`verify_proxy_auth`), `routes/health.rs` (`/metrics` admin session path), `routes/marketplace/catalog.rs` (optional `/api/v1/public/marketplace` — invalid/revoked human session falls back to unauthenticated response), `ws/tickets.rs`, and `oidc/authorize.rs` (alongside `proxy_helpers.rs` and `app_launch.rs` in Items 5 and 7). Non-human credentials (`METRICS_BEARER_TOKEN`, API tokens, OIDC client tokens) bypass human `active_sessions`.
       *   In `auth/sessions.rs` (`refresh_session_with_peer`), fail closed with `401` when `existing_family_opt.is_none()` so deleted `active_sessions` rows cannot be resurrected on refresh.
       *   Retain strict-fingerprint in-memory `ROTATED_TOKEN_GRACE` (`10s`) and `ROTATED_SESSION_SUCCESSOR` in `auth/revocation.rs` / `auth/sessions.rs`, tightening grace acceptance to require an unexpired `active_sessions` row for `leaf_jti` (preserving immediate eviction on logout, single-session revoke, and admin kill while preventing multi-tab session-family destruction).

10. **`backend-rs/crates/af-api/src/middlewares/tests.rs`, `backend-rs/crates/af-api/src/middlewares_security_regressions.rs`, `backend-rs/crates/af-api/src/auth/session_tests.rs`, `backend-rs/crates/af-api/src/auth/middleware_tests.rs`** (Modify)
    *   **Type / Scope**: Track A Security Regression Tests (`ESC-09`, `ESC-10`, `ESC-13`, `ESC-14`, `ESC-05`)
    *   **Proposed Changes**:
        *   Verify `ESC-09`: master-credential Basic Auth fails after admin deletion, demotion, password rotation, or TOTP enrollment.
        *   Verify `ESC-10`: update/invert CGNAT assertions in `middlewares_security_regressions.rs` to distinguish authenticated Tailscale reachability (permitted) from unauthenticated LAN bypass (`100.64.0.1` and `127.0.0.1` rejected even when `AF_ALLOW_UNAUTH_LOCAL_LAN=1`, RFC 1918 requires auth by default and succeeds unauthenticated only with `AF_ALLOW_UNAUTH_LOCAL_LAN=1`); verify TOTP admin launch via `aetherflow_local_app` cookie on HTTP `*.aether.local`.
        *   Verify `ESC-13`: unlisted IPv4/IPv6 `Host`/`X-Forwarded-Host` returns `400 INVALID_HOST` with zero OIDC/CSP reflection, loopback IPs allowed, `/api/v1/auth/refresh` and `/api/auth/refresh` rate-limited, and `AF_DISABLE_RATELIMIT` ignored when `AETHERFLOW_ENV=production|release`.
        *   Verify `ESC-05`: uniform `active_sessions` enforcement across all API, proxy, WS, OIDC, launch-cookie, and optional marketplace surfaces; `/refresh` fails closed on deleted `active_sessions`; concurrent tab refresh stays alive under in-memory grace while explicit logout/revoke immediately rejects both old and new JTIs.

---

#### Track B — Filesystem Confinement, Host Backup/Restore, and FS Browser (`ESC-01`, `ESC-08`, `ESC-06` FS/Version)

11. **`backend-rs/crates/af-files/src/syscall.rs`, `backend-rs/crates/af-files/src/mutation.rs`, `backend-rs/crates/af-files/src/types.rs`, `backend-rs/crates/af-files/src/lib.rs`** (Modify)
    *   **Type / Scope**: Rust Filesystem Mount-Boundary Confinement (`ESC-01`)
    *   **Proposed Changes**:
        *   In `syscall.rs` and `mutation.rs`, reuse `openat2_with_resolve` with `RESOLVE_NO_XDEV` (falling back to `fstatat` `st_dev` comparison on `ENOSYS`) anchored to `self.root_fd` / parent directory FD before entering `user-<id>` so both nested and direct same-FS/cross-FS bind mounts are skipped without descending or unlinking. Ensure `cleanup_staging_tree` and `remove_orphaned_upload_temps_if_only_children` inherit `RESOLVE_NO_XDEV`.
        *   Define `RemoveTreeOutcome { removed_bytes: u64, skipped_mount_paths: Vec<PathBuf> }` (root-relative paths) in `types.rs` and re-export in `lib.rs`. Keep `BrowserFs::remove_tree_with_size*` returning `Result<u64, RemovalError>` (applying the boundary skip internally) and add `remove_tree_with_outcome` / `remove_tree_with_outcome_allowing_symlinks` returning `Result<RemoveTreeOutcome, RemovalError>`.
        *   Add unit tests verifying zero files are unlinked across an injected mount boundary (`EXDEV` / `st_dev` mismatch) and `skipped_mount_paths` contains exact preserved relative paths.

12. **`backend-rs/crates/af-api/src/account_cleanup.rs`, `deploy/systemd/aetherflow-api.service`** (Modify)
    *   **Type / Scope**: Account Deletion Worker and API Systemd Unit (`ESC-01`, `ESC-06`)
    *   **Proposed Changes**:
        *   In `account_cleanup.rs`, switch to `remove_tree_with_outcome*`. When `Ok(RemoveTreeOutcome)` returns non-empty `skipped_mount_paths`, delete the completed `account_storage_cleanup` retry row (no schema migration, no infinite 15-minute retry loop) and emit a structured `WARN` plus `admin_audit_log` entry listing the preserved mount paths. Add a regression test verifying zero pending `account_storage_cleanup` rows remain after a mount-boundary skip.
        *   In `deploy/systemd/aetherflow-api.service`, replace the commented `BindPaths=` example with an explicit warning against bind-mounting shared storage beneath `/var/lib/aetherflow/mcbrowser/user-*`, and remove the retired `EnvironmentFile=-/opt/AetherFlow/current/backend/.env` fallback line.

13. **`backend-rs/crates/af-host/src/restore/policy.rs`, `backend-rs/crates/af-host/src/restore/journal.rs`, `backend-rs/crates/af-host/src/restore/execution.rs`, `backend-rs/crates/af-host/src/tests/staged_restore.rs`, `backend-rs/crates/af-host/src/tests/security_and_provenance.rs`** (Modify)
    *   **Type / Scope**: Canonical `/` Host Restore Allowlist, Secret Mode Clamping, and Ownership (`ESC-08`)
    *   **Proposed Changes**:
        *   In `policy.rs`, add `var/lib/aetherflow/.master.creds` and `var/lib/aetherflow/oidc_rsa.pem` to `resolve_trusted_canonical_host_destination_with_sqlite_override`.
        *   In `journal.rs`, extend `is_secret_credential_entry` to match `.creds` so `.master.creds` receives mandatory `0o600` clamping.
        *   In `execution.rs`, extend `trusted_ancestor_uid` and `aetherflow:aetherflow` ownership (`trusted_sqlite_uid`/`trusted_sqlite_gid`) beyond `BackupTargetKind::SqliteSnapshot` to canonical `/var/lib/aetherflow/{.master.creds,oidc_rsa.pem}` when executing as `root` (skipping `chown` in non-root staging/tests).
        *   Add unit tests in `staged_restore.rs` and `security_and_provenance.rs` verifying a default `af backup create` archive containing `.master.creds` and `oidc_rsa.pem` passes canonical `/` preflight and staged restore with `0600` modes and expected ownership.

14. **`backend-rs/crates/af-cli/src/cli/parse_backup.rs`, `backend-rs/crates/af-cli/src/commands/backup.rs`, `backend-rs/crates/af-cli/src/tests/release_backup_tests.rs`, `backend-rs/crates/af-release/src/runtime.rs`, `backend-rs/crates/af-host/src/backup.rs`** (Modify)
    *   **Type / Scope**: Backup CLI Flags, Contained `AF_DB_PATH` Quiescence, and Dynamic Host Version (`ESC-08`, `ESC-06`)
    *   **Proposed Changes**:
        *   In `parse_backup.rs`, accept `--allow-overwrite` as an alias for `--allow-staging-overwrite` on `af backup restore-preflight`.
        *   In `commands/backup.rs`, reuse existing `is_system_scoped_backup_path` and `resolve_contained_sqlite_restore_override` in **both** `RestoreDestructive` and `RecoverInterrupted` so live quiescence runs only when `resolved_target` is `/` or contains the live `AF_DB_PATH`, and isolated staging targets use `NoopQuiescenceController`.
        *   Reuse `af-release::runtime::runtime_identity()` across all five hardcoded `"v4.0.0"`/`"4.0.0"` sites (`commands/backup.rs`, `parse_backup.rs`, `af-host/src/backup.rs`, `af-host/src/restore/policy.rs`, `af-host/src/restore/journal.rs`), respecting `--root`, validating semver with `af_host::parse_semver_triplet`, and falling back to `concat!("v", env!("CARGO_PKG_VERSION"))` for non-semver stamps.
        *   Add regression tests in `release_backup_tests.rs` verifying `--allow-overwrite`, staging `NoopQuiescenceController` vs custom `AF_DB_PATH` quiescence in both `RestoreDestructive` and `RecoverInterrupted`, and dynamic host version resolution.

15. **`backend-rs/crates/af-api/src/routes/fs_browser.rs`, `backend-rs/crates/af-api/src/routes/tests/security_and_account.rs`** (Modify)
    *   **Type / Scope**: FS Browser Default Roots (`ESC-06`)
    *   **Proposed Changes**: Remove `env::temp_dir()` from the default allowed roots when `AF_ALLOWED_FS_ROOTS` is unset (retaining `/mnt`, `/media`, `/srv`, `/data`, `/home`, and non-service `env::current_dir()`), and add a regression test in `security_and_account.rs` verifying `/tmp` is rejected by `/api/v1/auth/fs` when `AF_ALLOWED_FS_ROOTS` is unset.

---

#### Track C — Privileged Runner, Release Engine, Plugin Isolation, and Package Tooling (`ESC-07`, `ESC-11`, `ESC-02`, `ESC-03`, `ESC-12`, `ESC-06` Units/Shell)

16. **`backend-rs/crates/af-runner/src/plugins.rs`, `backend-rs/crates/af-runner/src/plugins/isolation.rs`, `backend-rs/crates/af-runner/src/plugins/tests.rs`** (Modify)
    *   **Type / Scope**: Managed Plugin Cgroup v2 Preflight and Systemd Network Hardening (`ESC-07`)
    *   **Proposed Changes**:
        *   In `plugins.rs` (`ensure_systemd_isolation_ready`), probe cgroup v2 (`/sys/fs/cgroup/cgroup.controllers`) and systemd version `>= 249`, returning `PluginRunnerError::IsolationUnavailable` (`503 PLUGIN_ISOLATION_UNAVAILABLE`) on unsupported hosts while preserving the `using_custom_systemd_run_override()` unit-test bypass.
        *   In `plugins/isolation.rs` (`push_common_isolation_properties`), append `--property=SocketBindDeny=any`, `--property=SocketBindAllow=ipv4:tcp:{port}`, `--property=IPAddressDeny=any`, and `--property=IPAddressAllow=localhost`.
        *   In `plugins/tests.rs`, verify the exact `systemd-run` argument list includes all four network properties for the plugin's allocated port and test cgroup v2 preflight failure handling.

17. **`backend-rs/crates/af-api/src/routes/health.rs`, `backend-rs/crates/af-api/src/routes/tests/security_and_account.rs`** (Modify)
    *   **Type / Scope**: Authenticated `/metrics` Endpoint (`ESC-07`)
    *   **Proposed Changes**:
        *   Remove the unauthenticated loopback shortcut in `routes/health.rs` (`is_metrics_request_authorized`) so `/metrics` requires `Authorization: Bearer <METRICS_BEARER_TOKEN>` or an active admin session even from `127.0.0.1` / `::1`, preserving live `METRICS_PUBLIC=1` as explicit opt-in only.
        *   Update `security_and_account.rs` to verify loopback `/metrics` returns `401` without credentials, `200` with `METRICS_BEARER_TOKEN` or active admin session, and `200` only when `METRICS_PUBLIC=1`.

18. **`backend-rs/crates/af-release/src/health.rs`, `backend-rs/crates/af-release/src/config.rs`, `backend-rs/crates/af-release/src/artifact.rs`, `backend-rs/crates/af-release/src/artifact/provider.rs`, `backend-rs/crates/af-release/src/tests/config_artifact_tests.rs`, `deploy/release-manager.sh`, `deploy/systemd/aetherflow-runner.service`** (Modify)
    *   **Type / Scope**: Release Rollback Resilience, Unified `aetherflow.env` Secret/Config Loading, and Runner Unit Cleanup (`ESC-11`, `ESC-02`, `ESC-06`)
    *   **Proposed Changes**:
        *   In `af-release/src/health.rs` (`restart_systemd_units`) and `deploy/release-manager.sh` (Stage 3/4 parity), restart `aetherflow-runner.service` and `aetherflow-api.service` before running `/var/log/aetherflow` directory ownership setup, `aetherflow-log-retention.timer` enablement, and `aetherflow-log-retention.service` start; run all three log-retention steps best-effort (`required = false`), updating `run_systemctl(..., false)` to log a structured warning via `append_jsonl_log(&config.log_file, "WARN", ...)` instead of returning `Ok(())` silently.
        *   In `af-release/src/config.rs`, unify loading from `cfg.env_file` (`/etc/aetherflow/aetherflow.env`, `0600`) with exact precedence: `process env > explicit --config assignment > /etc/aetherflow/aetherflow.env (unless AETHERFLOW_SKIP_ENV_FILES=1) > default-fallback --config line (is_default_fallback = true) > compiled default`. Resolve `HEALTH_ENDPOINT`, GitHub tokens (`AF_GITHUB_TOKEN` / `GITHUB_TOKEN` / `GH_TOKEN`, stored in a redacted non-`Debug`/non-`Serialize` field passed explicitly to `artifact/provider.rs`), and root-only `AETHERFLOW_SKIP_PROVENANCE_VERIFY` (`artifact.rs`); mirror in `deploy/release-manager.sh` without writing secrets into `<jobs_dir>/<unit>.conf` or staging world-readable copies.
        *   In `deploy/release-manager.sh`, clamp Python `os.fchmod` receipt creation from `0o644` to `0o600` (while preserving its Stage 0 v3→v4 `backend/.env` secret migration).
        *   In `deploy/systemd/aetherflow-runner.service`, remove the retired `EnvironmentFile=-/opt/AetherFlow/current/backend/.env` fallback.
        *   In `config_artifact_tests.rs`, add regression tests verifying Stage 4 rollback completes when `aetherflow-log-retention.service` fails (emitting a structured `WARN`), verifying `HEALTH_ENDPOINT` and GitHub token precedence across `release-manager.conf` (`is_default_fallback = true`) and `aetherflow.env`, and verifying tokens are redacted from `Debug`/`Serialize`.

19. **`backend-rs/crates/af-runner/src/lib.rs`, `backend-rs/crates/af-runner/src/self_update.rs`, `backend-rs/crates/af-runner/src/job_receipts.rs`, `backend-rs/crates/af-runner/src/core_restart_worker.sh`, `backend-rs/crates/af-runner/src/tests.rs`** (Modify)
    *   **Type / Scope**: Self-Update Immutable Binary Resolution and `0600` Receipt Modes (`ESC-02`)
    *   **Proposed Changes**:
        *   In `af-runner/src/lib.rs`, reorder `resolve_af_cli_binary`, `package_script_roots`, `resolve_release_manager_script`, and `resolve_sandbox_script_path` to check `env::current_exe().parent()` before mutable `/opt/AetherFlow/current` and `/usr/local/bin/af` (preserving explicit `AETHERFLOW_CLI_BIN` override first).
        *   In `self_update.rs`, verify no secret tokens or `AETHERFLOW_SKIP_PROVENANCE_VERIFY` are written to `systemd-run --setenv` or `<jobs_dir>/<unit>.conf` (the launched `af release deploy --local` process reads them directly from root-owned `/etc/aetherflow/aetherflow.env` via Item 18).
        *   In `job_receipts.rs` and standalone `core_restart_worker.sh` (Python `os.fchmod`), clamp `.self-update-jobs/*.json` receipt modes from `0o644` to `0o600`.
        *   Add regression tests in `af-runner/src/tests.rs` verifying `current_exe().parent()` precedence across all four resolvers and `0600` receipt permissions.

20. **`backend-rs/crates/af-runner/src/package_executor/model.rs`, `backend-rs/crates/af-runner/src/package_executor/validation.rs`, `backend-rs/crates/af-runner/src/package_executor/declarative_recipes/catalog.rs`, `backend-rs/crates/af-runner/src/package_executor/declarative_recipes/steps_files_services.rs`, `backend-rs/crates/af-runner/src/package_executor/declarative_recipes/steps_system.rs`, `backend-rs/crates/af-runner/src/package_executor/tests/recipes_and_security.rs`, `backend-rs/crates/af-runner/src/package_executor/tests/rclone_and_readiness.rs`** (Modify)
    *   **Type / Scope**: Remove Dead `DeclarativeStep::RunCommand` and Migrate `rclone` Unmount (`ESC-03`)
    *   **Proposed Changes**:
        *   In `model.rs`, extend `DeclarativeStep::UnmountPaths` with exact fields `{ paths: Vec<String>, only_if_delete_data: bool }` and delete the `DeclarativeStep::RunCommand` enum variant completely.
        *   In `steps_files_services.rs`, gate `UnmountPaths` execution on `only_if_delete_data` while preserving its existing fail-closed non-lazy shell-free unmount sequence (`is_active_mountpoint` → `fusermount -u` → `umount` without `-l` → re-check).
        *   In `catalog.rs`, migrate `build_rclone_recipe` from `/bin/sh -c` `RunCommand` to `DeclarativeStep::UnmountPaths { paths: vec!["/mnt/remote".into()], only_if_delete_data: true }` and update `build_mergerfs_recipe`'s existing `UnmountPaths` with `only_if_delete_data: false`.
        *   Remove dead `RunCommand` arms from `validation.rs` and `steps_system.rs`; update `recipes_and_security.rs` and `rclone_and_readiness.rs` to verify shell-free `rclone` unmount and `only_if_delete_data` gating.

21. **`packages/lib/versions_apt.sh`, `packages/lib/config_database.sh`, `packages/package/remove/removepackage-palate`, `docs/installpackage-template.sh`, `tests/test_apt_exact_versions.py`, `tests/test_marketplace_ports_removers_hardening.py`** (Modify)
    *   **Type / Scope**: Shell APT Lock Timeout, Post-Activation Backup Pruning, and Template Hygiene (`ESC-12`, `ESC-06`)
    *   **Proposed Changes**:
        *   In `packages/lib/versions_apt.sh`, add one shared digits-only `DPKG_LOCK_TIMEOUT` helper (defaulting to `120` when unset or non-numeric) injecting `-o DPkg::Lock::Timeout=<N>` unless already present, used by **both** the `apt-get()` wrapper and `rollback_apt_packages()` (`ESC-12`).
        *   In `packages/lib/config_database.sh` (`finish_app_archive_update`, invoked post-activation from `write_lock`), prune old `${destination}.af-backup.*` directories keeping the newest 2 backups (matching `retain_successful_app_backups`), validating `.af-archive-owner` and skipping `.af-archive-pending` and symlinks; apply the same retention helper to `replace_app_tree` backups.
        *   In `packages/package/remove/removepackage-palate`, emit the backup-retention note only when `DELETE_DATA != true` and emit purge confirmation when `DELETE_DATA=true`.
        *   Update `docs/installpackage-template.sh` to use `af-<app_id>.service`, `validate_config_paths`, `write_config_file`, `af_github_curl`, and `127.0.0.1` loopback binding, passing `tests/check_shell_hygiene.py`.
        *   Add regression tests in `tests/test_apt_exact_versions.py` (verifying `DPkg::Lock::Timeout` injection in both `apt-get()` and `rollback_apt_packages()`, including non-numeric fallback) and `tests/test_marketplace_ports_removers_hardening.py` (verifying post-activation `.af-backup.*` retention-of-2 pruning and `removepackage-palate` conditional output).

---

#### Track D — FlowAI Guardrails and Contract Test Integrity (`ESC-04`, `ESC-06` E2E/Streaming)

22. **`backend-rs/crates/af-api/src/intelligence/flowai.rs`, `backend-rs/crates/af-api/src/intelligence/ai_providers.rs`, `backend-rs/crates/af-api/src/routes/settings.rs`, `backend-rs/crates/af-api/src/intelligence/audit_tests.rs`, `backend-rs/crates/af-api/src/intelligence/flowai_tests.rs`** (Modify)
    *   **Type / Scope**: FlowAI Port Default, Self-Target Guard, and Outbound Cloud-Credential RBAC (`ESC-04`)
    *   **Proposed Changes**:
        *   Define one shared `DEFAULT_ANTHROPIC_LOCAL_ENDPOINT = "http://127.0.0.1:8081"` constant replacing all four `"http://localhost:8080"` defaults across `flowai.rs` and `ai_providers.rs`.
        *   Enforce a structural outbound invariant inside `run_chat_session`: local providers (`ollama`, `lm-studio`, `anthropic-local` / `localai`) never attach paid cloud API keys (`ps.anthropic_api_key`, etc.) and never default to `https://api.anthropic.com`; any dispatch using a paid cloud API key or cloud endpoint (`openai`, `anthropic`, `gemini`, including `"anthropic"` unless configured to a local endpoint without a cloud key) requires `user.role == "admin"` unless `AF_AI_ALLOW_USER_CLOUD_PROVIDERS` is `1` or case-insensitive `true` (default `false`), returning `403 AI_PROVIDER_ADMIN_ONLY`.
        *   Enforce the self-target guard returning `400 AI_SELF_TARGET_REJECTED` in `routes/settings.rs` (save-time validation), `test_ai_connection`, and outbound local dispatch, checking syntactic and canonical loopback/unspecified/configured `BIND_ADDR` hosts (`localhost`, `127.0.0.0/8`, `::1`, `::ffff:127.0.0.0/104`, `0.0.0.0`, `[::]`, `BIND_ADDR`) plus implicit scheme ports (`80`/`443`) against `aetherflow-api`'s configured `PORT` (default `8080`).
        *   Add regression tests in `audit_tests.rs` (covering `anthropic-local` cloud-key isolation, `403 AI_PROVIDER_ADMIN_ONLY`, `AF_AI_ALLOW_USER_CLOUD_PROVIDERS` case-insensitive parsing, and `400 AI_SELF_TARGET_REJECTED` at save, probe, and chat) and update `flowai_tests.rs` where `run_chat_session` non-admin tests previously invoked `"openai"`.

23. **`tests/e2e/tier1_features/test_f32_to_f37_system_pipeline.py`, `tests/e2e/tier2_boundaries/test_boundaries_api.py`, `tests/e2e/tier2_boundaries/test_boundaries_backend_core.py`, `tests/e2e/tier2_boundaries/test_boundaries_components.py`, `tests/e2e/tier2_boundaries/test_boundaries_debian.py`, `tests/e2e/tier2_boundaries/test_boundaries_obsidian.py`, `tests/e2e/tier2_boundaries/test_boundaries_operator_panels.py`, `tests/e2e/tier2_boundaries/test_boundaries_pipeline.py`, `tests/e2e/framework.py`, `tests/e2e/runner.py`, `scripts/run_embedded_e2e.sh`, `tests/test_v4_release_bootstrap_ci.py`** (Modify)
    *   **Type / Scope**: Python E2E Contract Suite Integrity and Dead `--socket` Removal (`ESC-06`)
    *   **Proposed Changes**:
        *   Remove dead `RunnerSocketClient` from `tests/e2e/framework.py` and unused `--socket` (`self.socket_path`) from `tests/e2e/runner.py`, `scripts/run_embedded_e2e.sh`, and `tests/test_v4_release_bootstrap_ci.py`.
        *   Replace all 25 `self.assert_true(True, ...)` placeholders with concrete declarative/AST/source/test-anchor assertions per the table below (preserving the 3 existing `--mode live` checks in `test_boundaries_api.py`):

| # | Test ID | File | Required `--mode contract` Assertion (and Live Behavior) |
| :-: | :--- | :--- | :--- |
| 1 | `T1_F36_01` | `test_f32_to_f37_system_pipeline.py` | Discover all Tier 1 `F01`–`F37` test classes via AST/registry and assert 100% feature-ID coverage (`37/37`). |
| 2 | `T1_F37_04` | `test_f32_to_f37_system_pipeline.py` | Parse all `tests/e2e/**/*.py` ASTs and assert `0` `self.assert_true(True, ...)` calls remain. |
| 3 | `T1_F37_05` | `test_f32_to_f37_system_pipeline.py` | Verify `tests/e2e/runner.py` accepts `--mode contract` and `--mode live` and exports deterministic exit-code handling without daemon dependency. |
| 4 | `T2_B01_02` | `test_boundaries_api.py` | Preserve `--mode live` HTTP null-byte check; in `--mode contract`, assert `af-api/src/routes/fs_browser.rs` rejects `'\0'` and `af-files` rejects null bytes. |
| 5 | `T2_B02_02` | `test_boundaries_api.py` | Preserve `--mode live` `401` check; in `--mode contract`, assert `auth/sessions.rs` rejects missing session cookie on refresh and `auth/session_tests.rs` tests it. |
| 6 | `T2_B02_05` | `test_boundaries_api.py` | Preserve `--mode live` malformed-cookie `401` check; in `--mode contract`, assert `auth/tokens.rs` JWT decode + `auth/middleware_tests.rs` malformed-token test anchor exist. |
| 7 | `T2_B03_04` | `test_boundaries_api.py` | Assert password-update route/handler in `af-api/src/routes/` validates current password and hashes idempotently via bcrypt without clearing session/user state. |
| 8 | `T2_B06_05` | `test_boundaries_api.py` | Assert topology builder in `af-api` validates link source/target node IDs against emitted node set (or references its Rust unit test anchor). |
| 9 | `T2_B12_02` | `test_boundaries_backend_core.py` | Assert `backend-rs/crates/af-api` test helpers serialize/isolate DB & env mutations (e.g., `Mutex` / temp-dir SQLite DBs) with zero unsynchronized shared SQLite paths. |
| 10 | `T2_B19_05` | `test_boundaries_components.py` | Assert `frontend-rs` sparkline component clamps values with `.clamp(` / `.min(` / `.max(` and guards zero/non-finite denominator scaling. |
| 11 | `T2_B22_05` | `test_boundaries_components.py` | Assert `frontend-rs` profile/user rendering components contain zero `inner_html` bindings for usernames (relying on Leptos escaped text nodes). |
| 12 | `T2_B30_05` | `test_boundaries_debian.py` | Assert `setup/AetherFlow-Setup` optional utility installs guard non-fatal failures (`|| true` / warning handler) without aborting bootstrap. |
| 13 | `T2_B31_01` | `test_boundaries_debian.py` | Assert installer/bootstrap scripts create `/usr/share/keyrings` with mode `0755` (`install -d -m 0755` / `chmod 0755`). |
| 14 | `T2_B31_02` | `test_boundaries_debian.py` | Assert `.gpg` keyring files written by installers/bootstrap are set to `0644` (`chmod 0644` / `chmod a+r`). |
| 15 | `T2_B13_05` | `test_boundaries_obsidian.py` | Assert `frontend-rs` CSS contains `@media print` rules disabling background radial gradients / animations. |
| 16 | `T2_B16_05` | `test_boundaries_obsidian.py` | Assert `frontend-rs` CSS defines horizontal scroll containers (`overflow-x: auto`) with smooth touch scrolling (`-webkit-overflow-scrolling: touch` or `scroll-behavior: smooth`). |
| 17 | `T2_B17_02` | `test_boundaries_obsidian.py` | Assert `frontend-rs` aurora opacity controls clamp/blend layer opacity without reducing foreground text contrast tokens. |
| 18 | `T2_B17_04` | `test_boundaries_obsidian.py` | Assert `frontend-rs` grain/animation toggle logic uses reactive Leptos signals / CSS classes without registering leaked raw `window` intervals/listeners. |
| 19 | `T2_B17_05` | `test_boundaries_obsidian.py` | Assert `frontend-rs` appearance settings implement a reset handler restoring default Obsidian V2 theme/opacity/grain tokens. |
| 20 | `T2_B25_05` | `test_boundaries_operator_panels.py` | Assert rule-creation route/handler in `af-api` handles duplicate rule names cleanly (`409` / `UNIQUE` / duplicate check) with a Rust test anchor. |
| 21 | `T2_B32_05` | `test_boundaries_pipeline.py` | Assert `backend-rs/Cargo.toml` `[profile.release]` enables size/optimization settings (`lto` / `strip` / `codegen-units`) and if `target/release/aetherflow-api` exists, its size is `< 150 MB`. |
| 22 | `T2_B34_05` | `test_boundaries_pipeline.py` | Assert `deploy/systemd/aetherflow-api.service` and `aetherflow-runner.service` configure systemd confinement directives (`NoNewPrivileges`, `ProtectSystem`, `PrivateTmp`, `TasksMax` / cgroup controls). |
| 23 | `T2_B35_05` | `test_boundaries_pipeline.py` | Execute `bash -n` via `subprocess.run` on `setup/AetherFlow-Setup`, `deploy/release-manager.sh`, `packages/common.sh`, and `packages/lib/*.sh`, asserting exit code `0`. |
| 24 | `T2_B36_04` | `test_boundaries_pipeline.py` | Inspect `tests/e2e/**/*.py` ASTs confirming every `TestCase` subclass implements isolated `run()` without mutating class-level mutable globals across tests. |
| 25 | `T2_B37_01` | `test_boundaries_pipeline.py` | Assert `af-api` enforces `DefaultBodyLimit` / payload size caps (`<= 10 MB` or explicit route limit) and JSON/UTF-8 rejection tests exist in `backend-rs/crates/af-api`. |

24. **`frontend-rs/crates/af-web-app/src/tabs/streaming/types.rs`, `frontend-rs/crates/af-web-app/src/tabs/streaming/history.rs`, `frontend-rs/crates/af-web-app/src/tabs/streaming/portability.rs`, `scripts/validate-streaming.sh`** (Modify)
    *   **Type / Scope**: Frontend Streaming Contract Fixture Parity (`ESC-06`)
    *   **Proposed Changes**:
        *   In `scripts/validate-streaming.sh`, verify `[[ -s ... ]]` for all three `AF_STREAMING_CONTRACT_FIXTURE`, `AF_STREAMING_ARCHIVE_FIXTURE`, and `AF_STREAMING_PORTABILITY_FIXTURE` files, and unset/re-export all three variables cleanly in `--integrated` mode.
        *   In `frontend-rs`, map each fixture fail-closed (when the env var is set, missing/unreadable/malformed JSON must panic/fail the test; inline JSON fallback is used only when the env var is unset):
            *   `AF_STREAMING_CONTRACT_FIXTURE` → `types.rs` (`Dashboard` / contract payload tests).
            *   `AF_STREAMING_ARCHIVE_FIXTURE` → new JSON deserialization test in `history.rs` parsing the backend wrapper object `{"administrative": HistoryPage, "linked": HistoryPage}`.
            *   `AF_STREAMING_PORTABILITY_FIXTURE` → `portability.rs` (`PortableArchive` / `ArchivePreview` tests).

---

#### Continuous Documentation Synchronization (Applied Inside Each Phase / Track)

25. **Living Documentation Files (27 files synchronized by executing track)** (Modify)
    *   **Type / Scope**: Documentation Parity (`tests/test_zero_go_cutover.py`, `tests/test_v4_release_bootstrap_ci.py`, `tests/test_listenarr_release_policy.py`, `tests/test_ci.py`)
    *   **Proposed Changes**: Update each living documentation file in the same PR that changes its corresponding code behavior, preserving all automated doc-contract unittest anchors (including the pinned `"2026-11-03"` anchor in `docs/deployment_checklist.md` verified by `tests/test_v4_release_bootstrap_ci.py` unless intentionally updated alongside the test):

| Phase / Track | Living Documentation Files Updated in That PR |
| :--- | :--- |
| **Phase 0** | `docs/testing.md` (if CI fixture/umask notes need update) |
| **Track A (`ESC-09`, `ESC-10`, `ESC-13`, `ESC-14`, `ESC-05`)** | `docs/security.md`, `docs/threat_model.md`, `SECURITY.md`, `docs/architecture.md`, `docs/API.md`, `docs/configuration.md`, `docs/deployment_checklist.md`, `docs/RUNBOOK.md`, `docs/upgrading.md`, `docs/troubleshooting.md`, `README.md` |
| **Track B (`ESC-01`, `ESC-08`, `ESC-06` FS/Version)** | `docs/mcbrowser.md`, `docs/rust-host-management.md`, `docs/rust-admin-cli.md`, `docs/security.md`, `docs/RUNBOOK.md`, `docs/configuration.md` |
| **Track C (`ESC-07`, `ESC-11`, `ESC-02`, `ESC-03`, `ESC-12`, `ESC-06` Shell/Units)** | `docs/rust-release-engine.md`, `docs/self-update.md`, `docs/rust-package-executor.md`, `docs/marketplace.md`, `docs/marketplace-developer-guide.md`, `docs/v4-native-packages.md`, `plugins/README.md`, `plugins/sdk-template-rust/README.md`, `docs/security.md`, `docs/RUNBOOK.md`, `docs/deployment_checklist.md` |
| **Track D (`ESC-04`, `ESC-06` E2E/Streaming)** | `docs/flowai.md`, `docs/streaming-validation.md`, `docs/testing.md`, `tests/TEST_INFRA.md`, `tests/TEST_READY.md`, `docs/configuration.md` |

### Verification Plan

#### Per-Phase / Per-Track Exit Gates

| Gate Scope | Required Verification Commands and Acceptance Criteria |
| :--- | :--- |
| **Phase 0 Exit** | `cargo deny --manifest-path backend-rs/Cargo.toml --locked check advisories`; `cargo deny --manifest-path frontend-rs/Cargo.toml --locked check advisories`; `cargo deny --manifest-path plugins/sdk-template-rust/backend/Cargo.toml --config backend-rs/deny.toml --locked check advisories`; `cargo audit` across all 3 lockfiles (`0` `RUSTSEC-2026-0592` findings); `gitleaks git . --config .gitleaks.toml` (`0` findings); `AETHERFLOW_SKIP_ENV_FILES=1 python3 tests/run_parallel_tests.py` (`0` failures); passing `CI`, `Security Gate`, and `Production Release Pipeline` on `origin/nightly`. |
| **Track A Exit** | Full Rust build/clippy/test on `backend-rs` (all `ESC-09`, `ESC-10`, `ESC-13`, `ESC-14`, `ESC-05` regression tests passing); `AETHERFLOW_SKIP_ENV_FILES=1 python3 tests/run_parallel_tests.py`; `python3 tests/check_shell_hygiene.py` (`192/192 or greater, 0 failures`); doc-contract unittests (`58/58 or greater, 0 failures`); `$egm-drift-report` delta check on Track A docs; passing GitHub Actions workflows. |
| **Track B Exit** | Full Rust build/clippy/test on `backend-rs` (`af-files`, `af-api`, `af-host`, `af-cli`, `af-release`); doc-contract unittests (`58/58 or greater, 0 failures`); `$egm-drift-report` delta check on Track B docs; passing GitHub Actions workflows. |
| **Track C Exit** | Full Rust build/clippy/test on `backend-rs` and `plugins/sdk-template-rust/backend`; `AETHERFLOW_SKIP_ENV_FILES=1 python3 tests/run_parallel_tests.py` (including `test_apt_exact_versions.py` and backup pruning); `python3 tests/check_shell_hygiene.py` (`192/192 or greater, 0 failures`); doc-contract unittests (`58/58 or greater, 0 failures`); `$egm-drift-report` delta check on Track C docs; passing GitHub Actions workflows. |
| **Track D Exit (Final Program Exit)** | All compilation, clippy, unit, advisory, shell-hygiene, and doc-contract gates above PLUS: `python3 tests/run_e2e.py --mode contract` (`387/387` passed, `0` `assert_true(True)` across `tests/e2e/`); `bash scripts/validate-streaming.sh` (all three `AF_STREAMING_*_FIXTURE` files consumed fail-closed); release build + staged WASM + Playwright browser suite; `$egm-drift-report` confirming zero unresolved drift across all 43 living documentation files; passing `CI`, `Security Gate`, and `Production Release Pipeline` on `origin/nightly`. |

#### Exact Verification Commands

*   **Compilation and Build**:
    *   `cargo build --manifest-path backend-rs/Cargo.toml --workspace --release --locked`
    *   `cargo build --manifest-path frontend-rs/Cargo.toml --workspace --locked`
    *   `cargo build --manifest-path plugins/sdk-template-rust/backend/Cargo.toml --locked`
    *   `scripts/build_wasm_frontend.sh --stage`
*   **Unit and Integration Tests**:
    *   `cargo test --manifest-path backend-rs/Cargo.toml --workspace --locked -- --test-threads=1`
    *   `cargo test --manifest-path frontend-rs/Cargo.toml --workspace --locked`
    *   `cargo test --manifest-path plugins/sdk-template-rust/backend/Cargo.toml --locked`
    *   `AETHERFLOW_SKIP_ENV_FILES=1 python3 tests/run_parallel_tests.py`
*   **Static Analysis, Linting, and Security Gates**:
    *   `cargo clippy --manifest-path backend-rs/Cargo.toml --workspace --all-targets --locked -- -D warnings`
    *   `cargo clippy --manifest-path frontend-rs/Cargo.toml --workspace --all-targets --locked -- -D warnings`
    *   `cargo clippy --manifest-path plugins/sdk-template-rust/backend/Cargo.toml --all-targets --locked -- -D warnings`
    *   `cargo deny --manifest-path backend-rs/Cargo.toml --locked check advisories`
    *   `cargo deny --manifest-path frontend-rs/Cargo.toml --locked check advisories`
    *   `cargo deny --manifest-path plugins/sdk-template-rust/backend/Cargo.toml --config backend-rs/deny.toml --locked check advisories`
    *   `cargo audit --file backend-rs/Cargo.lock && cargo audit --file frontend-rs/Cargo.lock && cargo audit --file plugins/sdk-template-rust/backend/Cargo.lock`
    *   `gitleaks git . --config .gitleaks.toml` (`0` findings)
    *   `python3 tests/check_shell_hygiene.py` (`192/192` or greater, `0` failures)
*   **E2E, Streaming, and Documentation Verification (Track D / Final Exit)**:
    *   `python3 tests/run_e2e.py --mode contract` (`387/387` passed, `0` `assert_true(True)` occurrences across `tests/e2e/`)
    *   `bash scripts/validate-streaming.sh` (verifying `frontend-rs` consumes all three `AF_STREAMING_*_FIXTURE` files fail-closed)
    *   `E2E_PLAYWRIGHT_SPECS="tests/e2e" scripts/run_embedded_e2e.sh --playwright` (full embedded Rust API + staged WASM Playwright suite across all specs)
    *   `$egm-drift-report` delta audit confirming zero unresolved drift across all 43 living documentation files and `58/58` or greater passing doc-contract `unittest`s (`test_zero_go_cutover.py`, `test_v4_release_bootstrap_ci.py`, `test_listenarr_release_policy.py`, `test_ci.py`)
*   **GitHub Actions Gate (Phase 0 Exit & Every Track)**:
    *   All jobs passing in `CI`, `Security Gate`, and `Production Release Pipeline` (including `amd64`/`arm64` tarball verification and Sigstore attestation) on `origin/nightly`.

---

<!-- Provenance: Indicates initial structural drafting and post-review resolution via EGM. -->

*Drafted with EGM*
