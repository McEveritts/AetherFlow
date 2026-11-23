# AetherFlow Threat Model

## 1. Overview

This document maps CWEs and privilege boundaries across the **AetherFlow v4.0.0** architecture:

- **Control Plane (`af-api`)**: Unprivileged Rust (`Axum` + `Tokio`) HTTP/WebSocket server serving the external **Leptos Rust WebAssembly (`frontend-rs`)** SPA from `web/dist` (`STATIC_DIR`), running as `User=aetherflow` under `ProtectSystem=strict`, `ProtectHome=read-only`, and `NoNewPrivileges=yes`.
- **Privileged Runner (`af-runner`)**: Root daemon listening exclusively on `/run/aetherflow/runner.sock` (`0660 root:aetherflow`).
- **Scoped File Manager (`af-files` & `af-api::mcbrowser`)**: Native McBrowser tenant storage under `/var/lib/aetherflow/mcbrowser` (`0700`).
- **Persistence (`af-db` & `af-host`)**: Bundled SQLite (`rusqlite`) in single-writer `WAL` mode with AES-256-GCM (`enc:v1:`) secret encryption and manifest-verified online backups.

---

## 2. CWE Mapping & Mitigations

### CWE-284 / CWE-285: Improper Access Control & Authorization

| Component | Threat | Mitigation |
| :--- | :--- | :--- |
| Route hierarchy (`af-api`) | Unauthenticated or cross-role access | Three-tier API router (`/api/v1/public`, `/api/v1/auth` with JWT + revocation checks, `/api/v1/admin` with live DB `role == "admin"` verification), plus top-level `/plugins/:id/{ui,proxy}`, legacy `/api/*` compatibility aliases, `/health*`, and `/metrics`. `POST /api/v1/auth/ai/support` enforces live admin RBAC (`403` for non-admins); non-admins can call `/api/v1/auth/ai/chat` without a per-user spend cap. On empty-DB hosts, `POST /api/v1/public/auth/setup` requires `/var/lib/aetherflow/.setup-bootstrap-token` (or `AETHERFLOW_SETUP_TOKEN`) on proxied/non-loopback calls (`403 SETUP_TOKEN_REQUIRED`), while direct unproxied loopback (`127.0.0.1:8080`) requests bypass the token until the first admin is created. |
| Plugin token RBAC & proxy (`af-api`) | Plugin token used outside authorized routes or for recursive proxy calls | `auth_middleware` (`plugin_claims_allow_request`) enforces segment-boundary `api_scopes` against manifest permissions and default-denied prefixes on plugin-to-API calls; the plugin reverse proxy (`backend-rs/crates/af-api/src/plugins/proxy.rs`) unconditionally rejects plugin tokens (`403 PLUGIN_PROXY_FORBIDDEN`) to block recursive proxying. |
| Host filesystem picker (`/api/v1/auth/fs`) | Non-admin user enumerating host directories | Restricted strictly to live-verified active `admin` accounts before any path canonicalization or existence checks; ordinary users are confined to McBrowser (`af-files`). |
| Cluster ingress (`af-services` / `af-api`) | Unauthorized cluster scraping, spoofing, or worker control | `/cluster/v1/{register,heartbeat,commands,commands/ack,metrics}` and HTTP/2 gRPC `cluster.ClusterService` (default `127.0.0.1:50051`) separate control-plane and worker auth: `GET /cluster/v1/metrics` and `/cluster/v1/commands` enforce `authorize_cluster_control_plane` (master `CLUSTER_PSK` or non-worker admin mTLS client certificate, rejecting worker certs and per-worker PSKs), while worker `register`/`heartbeat`/`commands/ack` validate per-node PSK or pinned worker mTLS certificates and `node_id`/payload bounds. **Loopback caveat**: opt-in `CLUSTER_ALLOW_INSECURE_LOOPBACK=true` disables TLS/mTLS on loopback and enables an unframed raw JSON-RPC handler (`register`/`heartbeat`), expanding loopback attack surface alongside shared-network-namespace processes such as managed plugins. |
| Subdomain Gateway Basic Auth, Apache `htpasswd` & `.aether.local` (`af-api` / `af-runner`) | Offboarded admin retaining Basic Auth access, or LAN/Tailscale/CGNAT peers reaching McVNC & protected apps unauthenticated | External `<app>.<baseDomain>` requests enforce admin sessions or rate-limited Basic Auth (blocking TOTP-enrolled live `users` rows). **Three residual boundaries**: (1) `verify_proxy_basic_credentials` checks `load_master_credentials()` (falling back across `/var/lib/aetherflow/.master.creds`, legacy `/opt/AetherFlow/backend/data/.master.creds`, `/install/.aetherflow.conf`, and SQLite `system_config.master_credentials`) *before* checking `users.role == "admin"`, so deleting, demoting, or rotating the initial admin password does not revoke Basic Auth via the provisioning secret (and deleting the matching `users` row bypasses TOTP); (2) static Apache Basic Auth files (`/etc/apache2/AetherFlow/htpasswd` for managed external non-gateway vhosts including ruTorrent, and `/etc/apache2/AetherFlow/rutorrent.htpasswd` for ruTorrent's local vhost) do not auto-revoke on account changes or TOTP enrollment; (3) `Host: <app>.aether.local` disables gateway auth and bypasses `ALLOWED_HOSTS` and `external_access_enabled = 0` for loopback (`127.0.0.0/8`, `::1`), RFC1918 LAN, link-local (`169.254.0.0/16`, `fe80::/10`), IPv6 ULA (`fc00::/7`), and **RFC 6598 CGNAT (`100.64.0.0/10`, covering Tailscale tailnet peers and ISP CGNAT)**. Operators must scrub all four master-credential stores and both Apache `htpasswd` files on admin offboarding and restrict LAN/Tailscale access via firewall/ACLs. |

### CWE-22 / CWE-59: Path Traversal & Improper Link Resolution (Symlink Following)

| Component | Threat | Mitigation |
| :--- | :--- | :--- |
| Native McBrowser (`af-files`) | Escaping `/var/lib/aetherflow/mcbrowser/user-<id>` via `..` or symlinks | Descriptor-confined capability traversal rejects `..`, NUL bytes, backslashes, and symlinked mutation parents while enforcing `0700` per-user roots. Opt-in internal symlink reads use Linux `openat2` confinement and target identity verification. Operators must **not** bind-mount shared host storage under `/var/lib/aetherflow/mcbrowser/user-*` because account deletion recursively removes `user-<id>` without a `st_dev` mount-boundary guard. |
| Declarative Package Executor (`af-runner`) | Arbitrary file overwrite or `chown -R` on system roots via symlink planting | Applies to the 9 opt-in declarative Rust recipes (`AETHERFLOW_ENABLE_RUST_PACKAGES=1`, default OFF): `validate_filesystem_path` inspects every ancestor component via `lstat` (`symlink_metadata`), rejects symlinks with `SecurityViolation`, and blocks shared system paths (`FORBIDDEN_EXACT_PATHS`, `SHARED_SYSTEM_CHOWN_PATHS`). |
| Release & Backup Engines (`af-release`, `af-host`) | Malicious archive entries or symlinked staging directories | `ensure_no_symlink_ancestors`, exclusive `0700` UUID staging dirs (`create_new`), rejection of tar symlink/hardlink/device entries, and mandatory `SHA256SUMS` + Sigstore/SLSA v1 provenance (unless `AETHERFLOW_SKIP_PROVENANCE_VERIFY=1` is set in a direct `--local` CLI or `deploy/release-manager.sh` process environment; never forwarded by `af-runner`) + `.manifest.json` verification before extraction. |

### CWE-78: OS Command Injection & Privilege Escalation

| Component | Threat | Mitigation |
| :--- | :--- | :--- |
| Privileged Runner (`af-runner`) | Unprivileged API or plugin process executing arbitrary root commands | `SO_PEERCRED` + `/proc/<pid>/exe` caller verification rejecting plugin binaries and scripting interpreters; strict regex allowlists on unit names (`SAFE_SERVICE_NAME`), package IDs (`SAFE_PKG_ID`), usernames (`SAFE_USERNAME`), and APT packages (`SAFE_APT_PKG_NAME`). Most declarative steps execute direct `execve` argv vectors with `stdin(Stdio::null())` and `process_group(0)`; **known boundary caveats**: all **77** catalog packages default to Bash installers under `/bin/bash` (`AETHERFLOW_ENABLE_RUST_PACKAGES` defaults OFF), **68** remain Bash-only when opt-in Rust recipes are enabled, and `DeclarativeStep::RunCommand` has no binary allowlist (`build_rclone_recipe` invokes `/bin/sh -c`). |
| Managed Plugin Backends (`af-api` -> `af-runner`) | Managed plugin backend or `on_stop` hook inheriting `aetherflow` API OS identity or reaching host-loopback services | `af-api` delegates lifecycle control over `runner.sock` (`/v1/plugins/{start,stop,status,token}`) to `af-runner`, which re-validates `plugin.manifest.json`, launches hardened transient `aetherflow-plugin-<id>.service` units (`DynamicUser=yes`, `ProtectSystem=strict`, `InaccessiblePaths` for control-plane state, read-only assets/token mounts; see [Security Guide](./security.md)), verifies UID/GID separation, and fails closed (`503 PLUGIN_ISOLATION_UNAVAILABLE`).<br/>**Shared network caveat**: Units set `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` without `PrivateNetwork=yes`, `SocketBindDeny`/`SocketBindAllow`, or `IPAddressDeny` (`PLUGIN_BIND_ADDR`/`PLUGIN_PORT` are advisory), so managed plugins share the host network namespace and can reach loopback `/metrics`, loopback-bound gateway-protected Marketplace apps, and outbound networks. |
| Human-Gated FlowAI (`af-api`) | Prompt injection triggering destructive host commands | LLM output is untrusted; proposed service `restart`/`stop` actions are queued in `pending_actions` (Approval Inbox) and cannot execute without explicit administrator approval (`POST /api/v1/admin/actions/:id/approve`). |
| Self-Updater (`af-runner` `/v1/self-update`) | Command injection or caller crash during updater launch | Request channel/command validated via `af_release::validate_self_update_request`; launched in a dynamic transient unit (`aetherflow-self-update-<command>-<channel>-<8hex>.service` via `systemd-run --collect`) with non-secret environment vars passed via `--setenv`, a `0600` config snapshot (`<jobs_dir>/<unit>.conf`) read by the worker, and durable JSON receipts in `<data_dir>/.self-update-jobs/<unit>.json`. GitHub tokens are not forwarded; `resolve_af_cli_binary` checks `AETHERFLOW_CLI_BIN`, `/opt/AetherFlow/current/bin/af`, `/opt/AetherFlow/current/af`, and `/usr/local/bin/af` ahead of `env::current_exe().parent()`. |

### CWE-613 / CWE-384: Session Expiration & Revocation

| Component | Threat | Mitigation |
| :--- | :--- | :--- |
| JWT lifecycle (`af-api`, `af-db`) | Stolen or logged-out tokens remaining usable | 15-minute HS256 access token expiry (`exp`) with a 2-hour refresh grace window and 30-day hard session cap (no separate refresh token). Regular HTTP and fallback `aetherflow_session` subdomain-proxy requests check SQLite `revoked_tokens` (allowing a 10-second `ROTATED_TOKEN_GRACE` window after rotation), client fingerprint, active user status, and `sessions_revoked_after`. `/api/v1/public/auth/verify`, non-loopback `/metrics`, optional authenticated `GET /api/v1/public/marketplace`, and HTTPS `__Host-aetherflow_app` cookies additionally verify `active_sessions`. |
| Account deletion (`af-api`) | Deleted user retaining active session or stranding last admin | Immediate transactional deletion revokes JWT sessions and OIDC tokens, verifies live owner existence on OIDC introspection and WebSocket upgrades, enforces last-usable-admin protection, and schedules durable `account_storage_cleanup`. **Caveat**: deleting the initial admin row does **not** revoke Subdomain Gateway Basic Auth via the provisioning master credential or static `/etc/apache2/AetherFlow/{htpasswd,rutorrent.htpasswd}` files (see CWE-284/285 above) until rotated or removed across all stores. |

### CWE-311 / CWE-89: Cryptographic Storage & SQL Injection

| Component | Threat | Mitigation |
| :--- | :--- | :--- |
| Stored secrets (`af-db`) | Plaintext credentials in SQLite backups | AI provider keys (`settings`), `users.totp_secret`, `streaming_servers.api_key`, `notification_channels.config`, `/var/lib/aetherflow/.master.creds`, and SQLite `system_config.master_credentials` are encrypted at rest with **AES-256-GCM** (`enc:v1:<base64(nonce \|\| ciphertext)>`) keyed by `AES_MASTER_KEY`. OIDC client secrets are SHA-256 hashed (`oidc_clients.client_secret_hash`), the OIDC RS256 signing key is stored at `/var/lib/aetherflow/oidc_rsa.pem` (`0600`), and `GOOGLE_CLIENT_SECRET` is environment-only. |
| SQLite queries (`af-db`) | SQL injection | Parameterized `rusqlite::params![]` queries throughout; online backups use `VACUUM INTO` (default) or `rusqlite::backup::Backup` inside private `0700` staging directories. |

### CWE-918 / CWE-601: SSRF & Host Header Poisoning

| Component | Threat | Mitigation |
| :--- | :--- | :--- |
| Outbound Webhooks (`backend-rs/crates/af-api/src/notifications_ext/webhook.rs`) | SSRF against loopback, link-local, or private LAN targets | Outbound webhook validation blocks loopback, unspecified, link-local, metadata, multicast, and RFC1918/CGNAT/ULA private targets by default (`AETHERFLOW_ALLOW_PRIVATE_WEBHOOKS=1` opts into RFC1918/CGNAT/ULA LAN targets while continuing to block loopback, link-local, and metadata). |
| Streaming Collectors & FlowAI Endpoints (`af-services` `streaming.rs::validate_server_url`) | SSRF against cloud metadata or unsafe redirects | Intentionally permits loopback, RFC1918/ULA LAN, and RFC 6598 CGNAT (`100.64.0.0/10`, set `AETHERFLOW_BLOCK_CGNAT=1` to block) hosts so local and Tailscale Jellyfin/Emby/Plex and LM Studio/Ollama/Anthropic-Local endpoints work natively, while blocking unspecified (`0.0.0.0`/`::`), link-local (`169.254.0.0/16`, `fe80::/10`), cloud metadata endpoints, multicast, proxies, and HTTP redirects. Operators enabling `anthropic-local` must override its `http://localhost:8080` default to avoid targeting `aetherflow-api`. |
| Host Header Validation (`ALLOWED_HOSTS`) | Host header poisoning in OAuth/OIDC redirects and CSP `connect-src` | Middleware validates `Host` against `ALLOWED_HOSTS` and strips untrusted client `X-Aetherflow-User` / `Remote-User` identity headers at the Subdomain Gateway perimeter. **Two exemptions**: (1) `host_validation.rs` implicitly accepts `*.aether.local` hosts even when omitted from `ALLOWED_HOSTS`, and the Subdomain Gateway routes them unauthenticated for loopback, RFC1918, link-local, ULA, and `100.64.0.0/10` (Tailscale/CGNAT) clients; (2) `local_control_plane_host` (`host_resolution.rs`) unconditionally accepts **any valid IPv4/IPv6 literal**, which can reflect arbitrary attacker-supplied IP literals into `GET /.well-known/openid-configuration` (when `PUBLIC_URL`/`OIDC_ISSUER` are unset) and SPA `Content-Security-Policy` `connect-src`. Pin explicit `PUBLIC_URL` and `OIDC_ISSUER` in `/etc/aetherflow/aetherflow.env` and reject catch-all IP `Host` headers at Apache2. |

---

## 3. Trust Boundaries

```text
[Internet / LAN / Tailscale 100.64.0.0/10] ──HTTPS/TLS──> [Apache2 + Subdomain Gateway]
                                   │ (*.aether.local unauthenticated for loopback/RFC1918/ULA/100.64.0.0/10)
                    127.0.0.1:8080 (AetherFlow-Setup;
                    af-api bare default is 0.0.0.0:8080)
                                   ▼
             [aetherflow-api.service (Rust / af-api)]
             (User=aetherflow • ProtectSystem=strict • ProtectHome=read-only • NoNewPrivileges=yes)
                  ├──> [/var/lib/aetherflow/aetherflow.sqlite (0600/0640)]
                  ├──> [/var/lib/aetherflow/mcbrowser/user-<id> (0700)]
                  ├──> [Optional ReadWritePaths: -/srv -/mnt -/media -/data -/opt/AetherFlow/backend/data]
                  └──> [/run/aetherflow/runner.sock (0660 root:aetherflow)]
                                   │
                                   ▼
             [aetherflow-runner.service (Root Daemon / af-runner)]
                  ├──> [systemd Service Manager]
                  ├──> [9 Opt-In Declarative Rust Recipes / Locked Bash Package Scripts]
                  ├──> [aetherflow-self-update-<command>-<channel>-<8hex>.service (af-release)]
                  └──> [aetherflow-plugin-<id>.service (DynamicUser=yes • RO assets/token • 0700 StateDirectory • Inaccessible control-plane paths • shared host network namespace)]
```

---

## 4. Risk Matrix

| Risk | Likelihood | Impact | Severity | Status |
| :--- | :--- | :--- | :--- | :--- |
| Privilege escalation across `runner.sock` | Low | Critical | HIGH | Mitigated (`SO_PEERCRED` + `/proc/<pid>/exe` + strict allowlists + `lstat` guards; Bash installers and `DeclarativeStep::RunCommand` remain audited privileged paths) |
| Managed plugin reading/writing API control-plane files or `runner.sock` | Low | Critical | HIGH | Mitigated (`af-runner` transient `DynamicUser=yes` units + `InaccessiblePaths` + read-only `/run/aetherflow-plugin-{app,token}` mounts + fail-closed `503 PLUGIN_ISOLATION_UNAVAILABLE`) |
| Managed plugin reaching host loopback services (`/metrics`, loopback Marketplace apps) | Medium | High | HIGH | Residual boundary (no `PrivateNetwork=yes`, `SocketBindDeny`, or `IPAddressDeny`; `PLUGIN_BIND_ADDR`/`PLUGIN_PORT` are advisory — install only loopback-trusted plugins) |
| Offboarded admin retaining Subdomain Gateway or Apache Basic Auth via provisioning master secret / static `htpasswd` | Medium | High | HIGH | Residual boundary (`verify_proxy_basic_credentials` checks `.master.creds` / `system_config.master_credentials` before `users.role == "admin"` and skips TOTP if `users` row is deleted; `/etc/apache2/AetherFlow/{htpasswd,rutorrent.htpasswd}` do not auto-revoke — scrub all stores on admin offboarding) |
| Unauthenticated LAN / Tailscale (`100.64.0.0/10`) access to gateway-protected apps via `Host: <app>.aether.local` | Medium | Critical | HIGH | Residual boundary (`.aether.local` disables gateway auth and bypasses `ALLOWED_HOSTS`/`external_access_enabled` for loopback/RFC1918/link-local/ULA/`100.64.0.0/10` — restrict reachability via host firewall and Tailscale ACLs) |
| Tenant file escape in McBrowser | Low | High | HIGH | Mitigated (`af-files` capability scoping + `openat2` opt-in read confinement + strict mutation-parent symlink rejection + admin-only `/fs`; avoid bind mounts under `user-*`) |
| Broken update killing the updater mid-restart | Low | High | HIGH | Mitigated (dynamic transient `aetherflow-self-update-<command>-<channel>-<8hex>.service` + WAL-safe snapshot + binary path check + durable receipts) |
| AI prompt injection mutating host state | Medium | High | HIGH | Mitigated (Approval Inbox `pending_actions` gate + `admin_audit_log`) |
| API key or TOTP secret plaintext exposure in DB | Low | High | HIGH | Mitigated (AES-256-GCM `enc:v1:` envelope encryption keyed by `AES_MASTER_KEY`) |

---

*Last updated: 2026-11-23 (AetherFlow v4.0.0)*
