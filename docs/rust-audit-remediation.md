# Rust McSurgeon Remediation - October 31, 2026

## Scope

Remediation of the 41 findings in McSurgeon run `worktree_20261031_062251`.
Existing working-tree implementation changes were preserved. Four parallel
implementation agents used separate file ownership; integration was validated
against the complete six-crate Rust workspace.

## Fix Coverage

| Findings | Remediation |
| --- | --- |
| L-01, L-04, L-05, L-07, L-08, L-09, P-01 through P-05, SEC-09 | Canonical `af_models::AppIngressConfig`, timestamp types, `set_app_ingress_config`, derived internal domains, reachable port fallback, and consistent provisioning signatures. |
| L-03, L-11, P-06, P-07 | Exported demo-mode predicate, canonical streaming fields, `connected` status, string dashboard window, correct demo-seed return handling, and connection release before demo seeding. |
| L-10, L-12 through L-16, L-18 | Reuse held connections or release them before nested database helpers in action resolution, metrics, quotas, settings, authentication, and OIDC. The pool remains `max_size(1)`. |
| SEC-01 | Compatibility ingress routes require authentication, CSRF validation, and an administrator role; unrelated compatibility routes retain their existing authentication behavior. |
| SEC-02, SEC-03, P-09 | Fail-closed 2FA disable, transactional hashed recovery-code replacement, conditional single-use consumption, and blocking-worker regeneration. |
| SEC-04, SEC-08 | Forward-auth validates revocation and client fingerprint; session prefix matching is literal, user-scoped, and rejects ambiguity. |
| SEC-05 | Heartbeats require a valid configured or previously enrolled PSK; untrusted first enrollment fails closed. Stored SHA-256 hashes are not accepted as plaintext PSKs. |
| SEC-06 | Webhook URLs and resolved addresses must be public; DNS addresses are pinned and redirects and environment proxies are disabled. |
| SEC-07, P-08 | MediaFlow scans canonicalize paths, enforce configured roots, skip nested symlinks, run off Tokio workers, and release SQLite connections before probing files. |
| L-02, L-06 | Canonical runner socket resolution, `SystemctlRequest.service`, and extraction of metadata from response payloads rather than their envelopes. |
| L-17, P-10 | Package failures propagate instead of completing successfully; child commands use kill-on-drop and drain stdout and stderr concurrently. |
| P-11 | Network status includes real WireGuard and Tailscale objects when available, with blocking commands offloaded and corrected field extraction. |
| P-12, P-13, P-14 | Blocking backup/update work is offloaded, backup hashing releases SQLite, update scripts use canonical resolution, and audit-log fallback reads `detail`. |

Integration compilation additionally exposed and fixed the dashboard handler's
extractor signature, intelligence telemetry's `live_summary` fields, and the
large JSON macro's required crate recursion limit (`256`).

## Validation

Validation ran over SSH in `/tmp/aetherflow-audit-c10ad714` on Hetzner, not in
the production checkout or a running deployment. No local Node/npm commands,
production restarts, commits, or branches were used.

- Rust/Cargo toolchain: `1.99.1`.
- `cargo check --workspace`: passed.
- `cargo test --workspace`: **53 passed, 0 failed**; documentation tests passed.
- `git diff --check`: passed.
- Test totals: API 19, database 2, hardware 3, models 2, runner 8, services 19.
- Existing unused-import, dead-code, and naming warnings remain outside scope.
- The source tree has no Cargo lockfile; Cargo resolved dependencies in the
  isolated validation directory. No generated lockfile was copied back.

Regression coverage includes recovery hashing, normalization, rollback and
single use; malformed 2FA-disable requests; proxy revocation/fingerprint checks;
literal session lookup; webhook URL/IP checks; MediaFlow traversal and symlink
rejection; VPN response parsing; ingress preservation; package failures and
stderr draining; runner metadata envelopes; cluster PSKs; and database helpers.

## Operational Notes

- New cluster enrollment requires a configured master `CLUSTER_PSK`. Existing
  enrolled nodes may authenticate against their stored trusted PSK hashes.
- Webhook destinations on private, loopback, link-local, reserved, or other
  nonpublic addresses are rejected, including private Gotify destinations.
- MediaFlow uses comma-separated `AF_ALLOWED_FS_ROOTS`. Without an override,
  the permitted roots are `/mnt`, `/media`, `/home`, `/opt/AetherFlow`, and
  `/var/lib/aetherflow`; only existing canonical roots are used.
- Recovery-code replacement clears the affected user's legacy plaintext column.
  Previously created database backups are not scrubbed by this change. Users
  with legacy recovery codes should regenerate and securely store new codes.
- Production systemd/Apache behavior, live OIDC providers, VPN services, and
  real webhook delivery were not exercised. Complete deployment smoke checks
  before promoting the changes. No production deployment was performed.

---

## Round 2: Four-Model Ensemble Audit (`worktree_20261031_155126`) — v4.0.0 Release

Following Round 1, a second independent McSurgeon audit was executed across `backend-rs` using four specialist models in parallel:
- **Grok 4.7** (`GROK-01` through `GROK-25`)
- **Gemini 4 Argon** (`ARGON-01` through `ARGON-12` + 4 supplementary pass-1 fixes)
- **Gemini 3.8 Flash** (`FLASH-01` through `FLASH-08`)
- **GPT-6.1 Terra** (`TERRA-01` through `TERRA-04`)

All **49 ensemble findings** (plus 4 supplementary Argon findings) were remediated and verified against the live workspace on Hetzner (`cargo check --workspace` and `cargo test --workspace`: **53/53 unit tests + doc-tests passing, 0 failed**):

| Lens / Area | Findings Remediated | Summary of Fixes |
| --- | --- | --- |
| **Security & Trust Boundaries** | `TERRA-01`, `TERRA-02`, `FLASH-01`, `GROK-02`, `GROK-04`, `GROK-11`, `GROK-21`, `ARGON-04` | Enforced `is_token_revoked` and fingerprint verification in `app_subdomain_proxy_middleware`, bound JWT refresh windows to original token `exp`, required `X-Cluster-PSK` on `/cluster/v1/metrics`, enforced cumulative `MAX_UPLOAD_SIZE` on chunked uploads, canonicalized `fileshare_delete` paths, and switched AES-GCM nonce generation to `OsRng`. |
| **SQLite `max_size(1)` Concurrency** | `ARGON-01`, `ARGON-02`, `ARGON-03`, `ARGON-05`, `ARGON-06`, `ARGON-07`, `GROK-01`, `GROK-03`, `GROK-22` | Added `insert_audit_log_on_conn` and `create_session_for_user_with_conn`, dropped held pooled connections before nested `af_db` calls across `auth.rs`, `oidc.rs`, `routes.rs`, `intelligence.rs`, and `storage.rs`, and wrapped multi-table user/role deletions in atomic transactions. |
| **Streaming, Proxy & Executor Performance** | `TERRA-03`, `FLASH-03..07`, `ARGON-08`, `GROK-18` | Replaced full-response `to_bytes(usize::MAX)` buffering in `app_subdomain_proxy_middleware` with `Body::from_stream(resp.bytes_stream())`, offloaded blocking backups/metrics/filesystem scans to `tokio::task::spawn_blocking`, and normalized ISO-8601/SQLite timestamp comparisons in `get_metrics_history`. |
| **API Contracts & State Machines** | `TERRA-04`, `FLASH-02`, `FLASH-08`, `ARGON-09..12`, `GROK-05..10`, `GROK-12..17`, `GROK-19..20`, `GROK-23..25` | Fixed Transmission HTTP 409 session-ID retry handling, reset `ENRICHER_STATE.scanning` when `media_files` is empty, ordered OIDC device expiry checks before status checks (`expired_token`), enforced 404 on missing user role updates, and added `limit`/`offset` pagination to `list_pending_actions`. |

