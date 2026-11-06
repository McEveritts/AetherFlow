# Marketplace hill climb — opening Opus and Sol implementation (2026-11-05)

Scope: install/reinstall/uninstall, application update checks/upgrades/recovery,
system updater across restarts, Services start/stop/restart, and the
Services/Marketplace UI's status, progress, and errors. Rust V4 is the
authoritative backend. The Go compatibility backend and the shell package
scripts were **not** changed or re-verified in this round.

Base: `nightly` @ `13066f92`. Everything here is uncommitted source in the shared
checkout. Nothing was staged, committed, pushed, deployed, or restarted, and no
real install/remove/update scripts ran.

## Orchestration note (not an application defect)

The first Opus task stopped after about 13 minutes with the provider error
`messages.181.content.0.thinking.signature: Field required`. That came from the
agent transport, not from AetherFlow. The parent saved that task's partial edits
in `/tmp/aetherflow-marketplace-opus-first-partial-20261105.patch`. This round
picked up those edits in the checkout without replaying the failed conversation.

A second environment problem: `/tmp` is a 32 GB tmpfs and was **100 % full**.
The first `cargo test` attempt with `CARGO_TARGET_DIR` under `/tmp` failed with
`No space left on device`. This round therefore built in
`backend-rs/target` on the main disk, with `TMPDIR` and the Jest cache in
`~/.cache/af-hillclimb-tmp`. A full tmpfs is a production risk on this host
because it uses RAM, so an operator should clean up old agent caches such as
`/tmp/aetherflow-rust-migration-d40b50a1` (8 GB),
`/tmp/aetherflow-audit-c10ad714` (6 GB), and
`/tmp/aetherflow-marketplace-repair-cargo-target` (4 GB). This round deleted none
of them.

## Defects addressed (source proofs)

| # | Defect (pre-change behaviour at `13066f92`) | Change | Proof |
|---|---|---|---|
| D1 | A package removal could inherit `DELETE_DATA` from the runner environment, so whether data was purged was implicit. | `PackageRunnerRequest.delete_data` is an explicit `bool` that defaults to `false`. Only `DELETE /…/uninstall?purge=true\|1` sets it. Any other `purge` value returns 400. The runner rejects purge for `install`/`update`. The legacy runner exports `DELETE_DATA` explicitly, and declarative packages get the same value. | `af-runner` `test_handle_package_rejects_purge_for_non_remove_actions`; `af-api` `test_uninstall_purge_requires_explicit_true` |
| D2 | A failed update cleared the active job and left the package `installed`. Polling clients saw success, and the UI showed "has been updated". | `af-services` keeps a terminal outcome per package (`PackageJobOutcome`). The public catalog's `last_job` carries the action, status, and timestamps but no error text. The authenticated `/progress` endpoint adds the failure message. Services status items carry `last_job`. | `test_failed_lifecycle_outcome_survives_active_job_removal`; `test_progress_reports_failed_outcome_after_job_clears_but_public_view_has_no_detail` |
| D3 | **Found in this round.** In the partial outcome registry, a late `finish_package_job` from a superseded job still overwrote the outcome while a newer job was active. It could also replace a newer job's terminal outcome. | `finish_package_job` now takes the jobs lock and then the outcomes lock, the same order as `try_start_package_job`. It records an outcome only if it owns the active job's identity (`started_at`), or if no job is active and no newer outcome exists. | Strengthened `test_stale_finish_does_not_remove_newer_active_job` |
| D4 | `POST /services/{name}/control` would run `systemctl` on any unit named in `process`, acting as a generic root systemctl proxy. | `authorize_service_control_target`: a core card (`aetherflow-api`, `aetherflow-frontend`, `apache2`) may control only itself. A package card may control only its own name, primary unit, resolved units, and sandbox/companion units. Shared-vhost packages cannot reach `apache2`. Unknown cards are rejected with 403 `SERVICE_CONTROL_FORBIDDEN`. Unknown managers and `embedded` are rejected. | `test_service_control_target_is_limited_to_card_units`; `test_service_control_rejects_foreign_units_and_unknown_managers`; `test_companion_units_resolve_to_owning_package` |
| D5 | Manual start/stop/restart during an install, update, or remove raced the installer's own stop/swap/start sequence. | Control returns 409 `PACKAGE_LIFECYCLE_IN_PROGRESS` while the owning package, including via a companion unit, has an active job. | `test_service_control_is_serialized_with_active_lifecycle_job` |
| D6 | A system self-update could start while a package job was running, and the reverse. The updater restarts the API and runner, which cuts the runner stream and kills the package script partway through. | `run_update` holds `PACKAGE_LIFECYCLE_MUTEX` for up to 10 s and refuses to start if jobs are active. It records the launched unit. Package dispatch blocks with `SYSTEM_UPDATE_IN_PROGRESS` and checks again under the mutex. If the updater status is unknown, it fails closed. | `test_system_update_blocks_package_lifecycle_until_terminal`; `test_active_system_update_tracking_is_unit_scoped` |
| D7 | Services reported the API and frontend as the hard-coded version `v3.2.6`. | Uses `af_release::runtime::runtime_identity().version`. | Source only, no dedicated test |
| D8 | **Found in this round (frontend).** The Marketplace UI announced a failed update as a success because the status stays `installed`. | `useMarketplace` adds `last_job` to the type and a pure helper, `lastJobFailed`. `MarketplaceTab` checks a matching failed outcome before the success branches. The pending (fast-finish) path trusts an outcome only when its `started_at` equals the job identity returned by this client's lifecycle POST, so an older outcome cannot be attributed to a new job. If a backend omits `last_job`, the UI keeps the status-only behaviour. | `src/hooks/useMarketplace.test.ts` (4 tests); `tsc` passes |

## Validation (exact)

Rust, run from `backend-rs/` with `cargo test --offline -p af-services -p af-runner -p af-api -p af-models -p af-cli` on the default on-disk target. **EXIT=0, 523 tests passed and 0 failed.** That includes 353 in the `aetherflow_api` binary (2 ignored, as before), 77 in `af-runner` (1 ignored), and 42 in `af-services`. The log is at `~/.cache/af-hillclimb-tmp/tests.log`.

- One `Failed to execute /usr/bin/pkttyagent` line went straight to the terminal during the run. It shows that some test (not identified) tried to use polkit. Because no agent was available, authorization could not have succeeded. The tests added in this round call no privileged commands, since the control tests use only `validate_service_control_request`. Sol should identify that test and isolate it.

Frontend, run from `frontend/` with Node `v24.22.2` from `/tmp/aetherflow-marketplace-test-tools`:

- `../node_modules/.bin/tsc --noEmit --incremental false`: **pass**. An earlier run caught a missing import that Jest's Babel transform had hidden, and it is fixed.
- `eslint` on the 3 changed frontend files: **0 errors**, plus 1 existing `no-img-element` warning, which stays because local app icons must keep working.
- Jest on `src/hooks` and `src/components/tabs`: see the next line.
- Result: **15 suites passed and 1 skipped. 166 tests passed and 3 skipped (169 total), with 0 failures.** Jest then printed "did not exit one second after the test run" (open handles), so this round stopped the process. This was not traced to the change; Sol should check it with `--detectOpenHandles`.

Not run in this round (source-only limits):

- Full `npm run test:ci`, `npm run lint`, and `NEXT_STATIC_EXPORT=1 npm run build` in an isolated output directory.
- `cargo clippy` and `cargo fmt --check`, plus tests for other workspace crates.
- Go backend tests and shell script contract checks (`tests/`).
- Any integration test against a real runner socket or systemd. By design, no mocked end-to-end harness exists yet for the lifecycle job, outcome, and UI loop.

## Scores (out of 10)

BEFORE is the source state at `13066f92`. AFTER is this checkout.

| Area | BEFORE | AFTER | Why not higher |
|---|---|---|---|
| (1) Install / reinstall / uninstall | 6 | 7 | Purge is explicit in Rust only. The Go compatibility path and script-level retention of data, config, secrets, and ports were not re-verified. The UI has no explicit purge option or confirmation. |
| (2) Application updater | 5 | 6.5 | Failures are now visible. Outcomes are in memory only and are lost when the API restarts. Rollback/recovery after a failed update and the version re-check after an update were not exercised. |
| (3) System updater / restart | 5 | 6 | The updater unit survives restarts (existing). The new API-side gate between updates and package jobs is **in memory**, so it is lost when the API restarts, which is exactly what the updater does. |
| (4) Services control and units | 5 | 7 | Authorization and lifecycle serialization are unit tested. The pm2 path allows only name or service_name. If the catalog fails to load, controls fail closed (deny), which may block legitimate core-adjacent controls. Not verified against live unit lists. |
| (5) Frontend workflow / errors / progress | 5 | 6 | Failure toast for the Marketplace only. The Services tab does not show `last_job`. The status-only fast-finish success toast and the clearing of pending state in `onSuccess` still have a stale-snapshot race. No purge UI. |
| (6) Regression confidence | 5 | 6.5 | 523 Rust tests, `tsc`, eslint, and focused Jest pass. No full frontend suite or build, no Go tests, no clippy, no integration harness. |
| **Overall** | **5** | **6.5** | Known scoped P1s remain (see below). |

## Opening Opus priorities for GPT 6.1 Sol X-High (historical; Sol disposition below)

1. **P1: Make system-update gating survive API restarts.** `ACTIVE_SYSTEM_UPDATE` is process memory. `system_update_lifecycle_block` should ask the runner or the journal whether any self-update unit or recovery journal is active (`/system/update/status` already survives restarts) instead of trusting only the unit this process launched. Add a test where an API restart happens mid-update.
2. **P1: Persist terminal job outcomes,** or rebuild them from the audit or package state at startup, so a failed update stays visible across an API restart. Consider a monotonic job id instead of a millisecond `started_at`. The current ordering logic depends on RFC3339 timestamps comparing correctly as strings.
3. **P1: Frontend stale-snapshot races.** `useMarketplace.onSuccess` can clear pending on a poll that lands before the POST registers the job. The fast-finish success branches for `updating` → `installed` can fire on the pre-POST snapshot. Both should require the job identity from the POST, matching what this round did for failures. Add `MarketplaceTab` tests for failed update, stale outcome, and successful update.
4. **P1: Services tab.** Show `last_job` with failure detail from the authenticated status, per-unit (companion) status, and logs. Keep the controls disabled while a lifecycle job runs so users don't hit the new 409s.
5. **P2: Explicit purge UI** with a confirmation that names the data to be destroyed. Check that the Go backend and `removepackage-*` scripts keep data, config, secrets, and ports unless `DELETE_DATA=1`.
6. **P2: Check service-control authorization** against real `get_active_services` output for every catalog package, including pm2 packages, `.timer` companions, and sandbox ids. Decide whether a catalog-load failure should deny core controls. Today the core cards bypass the catalog and still work.
7. **P2: Identify the test that invokes polkit** (`pkttyagent`) and isolate it. Run full `test:ci`, lint, the static-export build, clippy, and Go tests.
8. **P3: Add a dedicated test for D7** (runtime version shown in Services) and confirm the frontend displays it.

## Sol X-High implementation round

Performed directly by GPT 6.1 Sol X-High, without nested agents, delegation,
threads, commits, staging, pushes, deployments, live lifecycle commands, or
service restarts. Baseline and Opus results above are preserved as historical
results. **This round self-scores 8.5/10. Do not bring Opus back yet.** The next
Sol iteration should address the three P1 gaps below before the independent
review gate.

### Implemented

1. **Restart-surviving system-update discovery.** An empty runner status request
   discovers every persisted self-update receipt and the native recovery journal.
   It no longer depends on `ACTIVE_SYSTEM_UPDATE` in API memory. Unreadable,
   corrupt, missing expected, and unknown status fail closed. Terminal failures
   do not turn into successful updates. The old in-memory flag was removed.
2. **Cross-process admission in both directions.** Native and Bash package
   execution hold the release maintenance lock, as well as their existing package
   mutex/flock. Updater launch acquires that same maintenance lock. API package
   admission holds it while rechecking updater status and persisting the new job.
   Both runner launch and local `af release` execution check the durable API job
   table under this lock. Thus API pre-stop and post-script phases also block
   self-update. Lock order is package process mutex → package flock → maintenance
   lock; updater launch needs only maintenance → journal/database reads.
3. **Recovery remains reachable.** Discovery distinguishes `recovery_required`
   from a running updater so an explicit rollback remains allowed after an
   interrupted update. A corrupt database header is inspected without opening
   SQLite first: even a read-only WAL connection can alter `-shm`. Explicit
   rollback can proceed to the existing backup verification/quiescence path;
   deployment still fails closed. The existing tampered-snapshot regression
   verifies the corrupt DB/WAL/SHM remain unchanged and writers are not restarted.
4. **Durable lifecycle receipts and UUIDs.** `af-services/src/package_jobs.rs`
   serializes the registry with one mutex and persists identities/actions,
   timestamps, and states in SQLite before admission/completion. Every job has
   a UUID, separate from the display timestamp. Progress and finish require that
   UUID; late events cannot revive or overwrite a newer job. Startup changes
   unconfirmed API-owned work to `interrupted`, never guessed success. Only safe
   fixed summaries survive restart; installer output, failure details, and secrets
   are not persisted. The public catalog exposes outcome identity/status only,
   and its active progress label no longer carries raw installer output.
5. **Truthful progress and refresh.** Progress remains monotonic and is capped at
   95% until the orchestration completes. Failed execution also invalidates the
   runtime cache and refreshes update metadata. Finalization/persistence failures
   cannot emit a successful terminal receipt.
6. **Retained settings without active ingress.** Rust and Go archive ordinary
   uninstall's ingress settings in `retained_app_ingress_configs`, then remove
   active registrations. Reinstall reads the archive and retains allocated port,
   domain, and TLS policy. Purge removes the archive. Catalog gateway fallbacks
   require a physical installation when there is no active ingress record;
   retaining settings must not route a removed app's domain to another process.
   Removing the last app still synchronizes the managed DNS block.
7. **Explicit UI workflows.** Marketplace now has an in-place Reinstall
   confirmation and an Uninstall dialog that defaults to retained data. Purge is
   opt-in and requires typing the app identifier. Dialog edits survive background
   refresh. Completion requires the accepted UUID/action, including fast finishes;
   stale pre-POST snapshots never settle pending requests. Unknown/interrupted
   outcomes are errors, and failure messages no longer assert unverified rollback.
   Idle polling also discovers another client's operations. Observed job identities
   survive intervening stale snapshots until the matching receipt arrives.
8. **Services lifecycle and diagnostics.** Services consumes UUIDs and `last_job`,
   retains authenticated failure summaries on remount, and disables conflicting
   controls for install/update/remove. Companion unit roles/statuses and per-unit
   logs remain usable while busy. Service manager spoofing is rejected against
   the catalog, including pm2 on a systemd/core card. Manual runner controls also
   take package locks, protecting a surviving script after API restart.
9. **Core restart acknowledgment.** Core API/runner deferred restart arguments
   are restricted to those two targets and schedule a short independent systemd
   timer. API control returns HTTP 202/accepted before the restart can kill its
   response. Services reports scheduling, not completed restart. Live readiness
   certification and an operation-specific completion receipt remain follow-up.
10. **Go/script retention contract.** Go carries explicit `delete_data`, rejects
    purge on non-removal actions, defaults ambient `DELETE_DATA` to false, and
    sends `AF_PACKAGE_ACTION`. The API purge query matches Rust's strict values.
    Go's old async job API still lacks UUID/terminal receipt parity; the frontend
    reports missing identity instead of fabricating success.
11. **Safe tests and clean teardown.** The unsafe Rust sandbox test now injects
    its apply operation. The vanished-unit status test uses an explicit fake
    systemctl. Validation adds blocking PATH shims for systemctl/sudo/systemd-run/
    pm2, with test-specific fakes taking precedence. Jest retains native scheduling
    but closes every MessageChannel owned by a test environment in `afterAll`.
    Removing MessageChannel entirely was tested and rejected because it broke five
    existing workspace tests; the final teardown fix passes those tests too.
    Python harness path rewriting is single-pass, so disk-backed TMPDIR paths
    containing `/home/` are not rewritten twice; explicit `/tmp/` installer scratch
    paths are rebased inside their fixtures.

### Regression evidence and validation

All scratch/build/log output is disk-backed under
`/home/betheenvy/.cache/af-hillclimb-tmp`, with the warm Rust target in
`backend-rs/target`. Node is the existing verified v24.22.2 runtime at
`/tmp/aetherflow-marketplace-test-tools/node-v24.22.2-linux-x64/bin` (read-only
use of that runtime). No new output was placed in the full `/tmp` filesystem.

- `cargo test --offline --workspace -- --test-threads=1`: complete workspace
  passes on the final implementation: **726 top-level tests pass, 0 fail,
  3 existing ignored** (12 test binaries; subprocess re-executions are not
  double-counted). The final affected-crate run (`af-release`, `af-runner`,
  `af-services`, `af-api`) passes **508 tests**, with **3 existing ignored**:
  API 353, release 34, runner 79, services 42. Logs:
  `sol-rust-workspace.log`, `sol-rust-final.log`, and
  `sol-rust-workspace-final.log`.
- `cargo clippy --offline --workspace --all-targets`: passes, with existing
  warnings; log `sol-clippy-final.log`. No warnings were promoted to errors or
  suppressed to obtain this result.
- `cargo fmt --all -- --check`: **fails on pre-existing formatting**. New modules
  and formatting hunks overlapping the task's changes were formatted, without
  mass-formatting unrelated source. `sol-fmt-final.log` and
  `sol-format-baseline.json` compare failures to `git show HEAD:<file>`; this
  check is not being claimed as passing. All 50 distinct source files flagged
  by the full check are already unformatted at `HEAD`; duplicate module paths
  from the streaming test harness are normalized in the comparison.
- Frontend full TypeScript, including tests:
  `../node_modules/.bin/tsc --noEmit --incremental false`: passes.
- Frontend `npm run lint`: passes with **0 errors**, existing warnings (41 in
  the earlier full pass); log `sol-lint-final.log`.
- Frontend `npm run test:ci`: **58 suites pass, 1 skipped; 551 tests pass,
  5 skipped**. Uses the repository's existing `--forceExit` CI script, without
  changing failure exit codes. Log `sol-test-ci-current.log`.
- Independent open-handle verification: five suites (Marketplace, Services,
  hook, McBrowser, StreamingHistoryAdmin), **100 tests pass**, exit zero with
  `--detectOpenHandles` and **without `--forceExit`**. Log
  `sol-jest-handles-final.log`.
- `NEXT_STATIC_EXPORT=1 npm run build`: passes in the owned isolated copy
  `/home/betheenvy/.cache/af-hillclimb-validation-sol/frontend`; no live `.next`
  or export output is overwritten. The initial dependency symlink was rejected
  by Turbopack's workspace boundary. The final isolated copy has local hardlinks
  to the installed dependency files and preserves relative workspace links;
  no dependency installation or production dependency mutation was performed.
  Log `sol-build-final.log`.
- Go `go test ./services ./api ./db`: passes under host-control shims. Logs
  `sol-go-final.log`. Retention tests check explicit environment intent, retained
  port reuse, and removal of the active gateway route.
- Marketplace mocked-script harnesses: **85 tests pass** with
  `python3 -m unittest discover -s tests -p 'test_marketplace*.py' -v`.
  Log `sol-python.log`.
- Installer mocked-script harnesses: **68 tests pass** with
  `python3 -m unittest discover -s tests -p 'test_*installer*.py' -v`.
  Includes Maintainerr install/reinstall/retention/build isolation/rollback,
  Palate, Jellyseerr, The Lounge, Node helpers and network installer contracts.
  Log `sol-installers.log`.
- Disposable lifecycle harness guardrail/evaluation unit tests: **33 pass**.
  This tests the guest harness; it does **not** claim a guest integration run.
  Log `sol-guest-unit.log`.
- `git diff --check`: passes. No production shell script was changed, so no
  changed-shell syntax gate applies.

Regression additions cover receipt reload, interrupted recovery, stale UUID
finishes, no secret-output persistence, updater discovery without API memory,
corrupt/unknown/terminal update states, competing maintenance locks, explicit
rollback admission, ordinary removal versus purge, retained port/domain/TLS,
POST/poll ordering, failure/unknown/interrupted outcomes, external client jobs,
remounts, busy diagnostics, and confirmation input preservation.

### Remaining P1s — next Sol iteration before Opus

These are source-level gaps, not claimed live incidents. They keep this round
below the 9/10 gate even with passing validation.

1. **Owner-aware stale API job recovery for standalone updates.**
   `ensure_no_active_package_lifecycle_jobs` correctly blocks active durable
   records, but the rows do not identify a live API process/boot/instance. Only
   API startup currently converts unconfirmed records to `interrupted`. If the
   API cannot start after a crash, a standalone `af release … --local` can stay
   blocked by a stale row even after the runner script has exited. Add robust
   owner/liveness reconciliation under the shared lock; preserve unknown status
   as unknown. Do not delete/forge recovery state or infer success from locks.
2. **Full orchestration reservation shared with direct package CLI requests.**
   Self-update now checks the API's durable reservation during pre-stop and
   post-script work. Direct package execution's maintenance guard currently
   checks self-update receipts, not another API job's identity. A CLI package
   request can enter between an API script releasing its runner locks and API
   post-script persistence/restoration. Carry the API UUID to the runner and
   enforce an ownership-aware reservation covering the whole orchestration,
   without deadlocking its own service-control callbacks or queued API jobs.
   Reproduce with isolated concurrent API/CLI fixtures, including same-package
   update versus remove.
3. **Updater launch-versus-status reconciliation race.**
   The launcher writes a `running` receipt before invoking `systemd-run`.
   `query_self_update_job_at` can mark an incomplete receipt failed when
   `LoadState=not-found`, while terminal receipts are trusted without another
   unit query. A status request in the pre-unit-creation window can therefore
   publish premature failure. Shared locks substantially protect mutations,
   but do not make this status truthful. Introduce a durable launch phase and
   authoritative unit/launch ownership reconciliation; test a status query
   paused between receipt creation and unit admission, runner restart during
   launch, unknown systemd state, and late terminal writes.

Additional review priorities (P2): verify all catalog authorization outputs,
including explicit raw `.timer`/oneshot control policies; extend Go job identity/
outcome parity if the compatibility server remains supported by this frontend;
add a core restart completion/readiness receipt and stale Services fetch feedback;
review configuration-load fallback when an explicit catalog path is unreadable;
and inspect the new persistence/read-only admission code for WAL, lock-order,
rollback, and DB-restoration interactions. The parent still owns the independent
McSurgeon/lens review; none was delegated from this implementation round.

### Scores after Sol (source-level, out of 10)

| Area | Sol score | Material limit |
|---|---:|---|
| Install / reinstall / uninstall | 8.8 | Direct CLI/API full-orchestration reservation remains incomplete; no all-77 live certification. |
| Application updater | 8.5 | Durable truthful receipts and mocked rollback improve recovery, but same-package CLI interleaving remains. Upstream DB migration reversal is not guaranteed. |
| System updater / restart | 8.0 | Durable discovery/admission and explicit rollback work; stale owner reconciliation and launch/status race remain P1. Core restart is an acknowledgment, not a completion certificate. |
| Services controls and units | 8.8 | Busy state, failures, companion diagnostics and runner exclusion improved; raw-unit policy and core completion need independent review. |
| Frontend workflows | 9.0 | Matching receipts, late polls, remounts, purge/reinstall and preserved edits tested. Go missing-identity response is explicitly unknown. |
| Regression confidence | 8.8 | Broad Rust/Go/frontend/mock harnesses pass; workspace format baseline fails and live/disposable integration remains unrun. |
| **Overall** | **8.5** | **Known scoped P1s remain; another Sol X-High round is required before Opus returns.** |

No actual native application was installed, removed, purged, updated, or restarted.
No production database was used as a test fixture. Real systemd restart smoke,
full disposable-guest integration, upstream downloads/builds, and live data
migration/rollback certification across all 77 applications were not exercised.

Final safety observation: a read-only metadata check found no
`/etc/systemd/system/sonarr.service.d/aetherflow-sandbox.conf`; the existing
`10-aetherflow-sandbox.conf` is root-owned and dated 2026-11-04 18:44:52 UTC,
which predates this run. This does not establish that the earlier Opus test
had no effect (for example, a daemon-reload leaves no file timestamp). No
production file was changed or service reloaded to investigate it.

## Second Sol X-High implementation iteration — 2026-11-05 to 2026-11-06 CET

The opening Opus **6.5/10** and first Sol **8.5/10** assessments above are
historical and unchanged. This iteration works in the same uncommitted
`nightly` checkout based on `13066f92`; it does not replace or discard earlier
outcome, retention, UI, compatibility, or deferred-restart work. No agents,
specialist reviews, new threads, staging, commit, push, deployment, production
database mutation, or live service restart were used. The parent owns the
independent McSurgeon/lens review and any subsequent orchestration.

### P1 implementation and source proofs

1. **Owner-aware stale API work, including standalone recovery.**
   `af-release/src/lifecycle.rs:6` introduces UUID owner leases held by an
   advisory lock, not inferred from PID, timestamps, or a process name. The
   lease file and parent directory are synced before the durable SQLite row
   publishes its owner. Persistent `*.lifecycle-owners` evidence intentionally
   survives completion and database snapshot restoration. Reconciliation at
   `af-release/src/lifecycle.rs:108` changes only recognized active phases
   whose existing owner lease is provably released to **interrupted**. Missing,
   malformed, inaccessible, or unknown identity/status remains unresolved.
   It never infers success or edits the release recovery journal.

   `af-release/src/admin.rs:534` reconciles under shared maintenance admission
   before standalone local release work. The shell release manager uses the
   same lease protocol. Invalid SQLite headers are checked before opening;
   recognized SQLite corruption remains eligible for explicit rollback,
   including corruption in the lifecycle table with an intact database
   header. Other I/O, locking, and permission failures remain fail-closed.

   `af-services/src/package_jobs.rs:76` refreshes foreign durable jobs instead
   of assuming API startup owns or abandoned them. Unknown nonterminal phases
   cannot be overwritten by new admission. The lease transfers into the
   actual API task at `af-api/src/routes.rs:1559`; task cancellation/drop
   releases ownership but never fabricates completion. Terminal SQL updates
   require the matching still-active job identity.

2. **Full API/CLI reservation, not just script execution.**
   `af-release/src/lifecycle.rs:139` checks package, service/companion, or core
   system targets against durable active reservations. UUID plus package
   action must match for owned package work; copying an update UUID does not
   authorize remove. The API scopes the complete pre-stop/script/post-script
   future to its UUID. Runner UDS requests and native execution environments
   carry it, so legitimate service callbacks proceed while conflicting direct
   CLI work is refused. Unrelated package reservations do not prevent the
   active job's callbacks or the next queued job from making progress.

   `af-runner/src/lib.rs` checks reservation admission before waiting for
   execution locks and again under maintenance serialization. Services,
   no-runner local fallback, and automatic healing share those guards. Core
   API/runner stop/restart requires no active lifecycle, but starting an
   unavailable API does not unnecessarily require global quiescence.

   **Additional crash gap found and fixed here:** the installed runner unit
   uses `KillMode=process`, so an installer child can survive the runner.
   `af-release/src/lock.rs:100` now supports child inheritance of maintenance
   exclusion. Native commands, legacy installer scripts, sandbox helpers,
   and runner systemctl mutations retain it. Unix guard destruction closes
   its descriptor rather than explicitly unlocking the shared open-file
   description. Thus neither normal parent drop nor a killed runner can
   make surviving mutating children invisible to standalone recovery.

   Local Services fallback also uses a waiting lock guardian
   (`af-services/src/lib.rs:1710`): it survives loss/drop of the API's guard,
   while closing the inherited descriptor in the actual sudo/systemctl/pm2
   child so a long-lived daemon does not accidentally retain maintenance
   exclusion forever. Its isolated shell fixture checks both properties.

   **Additional reservation bypass found and fixed here:** standalone sandbox
   application may restart units through its shell helper. It now carries
   the lifecycle UUID and takes package maintenance admission, including for
   direct local callers (`af-runner/src/lib.rs:2909`). Own callbacks work;
   conflicting CLI sandbox requests do not touch drop-ins. Unknown packages
   no longer fall through to a fabricated generic system-unit sandbox target.
   The existing sandbox test remains dependency-injected and never calls
   live systemd/polkit.

3. **Durable launch phase and authoritative updater reconciliation.**
   `af-runner/src/job_receipts.rs:142` reserves a synced launch-owner lease
   before publishing **launching**. Both native and shell launch paths hold
   ownership across systemd admission, then compare-and-swap to **running**.
   Status at `af-runner/src/lib.rs:1723` leaves a live launch unresolved even
   before its unit exists. After owner loss, authoritative unit state decides
   running versus failed; unknown/unavailable/incomplete systemd state returns
   503 with the receipt retained and a retry instruction, never guessed success.
   Probes and launcher children have bounded timeouts and kill-on-drop.

   Receipt updates use cross-process locks, unique temporary files, file and
   directory sync, invariant checking, immutable terminal outcomes, and CAS.
   A concurrent real terminal write wins over a stale status probe or launch
   acknowledgment. Native and shell workers must claim an open receipt before
   invoking the release engine; a late admitted unit cannot execute after
   reconciliation closed its admission. Native completion-persistence errors
   are no longer silently discarded.

   **Deferred core restart gap also closed:** a durable receipt now covers the
   pending timer and independent restart worker
   (`af-runner/src/core_restart_worker.sh`). Admission cannot reopen between
   scheduling and the actual restart. The worker locks maintenance, claims
   admission, executes restart, checks unit-active state, and persists its
   outcome outside the caller's cgroup. Timer waiting/running differs from
   an expired timer; expired/orphan admission is not busy forever. The API's
   accepted response includes its job unit. This is **not** HTTP/UDS readiness
   certification or a new frontend completion-polling implementation.

### Isolated behavioral proofs

- Real subprocess owner death while the API is unavailable permits standalone
  recovery without starting the API and preserves a release-recovery sentinel.
  Same-PID/new-instance leases, live foreign ownership, missing identities,
  task drop, unknown phases, WAL-backed durable rows, and corrupt lifecycle
  pages are covered. A separate child-holds-lock test proves normal guard drop
  cannot unlock a still-running child.
- A real killed runner fixture leaves a real, blocked shell subprocess alive.
  Maintenance admission stays locked and its durable job remains updating
  until the child exits; only then does standalone admission mark interruption.
  FIFO/UDS barriers replace timing sleeps and polling.
- Concurrent UDS/native-executor fixtures pause in the API post-script phase:
  owned stop/start works, direct update/remove conflicts, wrong-action UUID is
  rejected, a separate CLI subprocess is refused, unrelated work proceeds,
  and queued API work subsequently executes. The same fixture exercises the
  actual sandbox UDS handler against an isolated systemd drop-in directory.
- A fake systemd-run process pauses between receipt publication and admission;
  status remains launching. Killing the actual launch owner tests restart
  recovery: unknown systemd is unresolved, known absence becomes failed, and
  late worker execution is fenced. Another UDS barrier pauses a status probe
  while a real terminal writer completes; the terminal receipt wins.
- The core-restart fixture covers pending timer exclusion, the actual isolated
  worker script, maintenance exclusion during restart, successful completion,
  refusal of a duplicate late worker, and expired-timer reconciliation.
- Shell release tests cover late-terminal fencing, live/dead lifecycle leases,
  and existing artifact/update/rollback fixtures. Repeated rollback attempts
  use separate logical receipt identities rather than rewriting a terminal
  receipt. No host release or real application installer runs in these fixtures.

### Final validation — 2026-11-06 CET

All commands use the disk-backed temporary directory and the existing main-disk
Rust target. The validation PATH's safety stubs reject accidental host
`systemctl`, `sudo`, `systemd-run`, and `pm2`; each integration fixture supplies
its own isolated fake programs ahead of those stubs.

```bash
export TMPDIR=/home/betheenvy/.cache/af-hillclimb-tmp
export PATH="$TMPDIR/safe-bin:$PATH"
```

Rust commands run from `backend-rs`; Python, syntax, and diff checks run from
the repository root. Logs are under the exported `TMPDIR`.

| Exact command / check | Result | Log |
|---|---|---|
| `cargo test --offline --workspace -- --test-threads=1` | **741 passed, 0 failed, 3 existing ignored**; subprocess test-harness results are not double-counted | `sol2-workspace-tests.log` |
| `cargo clippy --offline --workspace --all-targets` | **Passed**; carry-over warnings remain. Newly introduced test-module ordering and redundant-pattern warnings were corrected, not waived | `sol2-clippy.log` |
| `cargo test --offline -p af-runner lifecycle_tests:: -- --test-threads=1` | **6 top-level passed**; also included in final workspace run | `sol2-concurrency-tests.log` |
| `cargo test --offline -p af-release lifecycle::tests:: -- --test-threads=1` | **5 passed**; also included in final workspace run | `sol2-owner-tests.log` |
| `cargo test --offline -p af-services local_service_guardian -- --test-threads=1` | **1 passed**; also included in final workspace run | `sol2-service-guardian-tests.log` |
| `python3 -m unittest discover -s tests -p test_release_manager.py` | **32 passed, 1 existing skipped** (33 run) | `sol2-shell-release-tests.log` |
| `python3 -m unittest discover -s tests -p test_release_workflow.py` | **11 passed** | `sol2-release-workflow-tests.log` |
| `python3 -m unittest discover -s tests -p 'test_marketplace*.py'` | **85 passed** | `sol2-marketplace-tests.log` |
| `bash -n deploy/release-manager.sh backend-rs/crates/af-runner/src/core_restart_worker.sh` | **Passed** | Final tool output |
| `git diff --check` | **Passed** | Final tool output |
| `cargo fmt --all -- --check` | **Still fails on the 50 pre-existing files**, normalized to canonical paths; every failing file also fails formatting at `HEAD` | `sol2-full-format-check.log` |
| Read-only scoped rustfmt comparison | **Passed**: no remaining formatting hunks intersect changed regions; all new Rust modules are formatted | `sol2-scoped-format-check.log` |

The final workspace includes API **353 passed / 2 ignored**, CLI **18**, DB
**10**, Files **29**, Hardware **3**, Host **47**, Models **8**, Release **39**,
Runner **85 passed / 1 ignored**, Services **45**, and streaming harness **104**.
No new ignore, `forceExit`, test exclusion, or build-error bypass was added.
This iteration changes no frontend or Go source. Their previous round's
validation remains recorded above, rather than being misreported as a new run.

**Validation incident and repair:** the first mocked shell-release suite exposed
the pre-existing hardcoded `mktemp -d /tmp/af-release-XXXXXX`, despite exported
`TMPDIR`. Eight mocked artifact-copy tests encountered ENOSPC on the full tmpfs.
These attempted temporary fixture staging, not real installations or downloads.
The script cleaned failed staging directories; inspected reported examples were
absent afterward. Artifact staging now honors `${TMPDIR:-/tmp}`, and the full
33-test shell suite passes as recorded above. No unrelated cache was removed.
An initially overlong fixture UDS path was shortened for the disk-backed temp
root. Both are resolved validation defects, not ignored failures.

### Scores after second Sol (source-level, out of 10)

| Area | Second Sol score | Basis and remaining limitation |
|---|---:|---|
| Install / reinstall / uninstall | **9.1** | Existing retention/purge behavior preserved; full UUID orchestration exclusion, conflicting CLI actions, dropped owners, and surviving children now covered. No all-77 live certification. |
| Application updater | **9.0** | Same-package update/remove and post-script races are fenced; failed/interrupted outcomes remain truthful. Third-party upstream schema downgrade/reversal remains unguaranteed. |
| System updater / restart | **9.0** | Standalone abandoned-owner recovery, launch/status fencing, late-worker rejection, corruption rollback, and timer-gap exclusion pass isolated proofs. Unit-active receipt is not full HTTP/UDS readiness. |
| Services controls and units | **9.0** | Owned callbacks, companions, healing, sandbox application, and local-control crash exclusion share reservations. The complete catalog/manager matrix still needs independent review. |
| Frontend workflows | **9.0** | Prior matching-receipt, unknown-state, reinstall/purge, and late-poll work is preserved; no new frontend changes or fresh frontend validation claimed. |
| Regression confidence | **9.0** | 741 Rust tests plus meaningful cross-process/UDS races and shell/Python suites pass. Pre-existing global format drift and absent live/disposable-guest integration remain explicit. |
| **Overall** | **9.0** | **No known scoped P0/P1 remains in the authoritative Rust source path after these fixes and tests. This is a self-assessment, not independent certification.** |

**Opus return gate: REACHED for the source-level hill climb.** The opening
6.5 and first-Sol 8.5 assessments remain unchanged. The parent should now return
to Opus for independent review; this subagent did not launch it. A newly found
P1 must reopen the gate rather than be waived to preserve this score. This is
an implementation handoff, **not completion of the entire user task**.

### Prioritized independent-review brief

1. **Owner/child liveness and recovery safety:** review lease identity and
   filesystem durability/permissions; inherited open-file-description lifetime
   on normal drop, API death, and runner death; guardian descriptor closure;
   unknown owner/status fail-closed behavior; SQLite/WAL and restored-snapshot
   interactions; and the corruption-only explicit rollback exception. Start
   with `af-release/src/lifecycle.rs`, `lock.rs`, `admin.rs`, the release shell
   admission code, and `af-services/src/package_jobs.rs`.
2. **Full orchestration reservation and lock order:** follow the UUID through
   API pre-stop, runner/package execution, persistence/restoration, service and
   sandbox callbacks, direct CLI paths, local fallback, and healing. Challenge
   queued-job progress, action mismatch, shared/companion units, and callback
   reentrancy using `af-runner/src/lifecycle_tests.rs`. These are actual UDS and
   test-binary CLI-path subprocess fixtures, not an installed-host `af` smoke
   test or a full browser-to-HTTP-API end-to-end certification.
3. **Launch/status authority and terminal fencing:** inspect both engines,
   receipt lock/CAS ordering, worker claim-before-engine, launcher timeout/drop,
   late admission, unknown systemd state, unit collection, and core timer/worker
   lifetime. Challenge the immutable terminal inference against fresh systemd
   evidence without letting a closed late worker act.
4. **Remaining P2/product coverage:** enumerate all catalog authorization
   outputs (raw timers, oneshots, sandbox and pm2); decide whether the legacy Go
   server is still a supported runtime and add UUID/terminal parity if so;
   review core-restart receipt presentation and true application readiness;
   stale Services fetch feedback; and explicit unreadable-catalog-path fallback.

No production application, host release, or real systemd unit was installed,
removed, purged, updated, or restarted. Production databases were not test
fixtures. Real systemd/PM2 behavior, process/power-loss fault injection on a
disposable guest, actual upstream builds/downloads, vendor data migration
rollback, and live all-77 application certification remain unrun. Persistent
lease files are intentionally not garbage-collected: removing their evidence
can make restored durable jobs unverifiable.

McMemory's principal-agent gate correctly refused this subagent's direct
`remember` request. Two verified fix candidates were instead accepted by
`stage-submit`, with zero quarantined items, at
`/home/betheenvy/.gemini/antigravity/mcmemory/staging/subagent_aetherflow_sol2_20261106_w1.json`.
They remain **pending Main Model audit**; the parent must spot-check and
selectively ingest them. No direct memory-vault write was forced or bypassed.

## Returning Opus challenge — third Sol X-High implementation, 2026-11-06 CET

The returning independent reviews reopened the gate: logic **7.5**, contracts
**8.0**, security **8.6**. The earlier opening Opus **6.5**, first Sol **8.5**,
and second Sol **9.0** remain historical assessments, not certifications.
This implementation pass read all three review reports and JSON findings,
worked without subagents, and preserved the original 45 tracked/untracked
entries on `nightly` at `13066f92`. No reset, clean, stage, commit, push,
deployment, production database write, package installation, or live service
command/restart was performed. Test subprocesses use isolated roots, SQLite,
fake systemd/sudo programs, and Unix sockets. `TMPDIR` and safety stubs remain
on the main disk; Node **24.22.2** and the existing Rust target were reused.
The parent retains review consolidation, McMemory audit, and the fresh Opus gate.

### Consolidated resolutions and source proofs

1. **L-01 / corroborating S-02: detached helpers no longer co-own maintenance.**
   `af-release/src/lock.rs:117` exports the inherited descriptor identity for
   child commands, without unlocking it or removing surviving-child protection.
   `packages/common.sh:247` adds a synchronous subshell launcher: it closes
   that descriptor **before** forking the detached helper, then returns only
   after the fork. This is not the racy background-child close proposed in the
   review. `write_lock` uses it for certbot. The other shell background pattern
   found is SeedCross's generated runtime service script; systemd launches that
   runtime independently, rather than the installer directly forking it.

   `af-runner/src/lib.rs:1674` gives identity-bearing **Service** restores a
   bounded **30-second**, blocking-pool maintenance wait. Unrelated and host
   mutation admissions retain zero-wait exclusion, and reservation checks still
   run after acquisition. The actual legacy stream regression runs an installer
   sourcing `common.sh`, backgrounds a socket-gated helper, completes the
   installer, and successfully starts its owned unit while the helper remains
   alive. It also proves the owned restore waits across a held handoff lock and
   unrelated admission remains excluded. A separate actual legacy subprocess
   fixture kills its API/runner parent: the surviving installer still excludes
   maintenance even after the detached helper is released; only installer exit
   permits reconciliation to **interrupted**, never completed.

2. **PC-01: read-only, once-per-request lifecycle snapshots.**
   `af-services/src/package_jobs.rs:211` opens a separate **read-only** connection
   with a **150 ms SQLite busy timeout**, reads the journal in one SELECT, and
   overlays local progress only for the same identity and phase. Status reads
   never acquire the maintenance flock, reconcile rows, or hold the registry
   mutex during SQLite I/O. Catalog and Services builders consume one shared
   snapshot throughout each response (`af-services/src/lib.rs:220`, `:1382`).
   Marketplace listing, Services listing, package-progress reads, admission's
   catalog/status lookup, and service-control validation run their blocking work
   through `spawn_blocking` in API routes. Progress and control validation also
   reuse one snapshot, not separate active/outcome or per-target reads. Failed
   snapshots return **503 / unknown**, not an invented idle/success state;
   unknown durable phases block controls. Accepted ACKs return the admitted UUID
   directly rather than rereading a replaceable journal row.

   Reconciliation remains at startup and package admission; the mutation-only
   `has_active_package_jobs` preflight (`package_jobs.rs:262`) reconciles under
   maintenance before updater/heal admission. Thus a read does not mutate stale
   ownership, but subsequent mutation admission still recovers a provably dead
   owner and refuses unknown phases. The integrated Rust test first failed on
   the pre-repair source while a scratch SQLite EXCLUSIVE transaction stalled
   the real getter. After repair it verifies both maintenance and the mutation
   registry remain available, then overlaps hundreds of real snapshots with
   **eight admissions, actual legacy executions, and owned service controls**.
   It also checks dead-owner recovery happens at mutation preflight, not read.
   A final endpoint audit found residual synchronous/two-read progress and
   admission lookups plus a control-validation fallback. Two added isolated
   Rust endpoint tests first failed on those actual paths, then passed: blocked
   SQLite reads yield on a single-thread Tokio runtime and return 503, while
   unknown phases still exclude manual controls. Their logs are
   `pc01-endpoints-before.log`, `pc01-admission-before.log`, and
   `pc01-endpoints-after.log`.

3. **PC-02: bounded unknown outcomes, without UUID ordering assumptions.**
   `frontend/src/hooks/useMarketplace.ts:66` bounds local receipt tracking at
   **120 seconds**. An exact identity/action receipt still settles immediately,
   including completion before the POST acknowledgment. If A's receipt was
   replaced by another client's B, delayed indefinitely, or the app disappears,
   the local fast-poll/busy override expires with an explicit **unconfirmed**
   outcome, never B-as-A success. `MarketplaceTab.tsx:127` reports it once.
   Authoritative active server jobs still keep their cards busy. Services update
   tracking has the same deadline, and neither surface can resurrect an expired
   tracker from a late POST acknowledgment. Hook and tab tests cover A then B,
   missing app data, delayed outcomes/acknowledgments, and timer cleanup.
   This deliberately chooses bounded uncertainty rather than pretending UUIDs
   or an out-of-order response establish which job came later.

4. **PC-03: actual receipt-plus-readiness core restart tracking.**
   The admin-only `/api/v1/admin/services/restart/status` route accepts valid
   restart receipt identities and reuses the runner's durable status protocol
   (`af-api/src/routes.rs:860`). `useCoreRestart.ts:9` retains the accepted unit,
   retries through transient API disappearance, rejects foreign/unknown status,
   surfaces terminal failure, and requires a matching successful terminal
   receipt **before** requesting a fresh authenticated API response. Core
   controls stay busy through stale pre-restart healthy snapshots. The worker
   receipt confirms restart plus systemd activation; the fresh response confirms
   API availability, not arbitrary vendor application health. Tracking expires
   unconfirmed after **180 seconds**, bounds individual fetch attempts, aborts
   in-flight requests on unmount, and cleans up timers. Both hook and Services
   component regressions exercise these transitions. Deferred ACK ordering and
   durable job identity are preserved.

5. **S-01: descriptor-anchored, inode-bound restart locking.**
   The scheduler captures device/inode from its held, regular lock descriptor
   (`af-release/src/lock.rs:100`, `af-runner/src/lib.rs:567`). The worker opens
   each ancestor using directory descriptors and `O_NOFOLLOW | O_DIRECTORY`,
   then opens the existing leaf **read-only**, with `O_NOFOLLOW | O_NONBLOCK`
   and **no O_CREAT** (`core_restart_worker.sh:16`). It requires the scheduled
   regular-file device/inode, obtains flock on that descriptor, and rechecks
   the pathname identity after waiting. Thus the original check-then-open
   symlink patch was not used, and a replacement inode cannot silently become
   the lock. Tests reject post-schedule symlinks, missing paths, directories,
   FIFOs, replacement regular inodes, and symlink ancestors without running
   systemctl or creating the target; normal acquisition, exclusion waiting,
   receipt completion and late-worker rejection remain covered.
   The pinned descriptor is passed only to the foreground systemctl controller,
   so killing the Python worker cannot release maintenance while that controller
   still survives. An added worker-kill regression failed before that explicit
   inheritance was added and passes afterward (`core-controller-before.log`,
   `core-controller-after.log`). Other descriptors remain close-on-exec.

6. **Shared companion reservation follow-up.**
   `af-release/src/lifecycle.rs:139` permits a matching owner callback on a
   shared unit despite another recognized queued reservation, but only under
   the caller's maintenance serialization. Empty/foreign identities, core
   host mutations, and unknown matching phases still fail closed. The added
   Apache companion regression exercises each boundary. Existing receipt CAS
   behavior already retains a worker's early terminal publication; it was not
   weakened. F01/F02's adjudicated false-positive loops were not “fixed.”

### Fresh validation for this pass

All logs are in `/home/betheenvy/.cache/af-marketplace-review-20261106/sol3/`.
Commands use the safety PATH and disk-backed `TMPDIR`; Rust commands run from
`backend-rs`, frontend commands from `frontend` unless stated otherwise.

| Command / evidence | Fresh result | Log |
|---|---|---|
| `cargo test -p af-services polling_does_not_own -- --nocapture` before repair | **Failed as expected**: real status read owned maintenance | `pc01-before.log` |
| Same focused Rust regression after repair | **Passed**, including parallel admission/executor/control and stale-owner preflight | `pc01-after.log`; final workspace repeats the extended case |
| `cargo test --offline -p af-api journal -- --nocapture` | **4 passed**, including two endpoint regressions; both targeted failures reproduced before repair | `pc01-endpoints-before.log`, `pc01-admission-before.log`, `pc01-endpoints-after.log` |
| `cargo test --offline -p af-runner legacy_ -- --test-threads=1 --nocapture` | **3 passed**, including actual detached helper and API-parent death | `legacy-subprocess.log` |
| `cargo test --offline --workspace -- --test-threads=1` | **749 passed, 0 failed, 3 existing ignored**; nested subprocess summaries excluded | `workspace-final.log` |
| `cargo clippy --offline --workspace --all-targets` | **Passed**, carry-over warnings remain | `clippy-final.log` |
| Focused Jest, four lifecycle/restart suites, `--runInBand --detectOpenHandles`, no forceExit | **59 passed**, clean process exit | `frontend-focused-final.log` |
| `../node_modules/.bin/tsc --noEmit --incremental false` | **Passed**, including test files | `frontend-types-final.log` |
| `npm run lint` | **Passed** | `frontend-lint-final.log` |
| `npm run test:ci` | **565 passed, 5 existing skipped**; existing forceExit script unchanged | `frontend-full-final.log` |
| `NEXT_STATIC_EXPORT=1 npm run build`, isolated in `dist/sol3-marketplace-static-export/frontend` | **Passed**, default Next 16.4.3 Turbopack, 9 static outputs | `frontend-static-export-final.log` |
| `python3 -m unittest discover -s tests -p 'test_marketplace*.py'` | **85 passed** | `python-marketplace.log` |
| `python3 -m unittest discover -s tests -p 'test_*installer*.py'` | **68 passed** | `python-installers.log` |
| `python3 -m unittest discover -s tests -p test_release_manager.py` | **32 passed, 1 existing skipped** | `python-release-manager.log` |
| `python3 -m unittest discover -s tests -p 'test_v4_*guest_drills.py'` | **57 harness unit tests passed**; no real guest execution | `python-guest-harness.log` |
| Gitleaks on CI-shaped source tree, all tracked plus nonignored untracked files, unchanged config, `gitleaks dir . --config .gitleaks.toml --verbose --redact` | **No leaks** | `gitleaks-ci-source-relative.log` |
| Bash syntax, `git diff --check`, rustfmt of the three new/extended Rust modules | **Passed** | `diff-check.log`, `new-rust-format.log` |

Validation caveats are retained, not suppressed. An initial cache-directory
Turbopack copy failed its out-of-root dependency check; relocating only the
validation copy under the repository fixed that. An optional Webpack attempt
exposed `PublicShareView`'s **existing at HEAD** named page export (TS2344);
Webpack is not certified by this pass. The standard Turbopack export and the
full standalone TypeScript check pass without ignoring errors. An initial
whole-directory Gitleaks run found **427 ignored build/test-output hits** in
`dist`, `backend-rs/target`, and `frontend/.next`; no source exemption or scan
configuration was added. The CI-shaped scan excludes generated ignored output
by construction, not source or test changes. Invoking that mirror by absolute
path initially defeated existing anchored fixture allowlists; running the exact
CI-style relative `dir .` command restores their intended matching. A new
late-ACK test initially counted a queued React fake microtask as a timer; its
diagnostic showed zero actual timers, and the test now flushes fake microtasks
before asserting cleanup. None of these incidents was hidden by forceExit,
TypeScript suppression, or a new secret-scan exemption.

### Scope limits and third-pass self-assessment

- **No known scoped P0/P1 remains in the reproduced paths.** This is an
  implementation self-assessment, pending the parent's fresh independent review.
- Replacement receipts become explicitly unknown after two minutes, not an
  immediate inferred outcome. Core UI tracking is mounted-session tracking;
  durable receipts survive API/runner loss, but automatic browser-reload resume
  is not added. Readiness means systemd activation plus a responding API, not
  full vendor data or HTTP functional certification.
- Runtime certification is **Rust-only**. Legacy Go compatibility APIs still
  lack UUID/terminal receipt parity and are not claimed supported by this UI.
  No Go source changed and no prior Go result is presented as freshly rerun.
- Owner/launch evidence intentionally remains uncollected and grows over time;
  do not delete it as a cleanup shortcut, because restored jobs need it.
- Full all-77 live installs, real systemd/PM2, upstream downloads/builds, vendor
  migrations/rollback and disposable-guest power-loss fault matrices remain
  unrun. Existing global formatting debt is not mass-formatted.

| Area | Third Sol self-score / 10 |
|---|---:|
| Install | 9.0 |
| Reinstall, retained data/config/secrets/port | 9.1 |
| Uninstall / explicit purge | 9.1 |
| Application/system updater and progress | 9.0 |
| Core restart reliability | 9.0 |
| Services controls | 9.1 |
| **Overall, scoped source and isolated proofs** | **9.0** |

The implementation repair manifest for the parent's next review is
`/home/betheenvy/.cache/af-marketplace-review-20261106/sol3_resolution.md`.
No final independent certification or parent-task completion is asserted here.

## Parent repair pass after final Opus quota failure — November 6, 2026

**Current state: implementation and local validation are ready; the final
independent overall 9/10 gate remains open.** The completed Opus security recheck
rated the Sol3 snapshot **9.0/10**, with S-01/S-02 closed and no new verified
findings. The final logic and contracts delegates then failed with
`You have reached your Antigravity quota for this period.` No provider was
silently substituted and no retry loop or scheduled retry was started.

The contracts delegate saved a substantive report before its quota failure:
`/home/betheenvy/.cache/af-marketplace-recheck-20261106/opus_perf_contracts_recheck.md`.
It rated that snapshot **8.5/10**, with no P0/P1 but one P2 blocking its 9/10.
The final logic delegate left useful fixture logs but no completed verdict;
there is deliberately no fabricated empty logic lens. Earlier Opus findings
and all previous scores remain historical evidence, not current certification.

### Recovered findings and parent repairs

| Finding | Severity | Repair and evidence |
|---|---|---|
| PCR-01: two-minute receipt expiry despite the exact accepted job remaining active; Marketplace then suppressed its real terminal result | P2 | Successful matching identity/action observations renew the observation deadline. SWR `onSuccess` covers identical responses and `isValidating` completion covers requests deduplicated with another subscriber. Timers re-arm after ref-only deadline extensions. Stale cached data during errors does not renew indefinitely. Unknown notices have separate deduplication; accepted identity/action survives an observation timeout so a late exact terminal receipt is still shown once. Hook, real hook/component integration, and Services tests cover six-minute jobs, identical/deduplicated polls, wrong identity/action, stale errors, supersession, late receipts and cleanup. |
| PCR-02: healthy healer polling acquires the maintenance lock per unit | P3 | The healer gathers one read-only lifecycle snapshot and its unit list on the blocking pool. Healthy probes own neither lifecycle mutation lock. Reconciliation/admission runs only for an eligible restart; the runner still enforces its reservation and maintenance guard. An isolated Rust test holds both locks and proves all three healthy probes complete, then verifies real-active-job exclusion and missing-journal recovery. |
| PCR-03: failed lifecycle snapshot becomes empty service inventory | P3 | `get_active_services` now propagates errors. WS retains its known inventory (or null before any successful scan), service-down rules skip unknown observations, cluster heartbeats skip submission when inventory is unknown, and bandwidth analysis returns 503. Rust regressions prove alert suppression, cache preservation, recovery, and missing-journal error propagation. A prolonged journal outage can therefore delay cluster heartbeats; it cannot publish a false empty inventory. |

The exact-active job must also have the expected lifecycle phase/action; an
unrelated job or a response for a different action cannot prolong local pending
state. A successful shared SWR request renews tracking even when deep comparison
preserves the cached data reference. An unavailable or superseded receipt still
becomes explicitly unconfirmed after two minutes without matching observations.
The original saved scratch reproduction remains evidence of the pre-repair bug;
the new repository tests explicitly model successful polls and unavailable polls.

The parent reviewed the changes against caller contracts and preserved the
lease, UUID/action, maintenance, worker identity and authorization boundaries.
This is implementation review, **not a substitute for the requested independent
Opus return**. Parent self-score remains **9.0/10** for the scoped source and
isolated tests, with no known scoped P0/P1 or unresolved recovered PCR finding.

### Fresh validation after these repairs

Logs live in
`/home/betheenvy/.cache/af-marketplace-recheck-20261106/parent-repairs/`.
Commands ran with the existing rejecting safety stubs, Node **24.22.2**, and
`TMPDIR=/home/betheenvy/.cache/af-hillclimb-tmp`; `/tmp` remains full.

| Check | Result | Log |
|---|---|---|
| Rust workspace, offline, one test thread | **753 passed, 0 failed, 3 existing ignored**; top-level unfiltered summaries only; the WS regression is also compiled into the streaming test crate | `rust-workspace.log` |
| Workspace Clippy, all targets | **Passed**, existing warnings remain | `clippy.log` |
| Five focused frontend suites with `--detectOpenHandles`, without forceExit | **73 passed**, clean exit | `pcr01-focused.log` |
| Full frontend CI | **579 passed, 5 existing skipped**; existing CI forceExit script unchanged | `frontend-full.log` |
| TypeScript, including tests | **Passed** | `frontend-types.log` |
| Full frontend lint | **0 errors**, 41 warnings | `frontend-lint.log` |
| Isolated default static export | **Passed**, original frontend output untouched | `frontend-static-export.log` |
| Healer/unknown-inventory regression | **Passed** in a subprocess with fake system commands and temporary DB | `pcr02-03-services.log` |
| WS failed-snapshot/recovery regression | **Passed** | `pcr03-ws.log` |
| Notification unknown-state/recovery regression | **Passed** | `pcr03-notifications.log` |

The previous Sol3 Python totals (85 marketplace, 68 installer, 32 release-manager
plus one skip, and 57 guest-harness tests) remain the latest results for those
unchanged scripts. Earlier Go results remain historical; Go receipt parity is
still unsupported by the authoritative Rust UI contract. The optional Webpack
export issue and pre-existing global formatting debt remain documented above;
neither was hidden with a type-check or secret-scan bypass.

### Review evidence and remaining gate

- Frozen Sol3 review snapshot, manifests, the completed security report, recovered
  contracts report, and partial logic fixtures remain in
  `/home/betheenvy/.cache/af-marketplace-recheck-20261106/`.
- Parent resolution evidence, current-source hashes, final patch, and final
  handoff are stored under that run's `parent-repairs/` folder. The McSurgeon
  dossier retains the original valid findings and their separate parent
  resolutions; F01/F02/F03 are recorded as reviewed false positives.
- Verified memory lessons are `mem_0384`/`mem_0385` (helper descriptor and root
  worker identity), `mem_0386`/`mem_0387` (receipt freshness and unknown service
  inventory). The main model audited and ingested the two staged Sol2 historical
  lessons as `mem_0388`/`mem_0389`; their source-only/independent-review caveats
  are retained.
- Required next independent step: Opus logic/concurrency and contracts rechecks
  against the final source manifest, including this parent delta. The security
  worker's 9.0 applies to the reviewed Sol3 snapshot; the latest delta must be
  acknowledged in final sign-off. The requested Antigravity Opus quota is the
  current blocker, not a discovered application failure.

All original changes are preserved. Work remains unstaged and uncommitted on
`nightly` at HEAD `13066f92`. No production install, reinstall, uninstall, purge,
update, systemd/PM2 action, restart, staging, commit, push or deployment ran.
Live all-77 application/vendor behavior and disposable-guest power-loss
certification remain unexercised and are not claimed by these source scores.

Final artifact checks for the parent pass: `git diff --check` passes.
`cargo fmt --all -- --check` still flags **50 canonical source files**, every
one already unformatted at HEAD; changed/new regions were formatted without a
workspace rewrite (`parent-repairs/format-audit.json`). The interactive
`parent-repairs/hillclimb-summary.html` passed all seven McArtifacts checks and
inline preview had no console errors. The full `surgery_workbench.html` shows
the **frozen Sol3 review snapshot** and historical PCR findings; current repairs
and their final source hashes are in the separate parent handoff.

The final CI-shaped relative Gitleaks scan passed with **no leaks** and unchanged
configuration (`parent-repairs/gitleaks.log`). An initial absolute-directory scan
reported seven existing fixtures because their narrow relative-path exemptions
did not match; that redacted log is retained as `gitleaks-absolute-path.log`.
No exemption or source was changed to obtain the relative CI result.


## Opus after reset and small parent repairs — November 6, 2026

**The independent 9/10 gate is still open.** The fresh completed Opus
performance/contracts review rated the frozen 54-file parent snapshot **8.6/10**,
with no P0/P1/P2 and three P3 findings. It independently verified PCR-01/02/03
as repaired. Its unchanged report is
`/home/betheenvy/.cache/af-marketplace-opus-final-20261106-reset1/opus_perf_contracts_review.md`.
The fresh logic run failed on a provider thinking-signature error; its new
same-model recovery run then exhausted Antigravity's **weekly** allowance.
Neither produced a completed logic verdict. Saved checkpoints are coverage
notes and candidates, not an approval or score. The earlier security **9.0**
continues to cover the frozen Sol3 snapshot only.

The live November 6 **03:11 CET** quota check showed Claude & GPT five-hour
**38.9% remaining**, but weekly **0.0% remaining**. The binding reset is
**November 11, 2026 at 18:38 CET**; the November 6 five-hour reset cannot
restore the weekly allowance. No further failing review, fallback provider,
native agent, CLI model, nested delegate, polling or watcher loop was started.
The existing one-shot continuation will be moved to that weekly reset plus a
short buffer; the exact returned schedule is kept with the new handoff.

The three new contracts findings and one saved logic candidate were small
parent repairs. Their evidence lives under
`/home/betheenvy/.cache/af-marketplace-opus-final-20261106-reset1/parent-or-repairs/`.
The requested model sequence remains opening Opus, Sol X-High to self-9, and
independent Opus return. Parent implementation assessment remains **9.0**;
that is not a replacement for the unfinished independent gate.

| Finding | Local repair | Regression evidence |
|---|---|---|
| OR-PC01, P3 | Optimistic start/stop/restart feedback is local React presentation state. Services does not write fabricated data into SWR or clear its error, so an unrelated control cannot renew the tracked update's deadline during an outage. | Real-SWR Services deadline test; original Opus scratch proof preserved. |
| OR-PC02, P3 | Both systemctl runner clients preserve HTTP 409 as typed `LifecycleBusy`; the API recognizes local lock contention through the error chain and returns sanitized `409 LIFECYCLE_BUSY`. Ordinary runner error details stay visible. Documentation explicitly describes global maintenance serialization. | Isolated API regression holds the real fixture lock and covers local fallback, remote service control and deferred core restart with fake runner responses. Before repair the API returned 500; after repair all three return 409 without lock paths. |
| OR-PC03, P3 | Marketplace/Services have one slow 15-second recovery scheduler per SWR cache/key while transient errors persist. Shared subscribers share the request, departure of the initiating subscriber does not stop recovery, and last unmount removes the timer. Non-transient authorization/not-found errors do not automatically retry. The global SWR policy stays unchanged. | Actual SWR tests cover a long outage, truthful unknown warning, recovered late exact failure once, identical active polls, shared subscribers, cleanup, and HTTP 401/403/404. |
| OR-L01, P3 candidate from incomplete Opus logic checkpoint; parent verified | The shell release manager classifies corruption without Python 3.11-only SQLite attributes/constants. Explicit rollback may recover corrupt journals; deploy and unrelated database errors remain blocked. | Corrupted real SQLite page plus Python 3.10 module/exception-surface emulation reproduces the pre-fix AttributeError and passes after repair. This is not native Python 3.10 execution or a completed independent logic verdict. |

### Validation of the repaired source

| Check | Result | Evidence log |
|---|---|---|
| Rust workspace, offline, serial test threads | **754 passed, 3 existing ignored**, unfiltered top-level results only | `rust-workspace-final.log` |
| Workspace Clippy/all targets | **Passed**, carry-over warnings | `clippy.log` |
| Full frontend CI | **588 passed, 5 existing skipped** | `frontend-ci.log` |
| Eight focused frontend suites, no forceExit | **82 passed**, clean `--detectOpenHandles` exit | `frontend-focused.log` |
| Real-SWR integration tests | **9 passed**, including shared-key recovery and auth-error limits | `frontend-real-swr.log` |
| Full TypeScript including tests | **Passed** | `frontend-types.log` |
| Full frontend lint | **0 errors, 41 existing warnings** | `frontend-lint.log` |
| Isolated default static export | **Passed**; output under `dist/opus-contracts-repair-static-export/frontend/out` | `frontend-static-export.log` |
| Release-manager shell harness | **33 passed, 1 existing skip** | `release-manager.log` |
| CI-shaped source secret scan | **Passed**, unchanged relative config | `gitleaks.log` |
| Bash syntax and diff whitespace | **Passed** | `validation-summary.json` |
| Global format check | Same **50 pre-existing files**, zero newly flagged paths; newly edited Rust regions formatted | `rust-tools-validation.json`, `new-region-format.json` |

The first broad Rust run caught lost ordinary runner error text in the new typed
wrapping. The correction retains both the error type and its displayed detail;
the final full run passes. Earlier fixture/configuration attempts remain local
work logs, not additional independent verdicts.

All prior changes are preserved. Branch `nightly`, HEAD
`13066f92ade45ff5116ce1575aada45cff01ff2d` and the empty index remain unchanged.
The updated source inventory has 58 modified/untracked paths. No production
application operation, database write, systemd/PM2 control, restart, staging,
commit, push or deployment ran. Python marketplace/installer/guest suites and
Go results outside the changed shell path remain historical results, not fresh
runs in this pass. The live/vendor/all-77 and disposable-guest certification
limits remain in force. Separate curiosity-only audit material was not read or
used for these fixes, memories, scores or gates.

Next: verify the new manifest and obtain **new independent Opus logic and
contracts reviews** acknowledging this delta. Preserve actual reports and
honest scores; do not infer a verdict from saved partial checkpoints or passing
fixtures. Memory records `mem_0392`–`mem_0395` describe locally verified mechanisms
and explicitly retain the pending-independent-review limit.

## November 6 continuation: independently validated mechanisms repaired

The user's current objective is a fresh independent **GPT Sol MAX** assessment
of the current scoped source. That evaluator must not receive the target score,
prior ratings, goal, earlier reviews, repair narratives or memory context. The
historical Opus and Argon assessments above retain their original attribution and
snapshot limits; none is a verdict on this latest source.

This continuation uses the independently blinded Sol claim validation and the
user-authorized follow-up repairs. Curiosity-only audit outputs remain excluded
as direct implementation, scoring and review evidence. Implementation artifacts
live under `/home/betheenvy/.cache/af-marketplace-repair-20261106-r4/`.

### Integrated behavior and evidence

| Mechanism | Integrated behavior | Actual evidence |
|---|---|---|
| C01: stale owner recovery after busy API startup | A 15-second recovery worker reconciles only provably dead owners after maintenance becomes available. Mutation admission reconciles before deriving same-package catalog state. GET snapshots remain read-only; live owners and surviving child commands keep exclusion. | `sol-recovery/report.txt`, real flock/process regression and API retry regression |
| C02: retained ingress race and trailing recreation | Rust and Go read/archive/delete within an immediate SQLite write transaction. Central setters fence ordinary writers; callbacks require matching ownership. Both Rust API callbacks use the new identity-aware DB APIs. Cache generations prevent pre-invalidation reads from repopulating stale cache entries. | `sol-ingress/report.txt`; Rust SQLite, Go race and actual-worker fixtures; API callback integration regression |
| C03: truthful Go teardown | Archive, active-row deletion, purge, hosts teardown and update-cleanup failures terminate the actual worker as failed before Complete/uninstalled. | `sol-ingress/logs/go-race-final.log` and combined Go suites |
| C04: fast terminal launch acknowledgment | Both runner update engines preserve the receipt returned by CAS, including fast success/failure. API validation accepts only consistent terminal receipts. Settings handles a terminal POST result immediately. Deferred core restart CAS also preserves a terminal outcome. | `parent/launch-contract/runner-before.log`, `runner-after.log`, `api-launch-integrated.log`, `settings-after.log` |
| C05: prolonged polling outage | Existing shared transient-outage recovery resumes after SWR's normal retry budget, while preserving auth-error limits, subscriber sharing and cleanup. | Current real-SWR repository tests and 125-test focused clean-exit run |
| C06: catalog/lock uncertainty | Parse, type and stat failures return unknown/error rather than a smaller known inventory. Dynamic service status uncertainty remains a present unknown service. | `sol-inventory/report.md` and focused inventory regressions |
| C07: heartbeat liveness and freshness | Heartbeats continue during inventory failure with explicit fresh/stale/unknown metadata and last observation time. Cluster UI retains stale rows and distinguishes unknown from empty. | Backend heartbeat regressions, API fallback regression, four Cluster UI tests |
| C08: snapshot collection cost | One catalog parse per snapshot replaces per-app reparsing. Both status aggregation paths use bounded child processes and preserve unknown on failure; synchronous inventory callers run off async request threads. | `sol-inventory/report.md`, command-count and timeout/child-reaping tests |
| C09: useful safe failure summaries | Durable whitelisted categories distinguish preparation, installer, configuration, service restore, retention and combined finalization failures. Raw command output cannot become a durable/public outcome. | Category persistence/restart tests, API finalization tests and combined workspace run |
| C10: healing retry budgets | Unknown inventory and lifecycle suspension preserve backoff/exhaustion. Both healing probes kill and reap timed-out children. | `sol-inventory/report.md`, direct healer regression tests |
| C11: privileged receipt directory confinement | Held directory FDs, no-follow traversal, stable identity and regular-file/link checks protect owner/receipt/lock/temp/replacement operations. Scheduler passes the authorized receipt-directory identity to the nine-argument worker. | `sol-security/REPORT.md`, directory-swap fixtures and current runner tests |
| C12: plugin HTTP capability policy | Explicit, wildcard and previously minted destructive plugin scopes fail at normalization/request gates. Legacy plugin-shaped sessions use the same policy. Ordinary admin users and intended reads remain supported. | Native policy tests and actual legacy JWT/auth middleware regression |
| C13: progress trust boundary | Raw diagnostics require an ordinary admin session. User/plugin HTTP telemetry and per-recipient WS output receive safe summaries. Plugins cannot mint operator WS tickets; ticket consumption checks current DB role. | `sol-recovery/report.txt`, actual serializer/handler/ticket regressions |

Go ownership added here is **process-local** and honors existing Rust durable
reservations. It is not durable Go job identity, cross-process Go recovery or a
new reboot-surviving Go receipt contract. Rust remains the deployed runtime.
HTTP plugin capability restrictions are not a plugin process sandbox.

The stopped Luna implementation did not produce a completed handback or review
verdict. Its useful partial integrations were preserved, reconciled and tested by
the parent and completed Sol implementations. The earlier Argon child with no
assistant result is likewise not counted as verification.

### Combined validation on integrated source

Commands used the existing Node 24.22.2, rejecting safe-bin command stubs, main-disk
Rust target, `RUST_TEST_THREADS=1` and
`TMPDIR=/home/betheenvy/.cache/af-hillclimb-tmp`. No production command or database
operation was exercised.

| Check | Actual result | Evidence under `parent/` |
|---|---|---|
| Rust workspace, offline | **795 passed, 0 failed, 3 existing ignored**; last summary per Cargo artifact, excluding nested subprocess totals | `rust-workspace-integrated.log`, `rust-integrated-counts.json` |
| Clippy, workspace/all targets | Passed with warnings | `clippy-integrated.log` |
| Go DB/services/API | Passed | `go.log` |
| Marketplace Python harnesses | **85 passed** | `marketplace-python.log` |
| Release-manager Python harness | **33 passed, 1 existing skip** | `release-python.log` |
| Full frontend CI | **594 passed, 5 existing skipped** | `frontend-integrated-full-ci.log` |
| Ten focused frontend suites | **125 passed**, clean `--detectOpenHandles` exit without forceExit | `frontend-integrated-focused-correct-cwd.log` |
| TypeScript including tests, lint, isolated default static export | Passed; isolated export preserves the working frontend output | `frontend-integrated-validation.json` |
| Source secret scan | Passed with unchanged relative CI configuration | Neutral review pack `validation/secret-scan.log` |
| Bash syntax and diff whitespace | Passed | `shell-syntax.json`, `review-source-integrity.json` |
| Formatting | Six new Rust source files pass. Global check flags 54 canonical paths: 50 previously flagged plus four additional files in this delta; unrelated formatting was preserved. | `new-rust-format-final.json`, `rust-global-format.json` |

The first combined Rust run caught an old test expecting raw stderr in a durable
receipt. The test now asserts the safe summary and absence of raw stderr; the
subsequent complete workspace run passes. Runner streaming fixture assertions
were reconciled with the sanitized terminal-line protocol while preserving
rejection/no-side-effect and matching-owner completion checks. Earlier failed
logs remain evidence of those corrections, not extra successful test counts.

The review input is frozen at
`/home/betheenvy/.cache/af-marketplace-neutral-review-20261106-b/`: **1,012 source
files, 67 changed files**, full patch, full/changed SHA-256 manifests, intended
behavior contract and neutral validation logs. The pack excludes scored audit
documents and memory context. The review launch uses `gpt-6.1-sol` with
`reasoningEffort=max`, alone, without nested reviewers or fallback. Its verdict
is pending; this section supplies no self-score or independent approval.

Branch `nightly`, HEAD `13066f92ade45ff5116ce1575aada45cff01ff2d`, all original
paths and the empty index are preserved. Everything remains unstaged and
uncommitted. No live install/remove/purge/update, systemd/PM2 control/restart,
production DB write, reset, clean, push or deploy occurred. Mounted-client
tracking and unexercised live/vendor/all-77/disposable-guest power-loss
certification remain explicit coverage limits.


### November 6 parent Services coverage check: companion log selection

The parent full-scope coverage audit reproduced a separate companion-log defect
(`PARENT-SVC01`, P2): clicking a companion log button requested its unit in
`serviceName`, but the modal always queried the first unit in `units` until the
operator selected a tab. A scratch regression against the unchanged component
failed with requested `wg-dashboard.service` and observed query
`wg-quick@wg0.service`. The failing fixture ran in the isolated export copy with
mocked SWR, not against a live service.

`ServiceLogsModal` now mounts a log session only while open, keys that session by
the requested service, and initially prefers the requested unit when present.
This resets prior tab/diagnostic state between services and closed sessions while
preserving manual tab selection inside a session. Four regressions cover initial
companion selection, changing requests, reopening and absence of hidden polling.

Validation after this two-file change:

- Focused modal/Services suites: **40 passed**, clean `--detectOpenHandles` exit.
- Complete frontend: **598 passed, 5 skipped**; TypeScript including tests, lint,
  and isolated default static export passed with no source drift.
- Current source secret scan passed. Backend hashes are unchanged, so the existing
  **795 passed / 3 ignored** Rust workspace and Go/Python results still apply.
- Original 58-file backups remain byte-exact; all current original paths, HEAD,
  branch and empty index are preserved. No production operation ran.

Evidence:
`/home/betheenvy/.cache/af-marketplace-repair-20261106-r4/parent/service-log-selection-proof/`.
The complete current requirement map is `parent/requirement-evidence-audit-c.json`.

The new neutral pack is
`/home/betheenvy/.cache/af-marketplace-neutral-review-20261106-c/`, with **1,012
included source files / 69 changed files**. Cancellation was requested for the earlier snapshot-b evaluator because its
input was superseded; no completed verdict is attributed to that run. A **new** independent `gpt-6.1-sol` review with
`reasoningEffort=max` was launched with only neutral source/contract/test evidence,
no target or historical ratings, no memory access, no nested agents and no
fallback. Its verdict is pending. All-source before-review hashes match pack c.
The parent dossier is now `surgery-c`; specialist results are not populated until
the actual independent output arrives.


### November 6 independent Sol MAX snapshot-c assessment and next repairs

The fresh blinded Sol MAX evaluator returned **7.0/10 overall**, with logic and
concurrency **6.5**, security **7.0**, and performance/contracts/Services UX
**7.5**. This supersedes the pending status for snapshot c; it does not rewrite
any earlier historical verdict. The goal remains open. All **1,012** frozen and
current included source hashes matched before and after its assessment; HEAD,
branch and empty index were preserved.

The evaluator supported six findings: **AFR-001 (P1)** failed stop can continue
through successful removal/purge; **AFR-002 (P2)** companion resources can overlap
across orchestration phases; **AFR-003 (P2)** direct CLI lacks shared durable
lifecycle/ingress orchestration; **AFR-004 (P2)** terminal receipt reads follow
symlinks rejected by the writer; **AFR-005 (P2)** actual gateway fallback can
recreate default aliases after removal; **AFR-006 (P2)** switching companions can
misattribute cached logs and a late diagnosis. Its fake-command destructive
continuation is observed; survival of a live daemon, vendor damage, reused-port
traffic and real exploitability remain inferences, not production incidents.

Independent report and verdict:
`/home/betheenvy/.cache/af-marketplace-neutral-review-20261106-c/review/report.md`
and `review/verdict.json`. Its proofs and three lens files remain unchanged.
The next implementation evidence is
`/home/betheenvy/.cache/af-marketplace-repair-20261106-r5/`. A parent integrity
check matched all 1,012 files before repair. Repairs and validation are underway;
no new independent approval is claimed.

### November 6 r5 completion and independent snapshot-d assessment

The r5 coordinator, teardown, receipt-reader, gateway and log-identity repairs
were integrated and validated. Rust workspace: **835 passed, 3 ignored**;
frontend: **601 passed, 5 skipped**; focused log/Services tests: **43**, clean
exit. Types, lint, isolated default static export, Clippy, source secret scan,
Go DB/services/API and the Python suites passed. Shell syntax passed for both
shared helpers and all 77 removers. Global formatting still flags **54**
canonical tracked paths: the initial 50 plus four carried from r4. This is not
an all-vendor, live-host, root systemd/PM2 or power-loss certification.

The fresh, blinded independent Sol MAX snapshot-d assessment returned **7.7/10
for the deployed Rust scope**: logic/concurrency **8.2**, security/trust **6.5**,
performance/contracts/Services **7.6**. All **1,019** frozen/live included source
hashes matched, with 151 changed source files and an empty index. It verified
three findings: ordinary Services HTTP viewers received an application API key
(**AF-ND-SEC-001**, P1); Dispatcharr purge ignored required SQL cleanup errors
(**AF-ND-LOG-001**, P2); bulk update checks reported success/zero updates when
inventory was unavailable (**AF-ND-PERF-001**, P2). The actual HTTP and rebased
remover observations are preserved separately from downstream live-impact
inferences. No earlier result or score is replaced retroactively.

Original independent report:
`/home/betheenvy/.cache/af-marketplace-neutral-review-20261106-d/review/report.md`.
The original three lens files were normalized only for McSurgeon's severity
schema and ingested into `af-marketplace-repair-20261106-r5/surgery-d`; the
originals remain unchanged. No automatic source fixes were applied by that tool.

### November 6 r6 repairs and independent snapshot-e assessment

The parent repaired all three snapshot-d findings. A shared HTTP/WebSocket
viewer allowlist removes credentials and private diagnostic fields for ordinary
and plugin viewers; human admins retain authorized credential access. Dispatcharr
requires both SQL teardown steps before deleting recovery credentials/data.
Bulk update inventory failures now return sanitized **503 STATUS_UNAVAILABLE**
without zero-update success fields; the UI displays a failed-check message.

Failed-before/passed-after evidence includes actual API handlers, per-session
WebSocket projection, React controls and rebased shipped Bash teardown. The
initial Bash fixture accidentally consulted host `/data`; rejecting fake `rm`
refused non-fixture deletion. The fixture was corrected to rebase `/data`, and
both SQL failure subcases were then reproduced against the saved pre-repair
script without swapping repository files. Initial Cargo `--lib` commands for the
binary af-api crate and invalid-cwd attempts were not counted as test results.

Final r6 validation: **837 Rust passed / 3 ignored**, **604 frontend passed / 5
skipped**, **44 focused frontend tests** with clean open-handle exit, **105
marketplace Python**, **68 installer Python**, **33 release-manager passed / 1
skipped**. Types including tests, lint, Clippy, isolated static export, all 79
shell syntax checks and frozen-source secret scan passed. An actual isolated HTTP
fixture verified ordinary and scoped-plugin credential absence, human-admin
access, catalog/lock failures returning 503 without counts, and known-empty
inventory returning an honest successful zero count. The broad wrapper reported
source drift only for the two intentionally updated frontend files; the final
frontend run revalidated those exact edits. Backend/Python sources were unchanged
during their checks. No production operations occurred.

Evidence: `/home/betheenvy/.cache/af-marketplace-repair-20261106-r6/parent/`;
neutral snapshot e: `/home/betheenvy/.cache/af-marketplace-neutral-review-20261106-e/`.
All **1,019** frozen/live hashes matched before and after the fresh independent
Sol MAX review, which received no target or previous ratings.

Its actual result is **7.6/10 deployed Rust**, with logic/concurrency **7.8**,
security/trust **8.7**, performance/contracts/Services **6.2**. The goal remains
open. Four verified Rust findings remain on that snapshot: **RUST-01 (P1)**
synchronous unbounded journal reads can starve API workers; **RUST-02 (P2)**
runner-unavailable controls have no execution bound; **RUST-03 (P3)** routine
admin control errors echo private diagnostic paths; **RUST-04 (P2)** configured
PM2 observation failures become falsely stopped. The shipped catalog contains no
PM2 entries, so that fourth finding is a supported configured-path defect, not a
claim of a default-app production incident. The independent report and all
proofs remain under snapshot e's `review/` directory.

The user clarified that Rust is authoritative and Go is retired. Legacy Go may
be read as a reference for required behavior; any missing scoped capability is
to be rebuilt in Rust. Go's historical ratings are separate and do not gate the
Rust result. The current repair evidence is
`/home/betheenvy/.cache/af-marketplace-repair-20261106-r7/parent/`.
No new score or independent approval is attributed to those in-progress repairs.

### November 6 r7 Services execution and observation repairs

The parent verified snapshot e's four Rust findings and repaired them directly.
`af-runner/src/bounded_command.rs` supervises capped stdout/stderr, execution
budgets, cancellation and process-group cleanup. Its supervisor retains the
Command's captured maintenance handle while required commands remain live;
timeout is explicitly unconfirmed. Ordinary runner controls use a bounded 40 s
budget; fallback and PM2 controls use a 20 s budget. Uncertain runner request
transmission is a failure rather than permission to issue a duplicate fallback.

`af-api/src/service_logs.rs` runs journal reads asynchronously with a 5 s budget,
1 MiB capture bounds and reader admission. File tails use bounded regular-file
reads off async workers and reject FIFOs/symlinked entries. Journal failure is
not converted to a successful empty audit fallback. Routine control/log errors
return fixed summaries and a correlation UUID; private details remain in server
logs. PM2 caches distinguish failed observations from successful empty listings;
configured-PM2 nonzero exit, malformed JSON and timeout remain unknown.

Actual isolated HTTP demonstrated that two stalled journal reads leave an
unrelated marketplace request responsive, then each returns 504. A stalled
fallback command held maintenance while running, returned a truthful 504 and
then freed maintenance. The ordinary control failure response omits the private
marker/path while its correlation ID and detail appear in the fixture server
log. A separate configured-PM2 HTTP fixture returns unknown, with no real PM2
process/daemon. Generic supervisor tests cover output overflow, cancellation,
lock lifetime and a descendant retaining a pipe after its leader exits.

Full final Rust workspace: **846 passed, 3 existing ignored**; full Clippy passes
with carry-over warnings. Focused inventory, log and error tests pass. The
frontend/root dependency hashes are unchanged from the **604 passed / 5 skipped**
frontend, TypeScript/lint/static-export validation; unchanged scripts retain the
**105/68/33+1 skipped** Python results. Both new Rust modules format cleanly.
Global formatting flags the same **54 canonical files**, with no new flagged
path. Frozen-source secret scanning passes. The first full run failed compilation
because applying only part of rustfmt's module movement dropped its declaration;
the declaration was restored before the complete passing rerun. That failed run
is preserved and not counted as a test pass.

The source walkthrough maps **17** retired-Go scoped route registrations to
Rust and finds no additional missing scoped capability to port. Route coverage
alone is not treated as vendor or behavioral certification. No Go source repair
or score is used as the Rust gate.

Evidence: `/home/betheenvy/.cache/af-marketplace-repair-20261106-r7/parent/`,
including `resolution.json`, `actual-tests.json`, `proofs/http-result.json`,
`proofs/pm2-result.json`, `rust-integrated-counts.json` and
`retired-go-to-rust-capability-map.json`. Snapshot e's actual Rust lens findings
are preserved in `r7/surgery-e`; retired-Go supplemental findings remain only in
the unchanged original report. No tool autofixes were applied.

Neutral snapshot f contains **1,021 source files / 153 changed files**, with all
original paths preserved, HEAD/branch unchanged and index empty. It contains no
scored reports or memory. A fresh independent assessment is still required.
The historical chart was rebuilt as HTML/CSS without JavaScript and actually
previewed/rendered in T3. The McArtifacts validator's sole failure is its
requirement for an unused Tailwind script; the six other checks and runtime
render pass. No complete validator pass is claimed.

Limits remain explicit: production operations were not run; no all-vendor,
real systemd/PM2 or power-loss certification is claimed. An in-process execution
budget is not claimed to survive destruction of its supervisor runtime;
inherited descriptors still preserve required child exclusion across parent
loss. The latest completed independent Rust rating remains snapshot e's
**7.6/10**, not a rating of r7.


## Snapshot f independent Rust return — November 6, 2026

The fresh blinded Sol MAX assessment of the frozen 1,021-file snapshot returned **7.3/10** for the deployed Rust scope: logic 7.1, security 7.5, performance/contracts and Services UX 6.9. The actual report records seven medium and two low findings, with no high finding reported. This does not meet the user’s independent-assessment goal. Retired Go is a behavior reference and is not the deployed rating target.

The report and exact proofs are preserved in `/home/betheenvy/.cache/af-marketplace-neutral-review-20261106-f/review/`. On resumption, all 1,021 manifest hashes matched; branch `nightly`, HEAD `13066f92ade45ff5116ce1575aada45cff01ff2d`, empty index, and existing worktree changes were preserved. Round r8 evidence is under `/home/betheenvy/.cache/af-marketplace-repair-20261106-r8/`. Repair groups cover strict runner control acknowledgements, HTTP update preparation/port preservation, fenced blueprint synchronization, Bash release receipt confinement, active updater discovery and authorization recovery, routine error projection, and bounded installer output. Repairs and validation remain pending; no new approval or production certification is claimed.


### Round r8 parent worker repairs — November 6, 2026

The privileged-worker implementation delegate was rejected by the provider cyber filter before source edits; the five backed-up existing source paths remained identical. The parent subsequently implemented the authorized defensive repairs directly; the blocked delegate was not retried or replaced. These repairs are not an independent approval.

Snapshot-f RUST-05: the Bash release-manager receipt writer now uses held no-follow directory traversal, scheduler device/inode binding, regular single-link identity checks, an existing admitted receipt, a bounded read, flock/CAS, relative temporary creation/replacement and directory fsync. Runner scheduling supplies the bound LaunchOwner directory identity. Receipt-producing invocations fail closed without the binding; standalone release-manager invocations without a receipt keep their existing interface.

Snapshot-f RUST-09: both legacy installer output pipes now use cancellation-safe bounded producer records before IPC. Overflow fails explicitly and invokes process-group termination/reaping while maintenance remains held. An actual public-stream regression failed before repair on a 2,097,153-byte emitted record and passed afterward; bounded partial-record/EOF/cancellation behavior has focused tests.

Actual parent checks: **135 runner tests passed / 1 existing ignored**, **8 receipt-confinement tests passed**, **33 release-manager tests passed / 1 existing skip**, and **105 marketplace Python tests passed**. Bash syntax and owned tracked diff whitespace checks pass. Evidence, exact pre/post logs, owned-only patch and hashes are in `/home/betheenvy/.cache/af-marketplace-repair-20261106-r8/parent/`, principally `workers-resolution.json`. The HTTP lifecycle and storage/Settings implementations are still in progress; final frozen-source integrated validation and fresh blinded review remain pending. No production operations, staging, commit, push or deployment occurred.


## Round r8 integrated validation and frozen review — November 6, 2026

All nine snapshot-f findings now have implemented repairs and focused passing evidence. This records implementation and validation, not an independent approval or an updated numerical assessment. The last completed independent assessment remains snapshot f (Rust 7.3/10). A new independent assessment of the frozen current source is required.

The HTTP handoff covers strict runner acknowledgement framing, uncertain-stop restoration, authoritative existing update ports, shared blueprint mutation admission and sanitized updater observation errors. The Settings/storage handoff adds authenticated durable updater discovery, exact receipt identity/action checks, transient-only recovery with permanent-auth failure stop and cleanup, and the whole storage deployment DNS/configuration/ingress boundary. That boundary is released before service callbacks. Parent worker repairs cover scheduler-bound confined Bash receipt writes and bounded installer output with child termination/reaping.

Integrated validation evidence in `/home/betheenvy/.cache/af-marketplace-repair-20261106-r8/parent/validation-summary.json`:

- Rust workspace: **865 passed, 0 failed, 3 ignored**, with no source drift during the run.
- Full frontend: **644 passed, 5 skipped**, 66 suites passed; TypeScript including tests, lint and isolated default static export pass, with no frontend source drift.
- Focused lifecycle frontend: **171 passed in 12 suites**, clean exit without `forceExit`.
- Clippy initially caught a new fake-UDS test that discarded its read byte count. Parent added an assertion that a nonempty request precedes acknowledgement. Focused Services regression and Clippy then pass. Production behavior was unchanged.
- Parent then applied rustfmt-only changes to the new routes/storage spans and the new assertion. The affected API/Services suites pass afterward: HTTP lifecycle 9, storage/update observability 2, Services HTTP lifecycle 5. These tests and compilation cover the final formatting delta; the earlier full-workspace result is not represented as a second full run on byte-identical formatted source.
- Preserved matching-source Python evidence: Marketplace 105 passed; release-manager 33 passed/1 skipped; receipt confinement 8 passed. Source hashes for those worker/script inputs still match.
- Frozen-source secret scan and tracked whitespace checks pass. All four new Rust modules pass rustfmt checks. Global format check retains **54 canonical flagged files**, exactly the preceding baseline set; no unrelated formatting cleanup was applied.

The immutable assessment pack is `/home/betheenvy/.cache/af-marketplace-neutral-review-20261106-g`: **1,027 files**, **159 changed source files**, branch `nightly`, HEAD `13066f92ade45ff5116ce1575aada45cff01ff2d`, zero drift, zero missing original paths, empty index. `source-manifest.json`, `source.patch`, `review-contract.md`, and neutral `validation-summary.json` are included. The evaluator receives no target score, previous ratings, scored documents, review history or shared-memory context. Retired Go remains behavior reference only; the score concerns deployed Rust and the Bash engine it invokes.

Source editing is frozen for the independent assessment. There were no production operations, production database writes, staging, commits, pushes, resets, cleans or deployments. Verification uses isolated roots, fake commands and disposable databases; no all-vendor/live-systemd/PM2/power-loss certification is claimed. Latest-source independent approval is pending.


## Snapshot g independent return and r9 repairs — November 6, 2026

The fresh blinded Sol MAX assessment returned **8.1/10** for the frozen 1,027-file Rust snapshot, with logic 8.3, security 8.0 and performance/contracts 7.6. It established three medium findings and no scoped P0/P1. Its actual report, findings, 51 executed existing tests, four isolated proofs and before/after integrity receipts are preserved in `/home/betheenvy/.cache/af-marketplace-neutral-review-20261106-g/review/`. This is an assessment of snapshot g, not approval of later changes. The separate curiosity audit remains excluded.

Round r9 repairs all three reported mechanisms. Established WebSockets retain account identity and revalidate current privilege before initial and later delivery; downgrade is monotonic and missing/uncertain account state closes the socket. Owned reinstall materializes native and Apache configuration from the same active-or-retained ingress used by durable restoration. Unowned settings remain active-only. The Services collector now bounds and coalesces observation work, and restart readiness uses a minimal authenticated database probe after a matching successful receipt.

Actual parent regressions include an upgraded production WebSocket before/after fixture, a persistent retained-reinstall integration test, four API WebSocket tests, three real-router/handler readiness tests, and the complete Services crate tests (69 unit tests plus the new integration test). The retained fixture covers custom host, port, credentials, unrelated native settings, retained TLS policy, disabled external access, explicit purge and malformed retained data. The Services implementer supplied 30 additional focused passing tests, with overlapping requests measured at about 3.03 seconds using nine fake unit probes. Counts from overlapping tests must not be added twice.

Evidence is under `/home/betheenvy/.cache/af-marketplace-repair-20261106-r9/parent/` and `../services-readiness/`. The parent accepted the narrow new `service_observations.rs` implementation helper. Concurrent Streaming changes are preserved; their owner repaired the compile call sites and is coordinating source freeze. Streaming review findings and scores are not imported as marketplace evidence. Integrated checks, final manifest and a fresh blinded independent assessment remain pending. No production operations, staging, commits or deployment occurred, and no live-vendor or power-loss certification is claimed.


### Round r9 frozen-source integration validation — November 6, 2026

All three snapshot-g findings have implemented repairs and local proofs. The integrated Rust workspace passes **882 tests, 3 ignored**, and Clippy exits successfully with warnings. After the concurrent Streaming owner completed its separate source freeze, all 24 declared integration hashes matched. The earlier drifted frontend run remains interim evidence only.

The stable frontend passes full CI (**665 tests, 5 skipped**), TypeScript including tests, and lint (41 warnings, no errors). Ten focused suites pass **158 tests** and exit cleanly without forceExit. A new isolated static export from this exact frontend succeeds. Global formatting retains the same 54 canonical flagged files. Frozen-source secret scanning passes from the source root using the existing configuration; the initial absolute-path invocation produced six synthetic-fixture matches because anchored allowlist paths did not match, and that original result is preserved. No scanner configuration or source was changed to obtain the passing relative-root run.

Neutral snapshot h contains **1,033 files / 183 changed files**, all matching frozen and live source, with original paths preserved, branch/HEAD unchanged and index empty. This validates local behavior and compilation, not all-vendor/live-host/power-loss behavior. A fresh blinded Sol MAX assessment remains pending. Historical ratings do not rate snapshot h.

Evidence: `/home/betheenvy/.cache/af-marketplace-repair-20261106-r9/parent/integrated-final/`, `parent/frontend-frozen-final/`, and `/home/betheenvy/.cache/af-marketplace-neutral-review-20261106-h/`. No production operations, staging, commit, push or deployment occurred.


## Snapshot h independent return and round r10 integration — November 6, 2026

The fresh blinded Sol MAX assessment returned **6.8/10** for the frozen 1,033-file deployed Rust scope, including its default Bash engine: logic **7.0**, security **7.3**, performance/contracts **6.0**. It reported two high findings (native metadata escaping the Services deadline; Dispatcharr adoption/purge of unrelated shared storage) and two medium findings (Emby activation failure reported as completion; raw update diagnostics exposed in ordinary/public status). The actual verdict, four proofs, executed checks and integrity receipts remain under `/home/betheenvy/.cache/af-marketplace-neutral-review-20261106-h/review/`. This historical score does not rate the current repairs.

Round r10 implements all four mechanisms:

- **F1:** Services status, PM2 and native metadata share the same three-second observation deadline and four-worker bound. Metadata requests use one absolute connect/write/read deadline, a 64-KiB response cap, shared admission and epoch-safe caching. The child reproduced four before-image failures and reports 19 passing focused tests. Eight overlapping native snapshots improved from 9.134 seconds / 48 requests to 3.024 seconds / six requests, peak four. Non-IPC filesystem/DB I/O outside the targeted deadline remains an explicit limitation.
- **F2:** Dispatcharr initializes only absent/empty dedicated `/var/lib/dispatcharr` with a protected path-bound ownership marker. Installation requires an absent or exclusive compatibility `/data` link; real/shared `/data` and nonempty unmarked legacy data require audited manual migration. No recursive retained-data adoption/chown occurs. Purge requires proven ownership and successful SQL teardown, retaining recovery data and credentials on failure. The child records 35 passing ownership regressions, with 26 unique before-image failures, plus scoped lifecycle/update/teardown checks. Parent reconciled the older fixture suite to valid retained environment and explicit legacy refusal; all 26 tests pass. No production safeguard was relaxed to satisfy old migration assumptions. `docs/marketplace.md` documents the compatibility limitation.
- **F3:** Emby's required restart failure now propagates before completion. Four complete-installer fixture tests pass, including first-install/reinstall failure and successful port retention; two of those failed against the before-image.
- **F4:** Version observation errors persist and serialize only fixed safe summaries. Raw diagnostics remain in server tracing. Legacy DB/cache reads, public Marketplace, ordinary Services/WS and direct responses sanitize their projection while preserving last-known versions and update availability. Focused production-router and persistence regressions pass.

Final integrated evidence is under `/home/betheenvy/.cache/af-marketplace-repair-20261106-r10/parent/`:

- Rust workspace: **897 passed, 0 failed, 3 ignored**; Clippy passes with warnings. Counts use the final summary of each Cargo target and exclude nested fixture subprocess summaries.
- Python: **144 Marketplace**, **68 installer**, and **33 release-manager passed / 1 skipped**. No source drift occurred during the integrated Python checks.
- All **323** frontend/root inputs match the previous frozen validation exactly. Reused evidence is **665 frontend passed / 5 skipped**, **158 focused tests exiting cleanly**, types including tests, lint and isolated static export. No frontend rerun or new browser certification is claimed this round.
- Three new/modified focused Rust modules pass rustfmt; each changed installer/remover passes its own `bash -n`. Owned tracked whitespace passes. Global formatting retains **54 canonical flagged files**; existing formatting debt is preserved.
- All original 1,033 source paths remain present. Implementation freezes and all **24** concurrent Streaming hashes match; HEAD remains `13066f92ade45ff5116ce1575aada45cff01ff2d`, branch `nightly`, index empty.

These are implementation and local-validation results, not independent approval. The latest completed independent score remains snapshot h's **6.8/10**. A new neutral full-scope assessment is required. Production lifecycle/service controls, production API/DB writes, staging, commits, pushes, resets, cleans and deployment were not performed. No real-vendor, live-systemd/PM2, all-application or power-loss certification is claimed.

Neutral snapshot i is frozen at `/home/betheenvy/.cache/af-marketplace-neutral-review-20261106-i`: **1,037 files / 190 changed files**, zero frozen/live drift and no missing original paths. Frozen-source secret scanning passes with zero findings. Its contract, current validation and source inputs contain no historical ratings or prescribed evaluator result. A new Sol MAX review will assess the complete deployed scope independently.

## GitHub submission preflight — November 6, 2026

The submission packages all 196 pending source, regression-test, installer and documentation files on the existing `nightly` branch, including the concurrent Streaming work. Older local repair branches were checked for already-integrated changes rather than merged again or used to restore the retired experimental channel.

Fresh submission checks pass: **910 Rust tests / 3 ignored**, **669 frontend tests / 2 skipped across 67 suites**, **228 Python tests / 1 skipped**, and all Go backend packages. TypeScript includes test files; lint reports no errors and 40 warnings. The isolated default static export, strict core Clippy, changed shell-script syntax, shell hygiene and final-source Gitleaks scan also pass. Rust totals use the final summary of each Cargo target, excluding nested fixture subprocess summaries.

Preflight repaired four test-only issues: generate the log-WebSocket nonce instead of embedding the public RFC example flagged by the secret scanner; isolate the plugin-router fixture's host allowlist from CI environment overrides; correct embedded Python indentation so version-probe cleanup tests actually launch their subprocess trees; and remove a needless generic borrow rejected by strict CLI-test Clippy. Runtime behavior and scanner policy are unchanged.

Checks use disposable databases and private test mount namespaces because the host `/tmp` tmpfs was full. The host mount and production services remain unchanged. Evidence is retained under `/home/betheenvy/.cache/af-github-submit-20261106-khRFbC/`. This is submission validation, not a new comprehensive independent rating or all-vendor/live-host/power-loss certification; previous snapshot assessments retain their original scope.
